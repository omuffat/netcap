/*
 * ftruncate() requires _POSIX_C_SOURCE on some systems.
 * Define it before any system header is pulled in.
 */
#ifndef _WIN32
#  define _POSIX_C_SOURCE 200809L
#endif

#include "ring.h"
#include "log.h"
#include "str.h"

#include <string.h>

#ifndef _WIN32
#  include <fcntl.h>
#  include <unistd.h>
#  include <sys/mman.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>

/*
 * On Windows, cn_ring_t.fd stores an index into g_win_slots[] rather than
 * a POSIX file descriptor.  Two HANDLEs are needed (file + mapping object),
 * so a small static table maps each slot index to both handles.
 * The table size matches CN_IFACE_COUNT_MAX (maximum concurrent rings).
 */
#  define CN_WIN_RING_SLOTS  CN_IFACE_COUNT_MAX

typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    int    in_use;
} cn_win_ring_slot_t;

static cn_win_ring_slot_t g_win_slots[CN_WIN_RING_SLOTS];

/* Allocate a slot and store both handles; return slot index or -1 on overflow. */
static int win_slot_alloc(HANDLE fh, HANDLE mh)
{
    for (int i = 0; i < CN_WIN_RING_SLOTS; i++) {
        if (!g_win_slots[i].in_use) {
            g_win_slots[i].file_handle = fh;
            g_win_slots[i].map_handle  = mh;
            g_win_slots[i].in_use      = 1;
            return i;
        }
    }
    return -1;
}

/* Release a slot. Precondition: idx in [0, CN_WIN_RING_SLOTS). */
static void win_slot_free(int idx)
{
    if (idx >= 0 && idx < CN_WIN_RING_SLOTS) {
        g_win_slots[idx].in_use = 0;
    }
}
#endif /* _WIN32 */

/* -------------------------------------------------------------------------
 * Atomic head accessors.
 *
 * write_head is owned (written) by the pcap capture thread only.
 * read_head  is owned (written) by the msync_worker / reader thread only.
 * Acquire/release semantics guarantee that each thread observes the
 * up-to-date value written by the other.
 *
 * GCC/Clang __atomic built-ins are used here.  On MSVC, replace with
 * InterlockedExchange64 / InterlockedCompareExchange64.
 * ---------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#  define RING_LOAD(ptr)        __atomic_load_n((ptr),  __ATOMIC_ACQUIRE)
#  define RING_STORE(ptr, val)  __atomic_store_n((ptr), (val), __ATOMIC_RELEASE)
#else
/* Volatile fallback for MSVC — sufficient on x86/x64 due to TSO memory model. */
#  define RING_LOAD(ptr)        (*(volatile uint64_t *)(ptr))
#  define RING_STORE(ptr, val)  (*(volatile uint64_t *)(ptr) = (val))
#endif

/* -------------------------------------------------------------------------
 * Internal copy helpers — handle wrap-around at the ring boundary.
 * Preconditions: base/src/dst != NULL, len > 0, len <= size.
 * ---------------------------------------------------------------------- */

/* Copy len bytes from src into the ring at position (head % size). */
static void ring_copy_in(uint8_t *base, size_t size, uint64_t head,
                         const uint8_t *src, size_t len)
{
    size_t pos   = (size_t)(head % (uint64_t)size);
    size_t first = size - pos;  /* contiguous bytes before wrap-around */

    if (first >= len) {
        memcpy(base + pos, src, len);
    } else {
        memcpy(base + pos, src,         first);
        memcpy(base,       src + first, len - first);
    }
}

/* Copy len bytes from the ring at position (head % size) into dst. */
static void ring_copy_out(const uint8_t *base, size_t size, uint64_t head,
                          uint8_t *dst, size_t len)
{
    size_t pos   = (size_t)(head % (uint64_t)size);
    size_t first = size - pos;

    if (first >= len) {
        memcpy(dst, base + pos, len);
    } else {
        memcpy(dst,        base + pos, first);
        memcpy(dst + first, base,      len - first);
    }
}

/* =========================================================================
 * Platform-specific init / flush / destroy
 * ====================================================================== */

#ifndef _WIN32

cn_err_t cn_ring_init(cn_ring_t *ring, const char *path, size_t size)
{
    if (ring == NULL || path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }
    if (size < CN_RING_SIZE_MIN || size > CN_RING_SIZE_MAX
            || size % 4096u != 0u) {
        return CN_ERR_INVAL;
    }

    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;

    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        CN_LOG_ERROR("open(\"%s\"): %s", path, CN_LOG_OS_ERR);
        return CN_ERR_IO;
    }
    ring->fd = fd;

    if (ftruncate(fd, (off_t)size) != 0) {
        CN_LOG_ERROR("ftruncate(\"%s\"): %s", path, CN_LOG_OS_ERR);
        cn_ring_destroy(ring);
        return CN_ERR_IO;
    }

    void *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        CN_LOG_ERROR("mmap(\"%s\"): %s", path, CN_LOG_OS_ERR);
        cn_ring_destroy(ring);
        return CN_ERR_NOMEM;
    }

    ring->base   = (uint8_t *)base;
    ring->size   = size;
    ring->mapped = true;
    return CN_OK;
}

cn_err_t cn_ring_flush(cn_ring_t *ring)
{
    if (ring == NULL || !ring->mapped) {
        return CN_ERR_INVAL;
    }
    if (msync(ring->base, ring->size, MS_SYNC) != 0) {
        return CN_ERR_IO;
    }
    return CN_OK;
}

void cn_ring_destroy(cn_ring_t *ring)
{
    if (ring == NULL) {
        return;
    }
    if (ring->mapped && ring->base != NULL) {
        (void)munmap(ring->base, ring->size);
        ring->base   = NULL;
        ring->mapped = false;
    }
    if (ring->fd >= 0) {
        (void)close(ring->fd);
        ring->fd = -1;
    }
}

#else /* _WIN32 */

cn_err_t cn_ring_init(cn_ring_t *ring, const char *path, size_t size)
{
    if (ring == NULL || path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }
    if (size < CN_RING_SIZE_MIN || size > CN_RING_SIZE_MAX
            || size % 4096u != 0u) {
        return CN_ERR_INVAL;
    }

    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;

    HANDLE fh = CreateFileA(path,
                            GENERIC_READ | GENERIC_WRITE,
                            0, NULL,
                            OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        CN_LOG_ERROR("CreateFileA(\"%s\"): %s", path, CN_LOG_OS_ERR);
        return CN_ERR_IO;
    }

    /* Extend or truncate the file to exactly size bytes. */
    LARGE_INTEGER sz;
    sz.QuadPart = (LONGLONG)size;
    if (!SetFilePointerEx(fh, sz, NULL, FILE_BEGIN) || !SetEndOfFile(fh)) {
        CN_LOG_ERROR("SetEndOfFile(\"%s\"): %s", path, CN_LOG_OS_ERR);
        CloseHandle(fh);
        return CN_ERR_IO;
    }

    HANDLE mh = CreateFileMappingA(fh, NULL, PAGE_READWRITE,
                                   (DWORD)((size) >> 32),
                                   (DWORD)((size) & 0xFFFFFFFFu),
                                   NULL);
    if (mh == NULL) {
        CN_LOG_ERROR("CreateFileMappingA(\"%s\"): %s", path, CN_LOG_OS_ERR);
        CloseHandle(fh);
        return CN_ERR_IO;
    }

    void *base = MapViewOfFile(mh, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (base == NULL) {
        CN_LOG_ERROR("MapViewOfFile(\"%s\"): %s", path, CN_LOG_OS_ERR);
        CloseHandle(mh);
        CloseHandle(fh);
        return CN_ERR_NOMEM;
    }

    int slot = win_slot_alloc(fh, mh);
    if (slot < 0) {
        (void)UnmapViewOfFile(base);
        CloseHandle(mh);
        CloseHandle(fh);
        return CN_ERR_NOMEM;
    }

    ring->base   = (uint8_t *)base;
    ring->size   = size;
    ring->fd     = slot;
    ring->mapped = true;
    return CN_OK;
}

cn_err_t cn_ring_flush(cn_ring_t *ring)
{
    if (ring == NULL || !ring->mapped) {
        return CN_ERR_INVAL;
    }
    if (!FlushViewOfFile(ring->base, ring->size)) {
        return CN_ERR_IO;
    }
    return CN_OK;
}

void cn_ring_destroy(cn_ring_t *ring)
{
    if (ring == NULL) {
        return;
    }
    if (ring->mapped && ring->base != NULL) {
        (void)UnmapViewOfFile(ring->base);
        ring->base   = NULL;
        ring->mapped = false;
    }
    if (ring->fd >= 0) {
        cn_win_ring_slot_t *slot = &g_win_slots[ring->fd];
        if (slot->map_handle != NULL
                && slot->map_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(slot->map_handle);
            slot->map_handle = NULL;
        }
        if (slot->file_handle != NULL
                && slot->file_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(slot->file_handle);
            slot->file_handle = NULL;
        }
        win_slot_free(ring->fd);
        ring->fd = -1;
    }
}

#endif /* _WIN32 */

/* =========================================================================
 * Platform-independent read / write / bytes_available
 * ====================================================================== */

cn_err_t cn_ring_write(cn_ring_t *ring, const uint8_t *data, size_t len)
{
    if (ring == NULL || data == NULL) {
        return CN_ERR_INVAL;
    }
    if (len == 0 || len > CN_RING_RECORD_MAX) {
        return CN_ERR_INVAL;
    }
    if (!ring->mapped) {
        return CN_ERR_INVAL;
    }

    uint64_t wh     = ring->write_head;            /* owned by this thread */
    uint64_t rh     = RING_LOAD(&ring->read_head); /* owned by reader */
    size_t   in_use = (size_t)(wh - rh);
    size_t   need   = 4u + len;

    if (ring->size - in_use < need) {
        return CN_ERR_OVERFLOW; /* Ring full — caller increments drop counter. */
    }

    /* Write 4-byte little-endian length prefix. */
    uint32_t len32 = (uint32_t)len;
    uint8_t  hdr[4];
    hdr[0] = (uint8_t)( len32        & 0xFFu);
    hdr[1] = (uint8_t)((len32 >>  8) & 0xFFu);
    hdr[2] = (uint8_t)((len32 >> 16) & 0xFFu);
    hdr[3] = (uint8_t)((len32 >> 24) & 0xFFu);

    ring_copy_in(ring->base, ring->size, wh,       hdr,  4u);
    ring_copy_in(ring->base, ring->size, wh + 4u, data, len);

    RING_STORE(&ring->write_head, wh + (uint64_t)need);
    return CN_OK;
}

cn_err_t cn_ring_read(cn_ring_t *ring, uint8_t *buf, size_t buf_size,
                      size_t *out_len)
{
    if (ring == NULL || buf == NULL || out_len == NULL) {
        return CN_ERR_INVAL;
    }
    if (buf_size < CN_PKT_SIZE_MAX) {
        return CN_ERR_INVAL;
    }
    if (!ring->mapped) {
        return CN_ERR_INVAL;
    }

    uint64_t wh     = RING_LOAD(&ring->write_head); /* owned by writer */
    uint64_t rh     = ring->read_head;              /* owned by this thread */
    size_t   in_use = (size_t)(wh - rh);

    if (in_use < 4u) {
        return CN_ERR_IO; /* Ring empty. */
    }

    /* Read the 4-byte little-endian length prefix. */
    uint8_t hdr[4];
    ring_copy_out(ring->base, ring->size, rh, hdr, 4u);

    uint32_t pkt_len = (uint32_t)hdr[0]
                     | ((uint32_t)hdr[1] <<  8)
                     | ((uint32_t)hdr[2] << 16)
                     | ((uint32_t)hdr[3] << 24);

    if (pkt_len == 0u || pkt_len > CN_PKT_SIZE_MAX) {
        return CN_ERR_IO; /* Corrupted record. */
    }
    if (in_use < 4u + (size_t)pkt_len) {
        return CN_ERR_IO; /* Partial record — write not yet complete. */
    }

    ring_copy_out(ring->base, ring->size, rh + 4u, buf, (size_t)pkt_len);
    RING_STORE(&ring->read_head, rh + 4u + (uint64_t)pkt_len);

    *out_len = (size_t)pkt_len;
    return CN_OK;
}

size_t cn_ring_bytes_available(const cn_ring_t *ring)
{
    if (ring == NULL || !ring->mapped) {
        return 0u;
    }
    uint64_t wh = RING_LOAD(&ring->write_head);
    uint64_t rh = RING_LOAD(&ring->read_head);
    return (size_t)(wh - rh);
}
