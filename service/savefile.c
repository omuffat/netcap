/* GCC 10+ does not suppress warn_unused_result via (void) cast. */
#define DISCARD(x)  do { cn_err_t _r_ = (x); (void)_r_; } while (0)

#include "savefile.h"
#include "upload_queue.h"
#include "../core/pcap_writer.h"
#include "../core/log.h"
#include "../core/str.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifndef _WIN32
#  include <pthread.h>
#  include <dirent.h>
#  include <unistd.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* =========================================================================
 * Opaque context
 * ====================================================================== */

struct cn_savefile_ctx {
    cn_ring_t          *ring;
    cn_pcap_writer_t   *writer;          /* Current open pcap file, or NULL. */

    char  savefile_dir[CN_PATH_MAX];
    char  iface_name[CN_IFACE_NAME_MAX];
    int   link_type;
    uint32_t snaplen;
    uint32_t rotation_secs;
    uint32_t max_count;

    char  current_path[CN_PATH_MAX];     /* Path of the currently open savefile. */
    cn_upload_queue_t *upload_queue;     /* NULL if auto-upload is disabled. */

    time_t  rotation_start;             /* When the current file was opened. */
    volatile int  running;
    int           thread_started;

#ifndef _WIN32
    pthread_t thread;
#else
    HANDLE    thread;
#endif
};

/* -------------------------------------------------------------------------
 * Atomic helpers for the running flag.
 * ---------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#  define SF_LOAD(ctx)     __atomic_load_n(&(ctx)->running, __ATOMIC_ACQUIRE)
#  define SF_STORE(ctx, v) __atomic_store_n(&(ctx)->running, (v), __ATOMIC_RELEASE)
#else
#  define SF_LOAD(ctx)     ((ctx)->running)
#  define SF_STORE(ctx, v) ((ctx)->running = (v))
#endif

/* =========================================================================
 * Internal helpers
 * ====================================================================== */

/*
 * build_filename: construct the next savefile path using the current time.
 * Format: <savefile_dir>/netcap_<iface>_<YYYY>_<MM>_<DD>_<HH>_<mm>_<SS>.pcap
 * Returns CN_ERR_OVERFLOW if the path would exceed CN_PATH_MAX.
 */
static cn_err_t build_filename(char *out, size_t out_size,
                               const char *savefile_dir,
                               const char *iface_name)
{
    time_t    now = time(NULL);
    struct tm tm_buf;

#ifndef _WIN32
    localtime_r(&now, &tm_buf);
#else
    localtime_s(&tm_buf, &now);
#endif

    int n = snprintf(out, out_size,
                     "%s/netcap_%s_%04d_%02d_%02d_%02d_%02d_%02d.pcap",
                     savefile_dir, iface_name,
                     tm_buf.tm_year + 1900,
                     tm_buf.tm_mon  + 1,
                     tm_buf.tm_mday,
                     tm_buf.tm_hour,
                     tm_buf.tm_min,
                     tm_buf.tm_sec);

    if (n < 0 || (size_t)n >= out_size) {
        return CN_ERR_OVERFLOW;
    }
    return CN_OK;
}

/*
 * delete_oldest_savefile: scan savefile_dir for files matching
 * "netcap_<iface>_*.pcap" and delete the lexicographically smallest one
 * (which is also the chronologically oldest).
 *
 * Called when the file count reaches max_count before a rotation.
 * Preconditions: savefile_dir and iface_name are non-empty, validated.
 */
static void delete_oldest_savefile(const char *savefile_dir,
                                   const char *iface_name)
{
    /* Build the prefix to match against: "netcap_<iface>_" */
    char prefix[CN_IFACE_NAME_MAX + 8u]; /* "netcap_" + iface + "_" + NUL */
    int  n = snprintf(prefix, sizeof(prefix), "netcap_%s_", iface_name);
    if (n < 0 || (size_t)n >= sizeof(prefix)) {
        return;
    }
    size_t prefix_len = (size_t)n;

    char oldest[CN_PATH_MAX];
    oldest[0] = '\0';

#ifndef _WIN32
    DIR           *d = opendir(savefile_dir);
    struct dirent *e;
    if (d == NULL) {
        return;
    }
    while ((e = readdir(d)) != NULL) {
        const char *name = e->d_name;
        size_t      nlen = cn_strnlen(name, CN_PATH_MAX);

        /* Must start with prefix and end with ".pcap". */
        if (nlen <= prefix_len + 5u) {
            continue;
        }
        if (strncmp(name, prefix, prefix_len) != 0) {
            continue;
        }
        if (strcmp(name + nlen - 5u, ".pcap") != 0) {
            continue;
        }
        /* Lexicographically smallest = oldest. */
        if (oldest[0] == '\0' || strcmp(name, oldest) < 0) {
            DISCARD(cn_strlcpy(oldest, name, CN_PATH_MAX));
        }
    }
    closedir(d);

    if (oldest[0] != '\0') {
        char full_path[CN_PATH_MAX];
        n = snprintf(full_path, sizeof(full_path),
                     "%s/%s", savefile_dir, oldest);
        if (n > 0 && (size_t)n < sizeof(full_path)) {
            (void)unlink(full_path);
        }
    }

#else /* _WIN32 */
    char pattern[CN_PATH_MAX];
    n = snprintf(pattern, sizeof(pattern), "%s\\netcap_%s_*.pcap",
                 savefile_dir, iface_name);
    if (n < 0 || (size_t)n >= sizeof(pattern)) {
        return;
    }

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        const char *name = fd.cFileName;
        if (oldest[0] == '\0' || strcmp(name, oldest) < 0) {
            DISCARD(cn_strlcpy(oldest, name, CN_PATH_MAX));
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (oldest[0] != '\0') {
        char full_path[CN_PATH_MAX];
        n = snprintf(full_path, sizeof(full_path),
                     "%s\\%s", savefile_dir, oldest);
        if (n > 0 && (size_t)n < sizeof(full_path)) {
            DeleteFileA(full_path);
        }
    }
#endif /* _WIN32 */
}

/*
 * count_savefiles: count the number of existing savefiles for this interface.
 */
static uint32_t count_savefiles(const char *savefile_dir,
                                const char *iface_name)
{
    char prefix[CN_IFACE_NAME_MAX + 8u];
    int n = snprintf(prefix, sizeof(prefix), "netcap_%s_", iface_name);
    if (n < 0 || (size_t)n >= sizeof(prefix)) {
        return 0u;
    }
    size_t   prefix_len = (size_t)n;
    uint32_t count      = 0u;

#ifndef _WIN32
    DIR           *d = opendir(savefile_dir);
    struct dirent *e;
    if (d == NULL) {
        return 0u;
    }
    while ((e = readdir(d)) != NULL) {
        const char *name = e->d_name;
        size_t      nlen = cn_strnlen(name, CN_PATH_MAX);
        if (nlen <= prefix_len + 5u) continue;
        if (strncmp(name, prefix, prefix_len) != 0) continue;
        if (strcmp(name + nlen - 5u, ".pcap") != 0) continue;
        count++;
    }
    closedir(d);
#else
    char pattern[CN_PATH_MAX];
    n = snprintf(pattern, sizeof(pattern), "%s\\netcap_%s_*.pcap",
                 savefile_dir, iface_name);
    if (n < 0 || (size_t)n >= sizeof(pattern)) {
        return 0u;
    }
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do { count++; } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#endif

    return count;
}

/*
 * open_next_file: enforce max_count, build filename, open a new pcap file.
 * Precondition: ctx->writer == NULL.
 */
static cn_err_t open_next_file(cn_savefile_ctx_t *ctx)
{
    /* Enforce the file count limit before creating a new file. */
    while (count_savefiles(ctx->savefile_dir, ctx->iface_name)
               >= ctx->max_count) {
        delete_oldest_savefile(ctx->savefile_dir, ctx->iface_name);
    }

    char path[CN_PATH_MAX];
    cn_err_t rc = build_filename(path, sizeof(path),
                                 ctx->savefile_dir, ctx->iface_name);
    if (rc != CN_OK) {
        return rc;
    }

    rc = cn_pcap_writer_open(&ctx->writer, path,
                             ctx->link_type, ctx->snaplen);
    if (rc != CN_OK) {
        CN_LOG_ERROR("failed to create savefile \"%s\"", path);
        return rc;
    }

    DISCARD(cn_strlcpy(ctx->current_path, path, CN_PATH_MAX));
    ctx->rotation_start = time(NULL);
    return CN_OK;
}

/*
 * write_one_packet: parse a compound ring record and write it to the
 * current pcap file.
 *
 * Ring record layout (written by capture.c pcap_callback):
 *   [ts_sec(4 LE)][ts_usec(4 LE)][orig_len(4 LE)][packet bytes(caplen)]
 *
 * Preconditions: ctx->writer != NULL, record != NULL, record_len >= 13.
 */
static cn_err_t write_one_packet(cn_savefile_ctx_t *ctx,
                                 const uint8_t *record, size_t record_len)
{
    if (record_len < 13u) {
        return CN_ERR_INVAL;
    }

    uint32_t ts_sec  = (uint32_t)record[0]
                     | ((uint32_t)record[1] <<  8)
                     | ((uint32_t)record[2] << 16)
                     | ((uint32_t)record[3] << 24);
    uint32_t ts_usec = (uint32_t)record[4]
                     | ((uint32_t)record[5] <<  8)
                     | ((uint32_t)record[6] << 16)
                     | ((uint32_t)record[7] << 24);
    uint32_t orig_len = (uint32_t)record[8]
                      | ((uint32_t)record[9]  <<  8)
                      | ((uint32_t)record[10] << 16)
                      | ((uint32_t)record[11] << 24);

    uint32_t caplen = (uint32_t)(record_len - 12u);

    return cn_pcap_writer_write(ctx->writer,
                                record + 12u,
                                caplen,
                                orig_len,
                                ts_sec,
                                ts_usec);
}

/* =========================================================================
 * Writer thread
 * ====================================================================== */

/*
 * savefile_worker: reads records from the ring and writes them to pcap files.
 * Handles rotation and max_count enforcement.
 */
#ifndef _WIN32
static void *savefile_worker(void *arg)
#else
static DWORD WINAPI savefile_worker(LPVOID arg)
#endif
{
    cn_savefile_ctx_t *ctx = (cn_savefile_ctx_t *)arg;
    uint8_t            record[CN_RING_RECORD_MAX];

    while (SF_LOAD(ctx)) {
        size_t   record_len = 0;
        cn_err_t rc = cn_ring_read(ctx->ring, record, sizeof(record),
                                   &record_len);

        if (rc == CN_OK && ctx->writer != NULL) {
            (void)write_one_packet(ctx, record, record_len);
        } else if (rc != CN_OK) {
            /* Ring empty — yield to avoid busy-waiting. */
#ifndef _WIN32
            struct timespec ts = { 0, 1000000L }; /* 1 ms */
            nanosleep(&ts, NULL);
#else
            Sleep(1);
#endif
        }

        /* Check rotation. */
        if (ctx->writer != NULL
                && (time(NULL) - ctx->rotation_start)
                       >= (time_t)ctx->rotation_secs) {
            /* Capture the completed path before open_next_file() overwrites it. */
            char completed_path[CN_PATH_MAX];
            DISCARD(cn_strlcpy(completed_path, ctx->current_path, CN_PATH_MAX));

            DISCARD(cn_pcap_writer_close(&ctx->writer));

            if (ctx->upload_queue != NULL && completed_path[0] != '\0') {
                DISCARD(cn_upload_queue_push(ctx->upload_queue,
                                             completed_path,
                                             ctx->iface_name));
            }

            (void)open_next_file(ctx);
        }
    }

    /* Drain remaining ring data after stop is signalled. */
    size_t record_len = 0;
    while (cn_ring_read(ctx->ring, record, sizeof(record), &record_len)
               == CN_OK) {
        if (ctx->writer != NULL) {
            (void)write_one_packet(ctx, record, record_len);
        }
    }

    /* Close the current pcap file. */
    if (ctx->writer != NULL) {
        DISCARD(cn_pcap_writer_close(&ctx->writer));
    }

#ifndef _WIN32
    return NULL;
#else
    return 0;
#endif
}

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_savefile_init(cn_savefile_ctx_t **ctx,
                          cn_ring_t          *ring,
                          const char         *savefile_dir,
                          const char         *iface_name,
                          int                 link_type,
                          uint32_t            snaplen,
                          uint32_t            rotation_secs,
                          uint32_t            max_count,
                          cn_upload_queue_t  *upload_queue)
{
    if (ctx == NULL || ring == NULL
            || savefile_dir == NULL || iface_name == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(savefile_dir, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(iface_name, CN_IFACE_NAME_MAX) >= CN_IFACE_NAME_MAX) {
        return CN_ERR_INVAL;
    }
    if (snaplen == 0u || snaplen > CN_PKT_SIZE_MAX) {
        return CN_ERR_INVAL;
    }
    if (rotation_secs < CN_SAVEFILE_ROTATION_SECS_MIN
            || rotation_secs > CN_SAVEFILE_ROTATION_SECS_MAX) {
        return CN_ERR_INVAL;
    }
    if (max_count < CN_SAVEFILE_MAX_COUNT_MIN
            || max_count > CN_SAVEFILE_MAX_COUNT_MAX) {
        return CN_ERR_INVAL;
    }

    cn_savefile_ctx_t *c = (cn_savefile_ctx_t *)malloc(sizeof(*c));
    if (c == NULL) {
        return CN_ERR_NOMEM;
    }
    memset(c, 0, sizeof(*c));

    c->ring          = ring;
    c->link_type     = link_type;
    c->snaplen       = snaplen;
    c->rotation_secs = rotation_secs;
    c->max_count     = max_count;
    c->upload_queue  = upload_queue;  /* NULL = auto-upload disabled. */
    DISCARD(cn_strlcpy(c->savefile_dir, savefile_dir, CN_PATH_MAX));
    DISCARD(cn_strlcpy(c->iface_name,   iface_name,   CN_IFACE_NAME_MAX));

    *ctx = c;
    return CN_OK;
}

cn_err_t cn_savefile_start(cn_savefile_ctx_t *ctx)
{
    if (ctx == NULL) {
        return CN_ERR_INVAL;
    }
    if (ctx->thread_started) {
        return CN_ERR_INVAL;
    }

    cn_err_t rc = open_next_file(ctx);
    if (rc != CN_OK) {
        return rc;
    }

    SF_STORE(ctx, 1);

#ifndef _WIN32
    if (pthread_create(&ctx->thread, NULL, savefile_worker, ctx) != 0) {
        CN_LOG_ERROR("pthread_create (savefile \"%s\"): %s",
                     ctx->iface_name, CN_LOG_OS_ERR);
        SF_STORE(ctx, 0);
        DISCARD(cn_pcap_writer_close(&ctx->writer));
        return CN_ERR_IO;
    }
#else
    ctx->thread = CreateThread(NULL, 0, savefile_worker, ctx, 0, NULL);
    if (ctx->thread == NULL) {
        CN_LOG_ERROR("CreateThread (savefile \"%s\"): %s",
                     ctx->iface_name, CN_LOG_OS_ERR);
        SF_STORE(ctx, 0);
        DISCARD(cn_pcap_writer_close(&ctx->writer));
        return CN_ERR_IO;
    }
#endif

    ctx->thread_started = 1;
    return CN_OK;
}

cn_err_t cn_savefile_stop(cn_savefile_ctx_t *ctx)
{
    if (ctx == NULL) {
        return CN_ERR_INVAL;
    }
    if (!ctx->thread_started) {
        return CN_OK;
    }

    SF_STORE(ctx, 0);

#ifndef _WIN32
    int join_ret = pthread_join(ctx->thread, NULL);
    if (join_ret != 0) {
        CN_LOG_ERROR("pthread_join (savefile \"%s\"): %s",
                     ctx->iface_name, CN_LOG_OS_ERR);
    }
    cn_err_t rc = (join_ret == 0) ? CN_OK : CN_ERR_IO;
#else
    cn_err_t rc = CN_OK;
    if (WaitForSingleObject(ctx->thread, INFINITE) != WAIT_OBJECT_0) {
        CN_LOG_ERROR("WaitForSingleObject (savefile \"%s\"): %s",
                     ctx->iface_name, CN_LOG_OS_ERR);
        rc = CN_ERR_IO;
    }
    CloseHandle(ctx->thread);
    ctx->thread = NULL;
#endif

    ctx->thread_started = 0;
    return rc;
}

void cn_savefile_destroy(cn_savefile_ctx_t **ctx)
{
    if (ctx == NULL || *ctx == NULL) {
        return;
    }

    DISCARD(cn_savefile_stop(*ctx));

    if ((*ctx)->writer != NULL) {
        DISCARD(cn_pcap_writer_close(&(*ctx)->writer));
    }

    free(*ctx);
    *ctx = NULL;
}
