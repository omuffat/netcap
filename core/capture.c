#include "capture.h"
#include "filter.h"
#include "log.h"
#include "str.h"

#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#ifndef _WIN32
#  include <pthread.h>
#  include <time.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* =========================================================================
 * Opaque capture context
 * ====================================================================== */

struct cn_capture_ctx {
    pcap_t             *handle;
    cn_ring_t          *ring;
    cn_filter_t        *filter;          /* NULL when no filter was applied. */
    cn_capture_stats_t  stats;           /* Updated by capture thread. */
    char                iface_name[CN_IFACE_NAME_MAX];
    int                 snaplen;
    int                 link_type;       /* DLT_* value from pcap_datalink(). */

    /*
     * running: 1 = threads are active, 0 = stop requested.
     * Written by cn_capture_stop() (any thread), read by worker threads.
     * Declared volatile; GCC/Clang __atomic_* intrinsics are used for
     * proper acquire/release semantics.
     */
    volatile int        running;
    int                 threads_started;

#ifndef _WIN32
    pthread_t           capture_thread;
    pthread_t           msync_thread;
#else
    HANDLE              capture_thread;
    HANDLE              msync_thread;
#endif
};

/* -------------------------------------------------------------------------
 * Atomic helpers for the running flag.
 * ---------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
#  define CTX_LOAD_RUNNING(ctx) \
       __atomic_load_n(&(ctx)->running, __ATOMIC_ACQUIRE)
#  define CTX_STORE_RUNNING(ctx, v) \
       __atomic_store_n(&(ctx)->running, (v), __ATOMIC_RELEASE)
#else
#  define CTX_LOAD_RUNNING(ctx)     ((ctx)->running)
#  define CTX_STORE_RUNNING(ctx, v) ((ctx)->running = (v))
#endif

/* =========================================================================
 * pcap callback — invoked by pcap_loop() in the capture thread.
 *
 * Ring record layout (written by this function, consumed by savefile.c):
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *        0     4  ts_sec   — capture timestamp, whole seconds (LE uint32)
 *        4     4  ts_usec  — capture timestamp, microseconds  (LE uint32)
 *        8     4  orig_len — original on-wire packet length   (LE uint32)
 *       12  caplen  data   — captured packet bytes
 *
 * Total record size: 12 + caplen bytes, max CN_RING_RECORD_MAX.
 *
 * Preconditions: header->caplen has been verified by libpcap to be <= snaplen.
 * The caplen guard below is the mandatory defence against untrusted network
 * input per the project security rules.
 * ====================================================================== */

static void pcap_callback(u_char *user,
                          const struct pcap_pkthdr *header,
                          const u_char *pkt_data)
{
    cn_capture_ctx_t *ctx = (cn_capture_ctx_t *)(void *)user;

    ctx->stats.pkts_received++;

    /* Reject oversized packets before any copy. */
    if (header->caplen == 0 || header->caplen > CN_PKT_SIZE_MAX) {
        return;
    }

    /*
     * Build a compound ring record: [metadata(12)][packet data(caplen)].
     * Using a fixed-size stack buffer is safe here — this thread has a
     * typical stack of 1-8 MiB and CN_RING_RECORD_MAX is ~64 KiB.
     */
    uint8_t  record[CN_RING_RECORD_MAX];
    uint32_t ts_sec   = (uint32_t)header->ts.tv_sec;
    uint32_t ts_usec  = (uint32_t)header->ts.tv_usec;
    uint32_t orig_len = header->len;

    record[0] = (uint8_t)( ts_sec        & 0xFFu);
    record[1] = (uint8_t)((ts_sec >>  8) & 0xFFu);
    record[2] = (uint8_t)((ts_sec >> 16) & 0xFFu);
    record[3] = (uint8_t)((ts_sec >> 24) & 0xFFu);
    record[4] = (uint8_t)( ts_usec        & 0xFFu);
    record[5] = (uint8_t)((ts_usec >>  8) & 0xFFu);
    record[6] = (uint8_t)((ts_usec >> 16) & 0xFFu);
    record[7] = (uint8_t)((ts_usec >> 24) & 0xFFu);
    record[8]  = (uint8_t)( orig_len        & 0xFFu);
    record[9]  = (uint8_t)((orig_len >>  8) & 0xFFu);
    record[10] = (uint8_t)((orig_len >> 16) & 0xFFu);
    record[11] = (uint8_t)((orig_len >> 24) & 0xFFu);
    memcpy(record + 12, pkt_data, header->caplen);

    cn_err_t rc = cn_ring_write(ctx->ring, record, 12u + header->caplen);
    if (rc == CN_OK) {
        ctx->stats.pkts_written++;
        ctx->stats.bytes_written += header->caplen;
    }
    /* CN_ERR_OVERFLOW = ring full; packet silently dropped.
     * pkts_dropped is refreshed from pcap_stats() in cn_capture_get_stats(). */
}

/* =========================================================================
 * Worker thread functions
 * ====================================================================== */

/*
 * capture_worker: drives pcap_loop() until pcap_breakloop() is called.
 * Runs in its own thread; ctx->ring must remain valid until this exits.
 */
#ifndef _WIN32
static void *capture_worker(void *arg)
{
    cn_capture_ctx_t *ctx = (cn_capture_ctx_t *)arg;
    /* pcap_loop returns when pcap_breakloop() is called or a fatal error
     * occurs.  The return value is intentionally discarded here; errors are
     * visible to the caller via cn_capture_get_stats(). */
    (void)pcap_loop(ctx->handle, 0, pcap_callback, (u_char *)ctx);
    return NULL;
}

/*
 * msync_worker: periodically flushes dirty ring pages to disk.
 * Wakes every 500 ms, calls cn_ring_flush(), then checks the running flag.
 */
static void *msync_worker(void *arg)
{
    cn_capture_ctx_t *ctx = (cn_capture_ctx_t *)arg;
    struct timespec   ts  = { 0, 500000000L }; /* 500 ms */

    while (CTX_LOAD_RUNNING(ctx)) {
        nanosleep(&ts, NULL);
        if (ctx->ring->mapped) {
            cn_err_t rc_f = cn_ring_flush(ctx->ring);
            (void)rc_f; /* Best-effort flush; errors are non-fatal in worker. */
        }
    }

    /* Final flush after the stop signal. */
    if (ctx->ring->mapped) {
        cn_err_t rc_f = cn_ring_flush(ctx->ring);
        (void)rc_f;
    }
    return NULL;
}

#else /* _WIN32 */

static DWORD WINAPI capture_worker(LPVOID arg)
{
    cn_capture_ctx_t *ctx = (cn_capture_ctx_t *)arg;
    (void)pcap_loop(ctx->handle, 0, pcap_callback, (u_char *)ctx);
    return 0;
}

static DWORD WINAPI msync_worker(LPVOID arg)
{
    cn_capture_ctx_t *ctx = (cn_capture_ctx_t *)arg;

    while (CTX_LOAD_RUNNING(ctx)) {
        Sleep(500);
        if (ctx->ring->mapped) {
            (void)cn_ring_flush(ctx->ring);
        }
    }

    if (ctx->ring->mapped) {
        (void)cn_ring_flush(ctx->ring);
    }
    return 0;
}
#endif /* _WIN32 */

/* =========================================================================
 * Internal thread start / join helpers
 * ====================================================================== */

/*
 * start_threads: spawn capture_worker and msync_worker.
 * On failure, any already-started thread is joined before returning.
 * Precondition: ctx->running == 1.
 */
static cn_err_t start_threads(cn_capture_ctx_t *ctx)
{
#ifndef _WIN32
    if (pthread_create(&ctx->capture_thread, NULL, capture_worker, ctx) != 0) {
        return CN_ERR_IO;
    }
    if (pthread_create(&ctx->msync_thread, NULL, msync_worker, ctx) != 0) {
        pcap_breakloop(ctx->handle);
        (void)pthread_join(ctx->capture_thread, NULL);
        return CN_ERR_IO;
    }
#else
    ctx->capture_thread = CreateThread(NULL, 0, capture_worker, ctx, 0, NULL);
    if (ctx->capture_thread == NULL) {
        return CN_ERR_IO;
    }
    ctx->msync_thread = CreateThread(NULL, 0, msync_worker, ctx, 0, NULL);
    if (ctx->msync_thread == NULL) {
        pcap_breakloop(ctx->handle);
        WaitForSingleObject(ctx->capture_thread, INFINITE);
        CloseHandle(ctx->capture_thread);
        ctx->capture_thread = NULL;
        return CN_ERR_IO;
    }
#endif
    return CN_OK;
}

/* join_threads: wait for both threads to exit. */
static cn_err_t join_threads(cn_capture_ctx_t *ctx)
{
    cn_err_t rc = CN_OK;

#ifndef _WIN32
    if (pthread_join(ctx->capture_thread, NULL) != 0) {
        rc = CN_ERR_IO;
    }
    if (pthread_join(ctx->msync_thread, NULL) != 0) {
        rc = CN_ERR_IO;
    }
#else
    HANDLE handles[2] = { ctx->capture_thread, ctx->msync_thread };
    if (WaitForMultipleObjects(2, handles, TRUE, INFINITE) == WAIT_FAILED) {
        rc = CN_ERR_IO;
    }
    CloseHandle(ctx->capture_thread);
    CloseHandle(ctx->msync_thread);
    ctx->capture_thread = NULL;
    ctx->msync_thread   = NULL;
#endif
    return rc;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_capture_init(cn_capture_ctx_t **ctx, const char *iface_name,
                         cn_ring_t *ring, int snaplen, const char *bpf_filter)
{
    if (ctx == NULL || iface_name == NULL || ring == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(iface_name, CN_IFACE_NAME_MAX) >= CN_IFACE_NAME_MAX) {
        return CN_ERR_INVAL;
    }
    if (snaplen <= 0 || (uint32_t)snaplen > CN_PKT_SIZE_MAX) {
        return CN_ERR_INVAL;
    }
    if (bpf_filter != NULL
            && cn_strnlen(bpf_filter, CN_BPF_FILTER_MAX) >= CN_BPF_FILTER_MAX) {
        return CN_ERR_INVAL;
    }

    cn_capture_ctx_t *c = (cn_capture_ctx_t *)malloc(sizeof(*c));
    if (c == NULL) {
        return CN_ERR_NOMEM;
    }
    memset(c, 0, sizeof(*c));

    c->ring    = ring;
    c->snaplen = snaplen;
    /* Length was validated above; cn_strlcpy cannot fail here. */
    cn_err_t rc_cpy = cn_strlcpy(c->iface_name, iface_name, CN_IFACE_NAME_MAX);
    (void)rc_cpy;

    char errbuf[PCAP_ERRBUF_SIZE];
    c->handle = pcap_open_live(iface_name,
                               snaplen,
                               1,    /* promiscuous mode */
                               1000, /* read timeout ms */
                               errbuf);
    if (c->handle == NULL) {
        CN_LOG_ERROR("pcap_open_live(\"%s\"): %s", iface_name, errbuf);
        free(c);
        return CN_ERR_IO;
    }

    c->link_type = pcap_datalink(c->handle);

    if (bpf_filter != NULL && bpf_filter[0] != '\0') {
        cn_err_t rc = cn_filter_compile(&c->filter, c->handle, bpf_filter);
        if (rc != CN_OK) {
            pcap_close(c->handle);
            free(c);
            return rc;
        }
        rc = cn_filter_apply(c->filter, c->handle);
        if (rc != CN_OK) {
            cn_filter_destroy(&c->filter);
            pcap_close(c->handle);
            free(c);
            return rc;
        }
    }

    *ctx = c;
    return CN_OK;
}

cn_err_t cn_capture_start(cn_capture_ctx_t *ctx)
{
    if (ctx == NULL) {
        return CN_ERR_INVAL;
    }
    if (ctx->threads_started) {
        return CN_ERR_INVAL; /* Already running. */
    }

    CTX_STORE_RUNNING(ctx, 1);

    cn_err_t rc = start_threads(ctx);
    if (rc != CN_OK) {
        CTX_STORE_RUNNING(ctx, 0);
        return rc;
    }

    ctx->threads_started = 1;
    return CN_OK;
}

cn_err_t cn_capture_stop(cn_capture_ctx_t *ctx)
{
    if (ctx == NULL) {
        return CN_ERR_INVAL;
    }
    if (!ctx->threads_started) {
        return CN_OK; /* Never started — nothing to do. */
    }

    CTX_STORE_RUNNING(ctx, 0);
    pcap_breakloop(ctx->handle); /* Unblock pcap_loop(). */

    cn_err_t rc = join_threads(ctx);
    ctx->threads_started = 0;
    return rc;
}

cn_err_t cn_capture_get_stats(const cn_capture_ctx_t *ctx,
                              cn_capture_stats_t *stats)
{
    if (ctx == NULL || stats == NULL) {
        return CN_ERR_INVAL;
    }

    struct pcap_stat ps;
    if (pcap_stats(ctx->handle, &ps) != 0) {
        return CN_ERR_IO;
    }

    /* Copy the in-memory counters, then overlay the driver-level counters. */
    *stats = ctx->stats;
    stats->pkts_dropped = (uint64_t)ps.ps_drop;
    stats->pkts_ifdrop  = (uint64_t)ps.ps_ifdrop;
    return CN_OK;
}

int cn_capture_get_link_type(const cn_capture_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }
    return ctx->link_type;
}

void cn_capture_destroy(cn_capture_ctx_t **ctx)
{
    if (ctx == NULL || *ctx == NULL) {
        return;
    }

    cn_err_t rc_stop = cn_capture_stop(*ctx);
    (void)rc_stop; /* Errors during destroy cannot be propagated. */

    if ((*ctx)->filter != NULL) {
        cn_filter_destroy(&(*ctx)->filter);
    }
    if ((*ctx)->handle != NULL) {
        pcap_close((*ctx)->handle);
    }

    free(*ctx);
    *ctx = NULL;
}
