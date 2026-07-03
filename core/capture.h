#ifndef CN_CAPTURE_H
#define CN_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
#include "constants.h"
#include "ring.h"

/* -------------------------------------------------------------------------
 * Capture statistics
 * ---------------------------------------------------------------------- */

/** Packet and byte counters for one capture context. */
typedef struct {
    uint64_t pkts_received;  /* Total packets delivered by the pcap loop. */
    uint64_t pkts_dropped;   /* Packets dropped by the kernel ring (from pcap_stats). */
    uint64_t pkts_ifdrop;    /* Packets dropped at the interface driver level. */
    uint64_t pkts_written;   /* Packets successfully written to the ring buffer. */
    uint64_t bytes_written;  /* Total payload bytes written to the ring buffer. */
} cn_capture_stats_t;

/* -------------------------------------------------------------------------
 * Capture context (opaque)
 * ---------------------------------------------------------------------- */

/** Per-interface capture session. Created by cn_capture_init(), freed by
 *  cn_capture_destroy(). Do not access members directly. */
typedef struct cn_capture_ctx cn_capture_ctx_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief Allocate and initialize a capture context for one network interface.
 *
 * Opens a live pcap handle on iface_name with the given snaplen and, if
 * bpf_filter is non-NULL, compiles and applies the BPF expression. Does NOT
 * start capture threads. Call cn_capture_start() when ready to begin.
 *
 * @security Requires CAP_NET_RAW (Linux) or administrator privilege (Windows).
 *           CAP_NET_RAW must be dropped via cn_caps_drop() after all capture
 *           contexts across all interfaces have been initialized.
 *           iface_name is validated against CN_IFACE_NAME_MAX.
 *           bpf_filter (if non-NULL) is validated against CN_BPF_FILTER_MAX.
 *
 * @param[out] ctx         Set to the allocated context on success. Must not be NULL.
 * @param[in]  iface_name  Network interface name (e.g., "eth0"). Must not be NULL.
 *                         Length must be < CN_IFACE_NAME_MAX.
 * @param[in]  ring        Pre-initialized ring buffer for this interface.
 *                         Must not be NULL and must be mapped.
 * @param[in]  snaplen     Maximum bytes captured per packet.
 *                         Must be > 0 and <= CN_PKT_SIZE_MAX.
 * @param[in]  bpf_filter  BPF filter expression string, or NULL for no filter.
 *                         If non-NULL, length must be < CN_BPF_FILTER_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if ctx, iface_name, or ring is NULL; or any parameter
 *                       exceeds its CN_*_MAX limit; or snaplen is 0.
 * @return CN_ERR_NOMEM  if memory allocation fails.
 * @return CN_ERR_IO     if the pcap handle cannot be opened.
 * @return CN_ERR_PERM   if the process lacks capture privileges.
 */
cn_err_t cn_capture_init(cn_capture_ctx_t **ctx, const char *iface_name,
                         cn_ring_t *ring, int snaplen, const char *bpf_filter)
    __attribute__((warn_unused_result));

/**
 * @brief Start the pcap capture thread and the msync_worker thread.
 *
 * Spawns two threads: a capture thread that calls pcap_loop() and writes each
 * packet into the ring buffer, and an msync_worker thread that periodically
 * calls cn_ring_flush() to persist data to disk.
 *
 * @security Must be called only after CAP_NET_RAW has been dropped via
 *           cn_caps_drop(). The context must not already be running.
 *
 * @param[in,out] ctx  Initialized (but not yet running) capture context.
 *                     Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if ctx is NULL or is already running.
 * @return CN_ERR_IO    if thread creation fails.
 */
cn_err_t cn_capture_start(cn_capture_ctx_t *ctx)
    __attribute__((warn_unused_result));

/**
 * @brief Signal capture and msync_worker threads to stop and wait for exit.
 *
 * Calls pcap_breakloop() on the capture handle, then joins both threads.
 * Blocks until both threads have fully exited. Safe to call if the context
 * was never started (no-op in that case).
 *
 * @param[in,out] ctx  Running capture context. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if ctx is NULL.
 * @return CN_ERR_IO    if a thread join call fails.
 */
cn_err_t cn_capture_stop(cn_capture_ctx_t *ctx)
    __attribute__((warn_unused_result));

/**
 * @brief Copy current capture statistics for this context.
 *
 * Reads counters atomically. The pcap driver counters (pkts_dropped,
 * pkts_ifdrop) are refreshed from pcap_stats() at the time of this call.
 *
 * @param[in]  ctx    Initialized capture context. Must not be NULL.
 * @param[out] stats  Output statistics structure. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if ctx or stats is NULL.
 * @return CN_ERR_IO    if pcap_stats() fails.
 */
cn_err_t cn_capture_get_stats(const cn_capture_ctx_t *ctx,
                              cn_capture_stats_t *stats)
    __attribute__((warn_unused_result));

/**
 * @brief Return the DLT_* link-layer type of the underlying pcap handle.
 *
 * Used by the savefile writer to open a pcap file with the correct network
 * layer type (e.g. DLT_EN10MB for Ethernet, DLT_NULL for loopback).
 *
 * @param[in] ctx  Initialized capture context. Must not be NULL.
 *
 * @return DLT_* value on success.
 * @return -1 if ctx is NULL.
 */
int cn_capture_get_link_type(const cn_capture_ctx_t *ctx);

/**
 * @brief Stop capture (if running) and free all resources.
 *
 * Calls cn_capture_stop() if the context is running, then closes the pcap
 * handle and frees the context structure. Sets *ctx to NULL on return.
 *
 * @param[in,out] ctx  Pointer to a capture context pointer. Must not be NULL.
 *                     *ctx may be NULL (no-op).
 */
void cn_capture_destroy(cn_capture_ctx_t **ctx);

#endif /* CN_CAPTURE_H */
