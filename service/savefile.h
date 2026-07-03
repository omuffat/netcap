#ifndef CN_SAVEFILE_H
#define CN_SAVEFILE_H

#include <stdint.h>
#include "../core/constants.h"
#include "../core/ring.h"

/* Forward declaration — include upload_queue.h for the full definition. */
typedef struct cn_upload_queue cn_upload_queue_t;

/* -------------------------------------------------------------------------
 * Savefile writer context (opaque)
 * ---------------------------------------------------------------------- */

/**
 * Per-interface savefile writer.  Runs a background thread that drains the
 * ring buffer and writes packets to rotating .pcap files in savefile_dir.
 *
 * Filename format:
 *   netcap_<iface>_<YYYY>_<MM>_<DD>_<HH>_<mm>_<SS>.pcap
 * where the timestamp is the moment the file was opened (local time).
 *
 * Rotation: a new file is opened every rotation_secs seconds.  When the
 * number of files for this interface reaches max_count, the oldest file is
 * deleted before a new one is created.  Incomplete files from a previous
 * service run are counted but not deleted pre-emptively.
 */
typedef struct cn_savefile_ctx cn_savefile_ctx_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief Allocate a savefile writer context.
 *
 * Validates parameters and allocates the context.  Does not open any file
 * or start any thread.  Call cn_savefile_start() when ready to begin.
 *
 * @security savefile_dir and iface_name are validated against their
 *           CN_*_MAX limits.  The writer thread creates files with mode
 *           0600.  Do not place savefile_dir in a world-writable location.
 *
 * @param[out] ctx           Set to the allocated context on success.
 *                           Must not be NULL.
 * @param[in]  ring          Initialized ring buffer to drain. Must not be NULL.
 * @param[in]  savefile_dir  Directory for .pcap output files. Must not be NULL.
 *                           Length must be < CN_PATH_MAX.
 * @param[in]  iface_name    Interface name used in filenames. Must not be NULL.
 *                           Length must be < CN_IFACE_NAME_MAX.
 * @param[in]  link_type     DLT_* link-layer type for the pcap global header.
 * @param[in]  snaplen       Maximum bytes stored per packet. Must be > 0
 *                           and <= CN_PKT_SIZE_MAX.
 * @param[in]  rotation_secs File rotation interval in seconds.
 *                           Must be in [CN_SAVEFILE_ROTATION_SECS_MIN,
 *                                       CN_SAVEFILE_ROTATION_SECS_MAX].
 * @param[in]  max_count     Maximum files retained per interface.
 *                           Must be in [CN_SAVEFILE_MAX_COUNT_MIN,
 *                                       CN_SAVEFILE_MAX_COUNT_MAX].
 * @param[in]  upload_queue  Upload queue to push completed savefiles to on
 *                           rotation, or NULL to disable automatic upload for
 *                           this interface.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if any required pointer is NULL or any parameter is
 *                       out of range.
 * @return CN_ERR_NOMEM  if allocation fails.
 */
cn_err_t cn_savefile_init(cn_savefile_ctx_t **ctx,
                          cn_ring_t          *ring,
                          const char         *savefile_dir,
                          const char         *iface_name,
                          int                 link_type,
                          uint32_t            snaplen,
                          uint32_t            rotation_secs,
                          uint32_t            max_count,
                          cn_upload_queue_t  *upload_queue)
    __attribute__((warn_unused_result));

/**
 * @brief Open the first output file and start the writer thread.
 *
 * @security Must be called only after cn_caps_drop() has been invoked —
 *           the writer thread itself requires no elevated privileges.
 *
 * @param[in,out] ctx  Initialized (but not yet started) context.
 *                     Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if ctx is NULL or is already running.
 * @return CN_ERR_IO     if the first output file cannot be opened or the
 *                       thread cannot be created.
 */
cn_err_t cn_savefile_start(cn_savefile_ctx_t *ctx)
    __attribute__((warn_unused_result));

/**
 * @brief Signal the writer thread to stop, drain the ring, and wait for exit.
 *
 * After this call returns, all packets that were in the ring at the time of
 * the call have been written to disk and the current pcap file is closed.
 * Safe to call if the context was never started (no-op in that case).
 *
 * @param[in,out] ctx  Running savefile context. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if ctx is NULL.
 * @return CN_ERR_IO    if the thread join fails.
 */
cn_err_t cn_savefile_stop(cn_savefile_ctx_t *ctx)
    __attribute__((warn_unused_result));

/**
 * @brief Stop the writer (if running) and free all resources.
 *
 * Sets *ctx to NULL on return.
 *
 * @param[in,out] ctx  Pointer to a savefile context pointer. Must not be NULL.
 *                     *ctx may be NULL (no-op).
 */
void cn_savefile_destroy(cn_savefile_ctx_t **ctx);

#endif /* CN_SAVEFILE_H */
