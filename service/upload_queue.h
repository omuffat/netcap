#ifndef CN_UPLOAD_QUEUE_H
#define CN_UPLOAD_QUEUE_H

#include "../core/constants.h"

/* Maximum number of pending upload entries before new ones are dropped. */
#define CN_UPLOAD_QUEUE_CAPACITY 64u

/* Opaque upload queue type. */
typedef struct cn_upload_queue cn_upload_queue_t;

/**
 * @brief Create an upload queue.
 *
 * Allocates the queue and initialises its synchronisation primitives.
 * The queue is empty and not shut down on return.
 *
 * @param[out] q  Set to the allocated queue on success. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if q is NULL.
 * @return CN_ERR_NOMEM if allocation fails.
 * @return CN_ERR_IO    if mutex or condvar initialisation fails.
 */
cn_err_t cn_upload_queue_create(cn_upload_queue_t **q)
    __attribute__((warn_unused_result));

/**
 * @brief Push a completed savefile path onto the queue (non-blocking).
 *
 * If the queue is at CN_UPLOAD_QUEUE_CAPACITY, the new entry is dropped
 * and CN_ERR_OVERFLOW is returned; a warning is logged.  The file remains
 * on disk and can be uploaded manually.
 *
 * Safe to call concurrently with cn_upload_queue_pop().
 *
 * @param[in] q          Upload queue. Must not be NULL.
 * @param[in] file_path  Absolute path of the completed savefile.
 *                       Length must be < CN_PATH_MAX. Must not be NULL.
 * @param[in] iface_name Interface name. Length must be < CN_IFACE_NAME_MAX.
 *                       Must not be NULL.
 *
 * @return CN_OK          on success.
 * @return CN_ERR_INVAL   if any pointer is NULL.
 * @return CN_ERR_OVERFLOW if the queue is full (entry dropped, logged).
 */
cn_err_t cn_upload_queue_push(cn_upload_queue_t *q,
                               const char        *file_path,
                               const char        *iface_name)
    __attribute__((warn_unused_result));

/**
 * @brief Pop the next entry from the queue (blocking).
 *
 * Blocks until an entry is available or the queue is shut down.  When the
 * queue is shut down, any entries that were queued before the shutdown are
 * drained before CN_ERR_INVAL is returned.
 *
 * @param[in]  q               Upload queue. Must not be NULL.
 * @param[out] file_path_out   Receives the file path. Must be CN_PATH_MAX bytes.
 *                             Must not be NULL.
 * @param[out] iface_name_out  Receives the interface name.
 *                             Must be CN_IFACE_NAME_MAX bytes. Must not be NULL.
 *
 * @return CN_OK       on success (entry written to out buffers).
 * @return CN_ERR_INVAL if any pointer is NULL, or the queue is shut down and
 *                      empty (caller should exit the worker loop).
 */
cn_err_t cn_upload_queue_pop(cn_upload_queue_t *q,
                              char              *file_path_out,
                              char              *iface_name_out)
    __attribute__((warn_unused_result));

/**
 * @brief Signal the queue to shut down.
 *
 * Sets the shutdown flag and wakes any thread blocked in cn_upload_queue_pop().
 * The blocked pop will drain remaining entries before returning CN_ERR_INVAL.
 * Safe to call from any thread.
 *
 * @param[in] q  Upload queue. Must not be NULL.
 */
void cn_upload_queue_shutdown(cn_upload_queue_t *q);

/**
 * @brief Destroy the queue and free all resources.
 *
 * Sets *q to NULL on return. Caller must ensure the worker thread has exited
 * (i.e. cn_upload_queue_shutdown() was called and the thread was joined) before
 * calling this function.
 *
 * @param[in,out] q  Pointer to queue pointer. Must not be NULL. *q may be NULL.
 */
void cn_upload_queue_destroy(cn_upload_queue_t **q);

#endif /* CN_UPLOAD_QUEUE_H */
