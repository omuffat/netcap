/* GCC 10+ does not suppress warn_unused_result via (void) cast. */
#define DISCARD(x)  do { cn_err_t _r_ = (x); (void)_r_; } while (0)

#include "upload_queue.h"
#include "../core/log.h"
#include "../core/str.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef _WIN32
#  include <pthread.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* =========================================================================
 * Internal types
 * ====================================================================== */

typedef struct {
    char file_path[CN_PATH_MAX];
    char iface_name[CN_IFACE_NAME_MAX];
} cn_upload_entry_t;

struct cn_upload_queue {
    cn_upload_entry_t entries[CN_UPLOAD_QUEUE_CAPACITY];
    uint32_t          head;     /* Index of next entry to pop. */
    uint32_t          tail;     /* Index of next slot to push. */
    uint32_t          count;    /* Number of entries currently in the queue. */
    bool              shutdown; /* Set by cn_upload_queue_shutdown(). */

#ifndef _WIN32
    pthread_mutex_t   mutex;
    pthread_cond_t    cond;
#else
    CRITICAL_SECTION  lock;
    CONDITION_VARIABLE cond;
#endif
};

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_upload_queue_create(cn_upload_queue_t **q)
{
    if (q == NULL) {
        return CN_ERR_INVAL;
    }

    cn_upload_queue_t *uq = (cn_upload_queue_t *)malloc(sizeof(*uq));
    if (uq == NULL) {
        return CN_ERR_NOMEM;
    }
    memset(uq, 0, sizeof(*uq));

#ifndef _WIN32
    if (pthread_mutex_init(&uq->mutex, NULL) != 0) {
        free(uq);
        return CN_ERR_IO;
    }
    if (pthread_cond_init(&uq->cond, NULL) != 0) {
        pthread_mutex_destroy(&uq->mutex);
        free(uq);
        return CN_ERR_IO;
    }
#else
    InitializeCriticalSection(&uq->lock);
    InitializeConditionVariable(&uq->cond);
#endif

    *q = uq;
    return CN_OK;
}

cn_err_t cn_upload_queue_push(cn_upload_queue_t *q,
                               const char        *file_path,
                               const char        *iface_name)
{
    if (q == NULL || file_path == NULL || iface_name == NULL) {
        return CN_ERR_INVAL;
    }

#ifndef _WIN32
    pthread_mutex_lock(&q->mutex);
#else
    EnterCriticalSection(&q->lock);
#endif

    cn_err_t rc;

    if (q->count >= CN_UPLOAD_QUEUE_CAPACITY) {
        CN_LOG_WARN("upload queue full (%u entries) — dropping \"%s\"",
                    CN_UPLOAD_QUEUE_CAPACITY, file_path);
        rc = CN_ERR_OVERFLOW;
    } else {
        cn_upload_entry_t *e = &q->entries[q->tail];
        DISCARD(cn_strlcpy(e->file_path,  file_path,  CN_PATH_MAX));
        DISCARD(cn_strlcpy(e->iface_name, iface_name, CN_IFACE_NAME_MAX));
        q->tail = (q->tail + 1u) % CN_UPLOAD_QUEUE_CAPACITY;
        q->count++;
        rc = CN_OK;

#ifndef _WIN32
        pthread_cond_signal(&q->cond);
#else
        WakeConditionVariable(&q->cond);
#endif
    }

#ifndef _WIN32
    pthread_mutex_unlock(&q->mutex);
#else
    LeaveCriticalSection(&q->lock);
#endif

    return rc;
}

cn_err_t cn_upload_queue_pop(cn_upload_queue_t *q,
                              char              *file_path_out,
                              char              *iface_name_out)
{
    if (q == NULL || file_path_out == NULL || iface_name_out == NULL) {
        return CN_ERR_INVAL;
    }

#ifndef _WIN32
    pthread_mutex_lock(&q->mutex);

    /* Wait until there is an entry to pop or the queue is shut down and drained. */
    while (q->count == 0 && !q->shutdown) {
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    if (q->count == 0) {
        /* Shut down and empty — signal the worker to exit. */
        pthread_mutex_unlock(&q->mutex);
        return CN_ERR_INVAL;
    }

    cn_upload_entry_t *e = &q->entries[q->head];
    DISCARD(cn_strlcpy(file_path_out,  e->file_path,  CN_PATH_MAX));
    DISCARD(cn_strlcpy(iface_name_out, e->iface_name, CN_IFACE_NAME_MAX));
    q->head = (q->head + 1u) % CN_UPLOAD_QUEUE_CAPACITY;
    q->count--;

    pthread_mutex_unlock(&q->mutex);

#else /* _WIN32 */

    EnterCriticalSection(&q->lock);

    while (q->count == 0 && !q->shutdown) {
        SleepConditionVariableCS(&q->cond, &q->lock, INFINITE);
    }

    if (q->count == 0) {
        LeaveCriticalSection(&q->lock);
        return CN_ERR_INVAL;
    }

    cn_upload_entry_t *e = &q->entries[q->head];
    DISCARD(cn_strlcpy(file_path_out,  e->file_path,  CN_PATH_MAX));
    DISCARD(cn_strlcpy(iface_name_out, e->iface_name, CN_IFACE_NAME_MAX));
    q->head = (q->head + 1u) % CN_UPLOAD_QUEUE_CAPACITY;
    q->count--;

    LeaveCriticalSection(&q->lock);

#endif /* _WIN32 */

    return CN_OK;
}

void cn_upload_queue_shutdown(cn_upload_queue_t *q)
{
    if (q == NULL) {
        return;
    }

#ifndef _WIN32
    pthread_mutex_lock(&q->mutex);
    q->shutdown = true;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
#else
    EnterCriticalSection(&q->lock);
    q->shutdown = true;
    WakeAllConditionVariable(&q->cond);
    LeaveCriticalSection(&q->lock);
#endif
}

void cn_upload_queue_destroy(cn_upload_queue_t **q)
{
    if (q == NULL || *q == NULL) {
        return;
    }

#ifndef _WIN32
    pthread_mutex_destroy(&(*q)->mutex);
    pthread_cond_destroy(&(*q)->cond);
#else
    DeleteCriticalSection(&(*q)->lock);
    /* CONDITION_VARIABLE has no Windows destroy function. */
#endif

    free(*q);
    *q = NULL;
}
