#ifndef CN_FILTER_H
#define CN_FILTER_H

#include <stddef.h>
#include "constants.h"

/* Forward declaration: avoids pulling the full pcap headers into every
 * translation unit that only needs to pass a handle pointer. */
struct pcap;

/* -------------------------------------------------------------------------
 * BPF filter handle (opaque)
 * ---------------------------------------------------------------------- */

/** Compiled BPF filter ready to be applied to a pcap handle. */
typedef struct cn_filter cn_filter_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief Compile a BPF filter expression against a pcap handle.
 *
 * Wraps pcap_compile() with optimization enabled. The pcap handle is used
 * only for link-type resolution during compilation; an active capture is not
 * required. The resulting filter must be applied via cn_filter_apply() before
 * the capture loop starts.
 *
 * @security expr is treated as user-supplied input. Validate its length
 *           against CN_BPF_FILTER_MAX before this call. BPF syntax errors
 *           are reported as CN_ERR_INVAL.
 *
 * @param[out] filter  Set to the allocated filter on success. Must not be NULL.
 * @param[in]  handle  Open pcap handle used for link-type resolution.
 *                     Must not be NULL.
 * @param[in]  expr    BPF filter expression string. Must not be NULL.
 *                     Length must be > 0 and < CN_BPF_FILTER_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if any pointer is NULL; expr length is 0 or >=
 *                       CN_BPF_FILTER_MAX; or the expression fails to compile.
 * @return CN_ERR_NOMEM  if allocation fails.
 */
cn_err_t cn_filter_compile(cn_filter_t **filter, struct pcap *handle,
                           const char *expr)
    __attribute__((warn_unused_result));

/**
 * @brief Apply a compiled BPF filter to a live pcap capture handle.
 *
 * Wraps pcap_setfilter(). After a successful call, only packets matching the
 * filter expression are delivered by the capture loop. Must be called before
 * pcap_loop() or pcap_next_ex().
 *
 * @param[in]     filter  Compiled filter. Must not be NULL.
 * @param[in,out] handle  Open pcap handle to configure. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if filter or handle is NULL.
 * @return CN_ERR_IO    if pcap_setfilter() fails.
 */
cn_err_t cn_filter_apply(const cn_filter_t *filter, struct pcap *handle)
    __attribute__((warn_unused_result));

/**
 * @brief Free all resources associated with a compiled filter.
 *
 * Calls pcap_freecode() on the internal bpf_program and frees the filter
 * structure. Sets *filter to NULL on return.
 *
 * @param[in,out] filter  Pointer to a filter pointer. Must not be NULL.
 *                        *filter may be NULL (no-op).
 */
void cn_filter_destroy(cn_filter_t **filter);

#endif /* CN_FILTER_H */
