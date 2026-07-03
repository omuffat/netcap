#ifndef CN_AUTH_H
#define CN_AUTH_H

#include <stddef.h>
#include "../core/constants.h"

/* -------------------------------------------------------------------------
 * Authentication context (opaque)
 * ---------------------------------------------------------------------- */

/** Holds credentials and produces HTTP Authorization header values. */
typedef struct cn_auth_ctx cn_auth_ctx_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief Initialize an authentication context with a bearer token.
 *
 * Stores a private copy of token. The token is used to produce the
 * "Authorization: Bearer <token>" HTTP header value via cn_auth_get_header().
 *
 * @security token is sensitive. Zero the source buffer after this call.
 *           The token is never written to log output or error messages.
 *           token length is validated against CN_AUTH_TOKEN_MAX.
 *
 * @param[out] ctx    Set to the allocated context on success. Must not be NULL.
 * @param[in]  token  Bearer token string. Must not be NULL.
 *                    Length must be > 0 and < CN_AUTH_TOKEN_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if ctx or token is NULL, or token length is invalid.
 * @return CN_ERR_NOMEM  if allocation fails.
 */
cn_err_t cn_auth_init(cn_auth_ctx_t **ctx, const char *token)
    __attribute__((warn_unused_result));

/**
 * @brief Write the full Authorization header value into buf.
 *
 * Writes "Bearer <token>" (NUL-terminated) into buf. The result is suitable
 * for direct use with curl_slist_append() or CURLOPT_HTTPHEADER.
 *
 * @param[in]  ctx       Initialized auth context. Must not be NULL.
 * @param[out] buf       Destination buffer. Must not be NULL.
 * @param[in]  buf_size  Capacity of buf in bytes. Must be > 7 (length of
 *                       "Bearer " prefix) and large enough for the token.
 *                       A size of CN_AUTH_TOKEN_MAX + 8 is always sufficient.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL    if ctx or buf is NULL.
 * @return CN_ERR_OVERFLOW if the formatted value does not fit in buf.
 */
cn_err_t cn_auth_get_header(const cn_auth_ctx_t *ctx, char *buf, size_t buf_size)
    __attribute__((warn_unused_result));

/**
 * @brief Securely erase and free an authentication context.
 *
 * Overwrites the stored token with zeros before freeing the allocation,
 * preventing the secret from persisting in freed memory. Sets *ctx to NULL.
 *
 * @param[in,out] ctx  Pointer to an auth context pointer. Must not be NULL.
 *                     *ctx may be NULL (no-op).
 */
void cn_auth_destroy(cn_auth_ctx_t **ctx);

#endif /* CN_AUTH_H */
