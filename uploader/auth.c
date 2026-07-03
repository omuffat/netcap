#include "auth.h"
#include "../core/str.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * Internal structure
 * ---------------------------------------------------------------------- */

struct cn_auth_ctx {
    char token[CN_AUTH_TOKEN_MAX]; /* Bearer token, NUL-terminated. */
};

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_auth_init(cn_auth_ctx_t **ctx, const char *token)
{
    if (ctx == NULL || token == NULL) {
        return CN_ERR_INVAL;
    }

    size_t len = cn_strnlen(token, CN_AUTH_TOKEN_MAX);
    if (len == 0 || len >= CN_AUTH_TOKEN_MAX) {
        return CN_ERR_INVAL;
    }

    cn_auth_ctx_t *c = malloc(sizeof(*c));
    if (c == NULL) {
        return CN_ERR_NOMEM;
    }

    /* Length was validated above; cn_strlcpy cannot fail here. */
    cn_err_t rc_cpy = cn_strlcpy(c->token, token, CN_AUTH_TOKEN_MAX);
    (void)rc_cpy;
    *ctx = c;
    return CN_OK;
}

cn_err_t cn_auth_get_header(const cn_auth_ctx_t *ctx, char *buf, size_t buf_size)
{
    if (ctx == NULL || buf == NULL) {
        return CN_ERR_INVAL;
    }
    if (buf_size == 0) {
        return CN_ERR_INVAL;
    }

    int rc = snprintf(buf, buf_size, "Bearer %s", ctx->token);
    if (rc < 0 || (size_t)rc >= buf_size) {
        return CN_ERR_OVERFLOW;
    }

    return CN_OK;
}

void cn_auth_destroy(cn_auth_ctx_t **ctx)
{
    if (ctx == NULL || *ctx == NULL) {
        return;
    }

    /* Overwrite the token before freeing to prevent the secret from
     * persisting in freed memory. */
    memset((*ctx)->token, 0, CN_AUTH_TOKEN_MAX);
    free(*ctx);
    *ctx = NULL;
}
