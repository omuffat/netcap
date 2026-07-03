/*
 * HTTP upload client — libcurl wrapper for single-shot POST uploads.
 *
 * Security invariants (enforced at init, never overridden):
 *   - TLS 1.3 minimum, no fallback.
 *   - CURLOPT_SSL_VERIFYPEER = 1L (certificate chain verified).
 *   - CURLOPT_SSL_VERIFYHOST = 2L (hostname verified against certificate).
 *
 * Compression:
 *   When compress=true, the entire file is read into memory and deflated into
 *   a heap buffer using a single gzip stream (windowBits = 15 + 16) before
 *   the POST. Content-Encoding: gzip is added to the request. The compressed
 *   buffer is freed after each call to cn_http_client_post_file().
 */
#include "http_client.h"
#include "../core/str.h"
#include "../core/log.h"

#include <curl/curl.h>
#include <zlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Per-transfer timeout in seconds. */
#define HTTP_TIMEOUT_SECS  120L

/*
 * "Authorization: Bearer " prefix is 23 chars; add CN_AUTH_TOKEN_MAX for the
 * token value itself, plus 1 for NUL.
 */
#define AUTH_HDR_MAX   (23u + CN_AUTH_TOKEN_MAX)

/* "X-Netcap-Iface: " + CN_IFACE_NAME_MAX + NUL */
#define IFACE_HDR_MAX  (16u + CN_IFACE_NAME_MAX)

/* "X-Netcap-Device: " + CN_HOST_NAME_MAX + NUL */
#define DEVICE_HDR_MAX (18u + CN_HOST_NAME_MAX)

/* "X-Netcap-Filename: " + CN_PATH_MAX + NUL */
#define FNAME_HDR_MAX  (20u + CN_PATH_MAX)

/* -------------------------------------------------------------------------
 * Internal structure
 * ---------------------------------------------------------------------- */

struct cn_http_client {
    CURL    *handle;
    char     endpoint_url[CN_URL_MAX];
    char     auth_header[AUTH_HDR_MAX]; /* "Authorization: Bearer <token>" */
    char     curl_errbuf[CURL_ERROR_SIZE]; /* Populated by libcurl on failure. */
    bool     compress;
    uint8_t  _pad[7];
};

/* -------------------------------------------------------------------------
 * libcurl callbacks
 * ---------------------------------------------------------------------- */

/*
 * Upload read callback — feeds an in-memory buffer to libcurl.
 * Precondition: userdata is a non-NULL pointer to upload_buf.
 */
struct upload_buf {
    const uint8_t *data;
    size_t         offset;
    size_t         len;
};

static size_t read_cb(char *buf, size_t size, size_t nmemb, void *userdata)
{
    struct upload_buf *u = (struct upload_buf *)userdata;
    size_t avail = u->len - u->offset;
    size_t want  = size * nmemb;
    size_t n     = (avail < want) ? avail : want;
    if (n > 0) {
        memcpy(buf, u->data + u->offset, n);
        u->offset += n;
    }
    return n;
}

/* Discard the response body — prevents libcurl from printing to stdout. */
static size_t write_cb(char *buf, size_t size, size_t nmemb, void *userdata)
{
    (void)buf;
    (void)userdata;
    return size * nmemb;
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * Read an entire file into a newly allocated buffer.
 * Caller must free *buf_out on CN_OK.
 * Preconditions: path != NULL, buf_out != NULL, len_out != NULL.
 */
static cn_err_t read_file(const char *path, uint8_t **buf_out, size_t *len_out)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return CN_ERR_IO;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return CN_ERR_IO;
    }

    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return CN_ERR_IO;
    }
    rewind(fp);

    uint8_t *buf = malloc((size_t)sz > 0u ? (size_t)sz : 1u);
    if (buf == NULL) {
        fclose(fp);
        return CN_ERR_NOMEM;
    }

    if ((size_t)sz > 0u && fread(buf, 1u, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return CN_ERR_IO;
    }

    fclose(fp);
    *buf_out = buf;
    *len_out = (size_t)sz;
    return CN_OK;
}

/*
 * gzip-compress src into a newly allocated buffer.
 * Caller must free *dst_out on CN_OK.
 * Preconditions: src != NULL or src_len == 0, dst_out != NULL, dst_len_out != NULL.
 */
static cn_err_t gzip_compress(const uint8_t *src, size_t src_len,
                               uint8_t **dst_out, size_t *dst_len_out)
{
    /*
     * compressBound gives the upper bound for deflate output. Add 18 bytes
     * for the gzip header and trailer produced by windowBits = 15 + 16.
     */
    uLong bound = compressBound((uLong)src_len) + 18uL;

    uint8_t *dst = malloc((size_t)bound);
    if (dst == NULL) {
        return CN_ERR_NOMEM;
    }

    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    /*
     * windowBits = 15 + 16 requests gzip encapsulation (header + trailer).
     * memLevel = 8 is the zlib default.
     */
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(dst);
        return CN_ERR_IO;
    }

    zs.next_in   = (Bytef *)(uintptr_t)src; /* const removed — zlib reads only */
    zs.avail_in  = (uInt)src_len;
    zs.next_out  = (Bytef *)dst;
    zs.avail_out = (uInt)bound;

    int rc = deflate(&zs, Z_FINISH);
    deflateEnd(&zs);

    if (rc != Z_STREAM_END) {
        free(dst);
        return CN_ERR_IO;
    }

    *dst_out     = dst;
    *dst_len_out = (size_t)zs.total_out;
    return CN_OK;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_http_client_init(cn_http_client_t **client,
                              const char *endpoint_url,
                              cn_auth_ctx_t *auth,
                              const cn_tls_config_t *tls,
                              bool compress)
{
    if (client == NULL || endpoint_url == NULL || auth == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(endpoint_url, CN_URL_MAX) >= CN_URL_MAX) {
        return CN_ERR_INVAL;
    }
    if (strncmp(endpoint_url, "https://", 8u) != 0) {
        return CN_ERR_INVAL;
    }
    if (tls != NULL) {
        if (tls->ca_cert_path[0] != '\0' &&
            cn_strnlen(tls->ca_cert_path, CN_PATH_MAX) >= CN_PATH_MAX) {
            return CN_ERR_INVAL;
        }
        if (tls->client_cert_path[0] != '\0' &&
            cn_strnlen(tls->client_cert_path, CN_PATH_MAX) >= CN_PATH_MAX) {
            return CN_ERR_INVAL;
        }
        if (tls->client_key_path[0] != '\0' &&
            cn_strnlen(tls->client_key_path, CN_PATH_MAX) >= CN_PATH_MAX) {
            return CN_ERR_INVAL;
        }
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return CN_ERR_NET;
    }

    CURL *h = curl_easy_init();
    if (h == NULL) {
        return CN_ERR_NET;
    }

    cn_http_client_t *c = malloc(sizeof(*c));
    if (c == NULL) {
        curl_easy_cleanup(h);
        return CN_ERR_NOMEM;
    }
    memset(c, 0, sizeof(*c));

    c->handle   = h;
    c->compress = compress;
    /* Length was validated above; cn_strlcpy cannot fail here. */
    cn_err_t rc_url = cn_strlcpy(c->endpoint_url, endpoint_url, CN_URL_MAX);
    (void)rc_url;

    /* Build "Authorization: Bearer <token>" header string. */
    char bearer[CN_AUTH_TOKEN_MAX + 8u]; /* "Bearer <token>" */
    cn_err_t rc = cn_auth_get_header(auth, bearer, sizeof(bearer));
    if (rc != CN_OK) {
        goto fail;
    }
    {
        int n = snprintf(c->auth_header, AUTH_HDR_MAX, "Authorization: %s", bearer);
        if (n < 0 || (size_t)n >= AUTH_HDR_MAX) {
            rc = CN_ERR_OVERFLOW;
            goto fail;
        }
    }

    /* ------------------------------------------------------------------
     * Fixed TLS security settings — never overridden.
     * ---------------------------------------------------------------- */
    if (curl_easy_setopt(h, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3)
            != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
    if (curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
    if (curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }

    /* ------------------------------------------------------------------
     * Optional TLS overrides (CA bundle, mTLS).
     * ---------------------------------------------------------------- */
    if (tls != NULL) {
        if (tls->ca_cert_path[0] != '\0') {
            if (curl_easy_setopt(h, CURLOPT_CAINFO, tls->ca_cert_path)
                    != CURLE_OK) {
                rc = CN_ERR_NET;
                goto fail;
            }
        }
        if (tls->client_cert_path[0] != '\0') {
            if (curl_easy_setopt(h, CURLOPT_SSLCERT, tls->client_cert_path)
                    != CURLE_OK) {
                rc = CN_ERR_NET;
                goto fail;
            }
        }
        if (tls->client_key_path[0] != '\0') {
            if (curl_easy_setopt(h, CURLOPT_SSLKEY, tls->client_key_path)
                    != CURLE_OK) {
                rc = CN_ERR_NET;
                goto fail;
            }
        }
    }

    /* ------------------------------------------------------------------
     * Common transfer settings.
     * ---------------------------------------------------------------- */
    if (curl_easy_setopt(h, CURLOPT_URL, c->endpoint_url) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
    if (curl_easy_setopt(h, CURLOPT_POST, 1L) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
    if (curl_easy_setopt(h, CURLOPT_READFUNCTION, read_cb) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
    if (curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
    if (curl_easy_setopt(h, CURLOPT_TIMEOUT, HTTP_TIMEOUT_SECS) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
    if (curl_easy_setopt(h, CURLOPT_ERRORBUFFER, c->curl_errbuf) != CURLE_OK) {
        rc = CN_ERR_NET;
        goto fail;
    }
#ifdef CN_DEV_BUILD
    /* Verbose TLS and protocol trace to stderr — dev builds only. */
    (void)curl_easy_setopt(h, CURLOPT_VERBOSE, 1L);
#endif

    *client = c;
    return CN_OK;

fail:
    curl_easy_cleanup(h);
    free(c);
    return rc;
}

cn_err_t cn_http_client_post_file(cn_http_client_t *client,
                                   const char *file_path,
                                   const char *iface_name,
                                   const char *device,
                                   const char *filename)
{
    if (client == NULL || file_path == NULL ||
        iface_name == NULL || device == NULL || filename == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(file_path,  CN_PATH_MAX)      >= CN_PATH_MAX)     { return CN_ERR_INVAL; }
    if (cn_strnlen(iface_name, CN_IFACE_NAME_MAX) >= CN_IFACE_NAME_MAX) { return CN_ERR_INVAL; }
    if (cn_strnlen(device,     CN_HOST_NAME_MAX)  >= CN_HOST_NAME_MAX) { return CN_ERR_INVAL; }
    if (cn_strnlen(filename,   CN_PATH_MAX)       >= CN_PATH_MAX)     { return CN_ERR_INVAL; }

    uint8_t  *file_buf = NULL;
    size_t    file_len = 0;
    uint8_t  *gz_buf   = NULL;
    cn_err_t  rc       = CN_OK;

    /* Read the savefile into memory. */
    rc = read_file(file_path, &file_buf, &file_len);
    if (rc != CN_OK) {
        return rc;
    }

    const uint8_t *body     = file_buf;
    size_t         body_len = file_len;

    /* Optionally compress before upload. */
    if (client->compress) {
        size_t gz_len = 0;
        rc = gzip_compress(file_buf, file_len, &gz_buf, &gz_len);
        if (rc != CN_OK) {
            goto cleanup;
        }
        body     = gz_buf;
        body_len = gz_len;
    }

    /* ------------------------------------------------------------------
     * Build per-request header list.
     * ---------------------------------------------------------------- */
    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    if (headers == NULL) { rc = CN_ERR_NOMEM; goto cleanup; }

    headers = curl_slist_append(headers, client->auth_header);
    if (headers == NULL) { rc = CN_ERR_NOMEM; goto cleanup; }

    {
        char hdr[IFACE_HDR_MAX];
        int n = snprintf(hdr, IFACE_HDR_MAX, "X-Netcap-Iface: %s", iface_name);
        if (n < 0 || (size_t)n >= IFACE_HDR_MAX) { rc = CN_ERR_OVERFLOW; goto cleanup; }
        headers = curl_slist_append(headers, hdr);
        if (headers == NULL) { rc = CN_ERR_NOMEM; goto cleanup; }
    }

    {
        char hdr[DEVICE_HDR_MAX];
        int n = snprintf(hdr, DEVICE_HDR_MAX, "X-Netcap-Device: %s", device);
        if (n < 0 || (size_t)n >= DEVICE_HDR_MAX) { rc = CN_ERR_OVERFLOW; goto cleanup; }
        headers = curl_slist_append(headers, hdr);
        if (headers == NULL) { rc = CN_ERR_NOMEM; goto cleanup; }
    }

    {
        char hdr[FNAME_HDR_MAX];
        int n = snprintf(hdr, FNAME_HDR_MAX, "X-Netcap-Filename: %s", filename);
        if (n < 0 || (size_t)n >= FNAME_HDR_MAX) { rc = CN_ERR_OVERFLOW; goto cleanup; }
        headers = curl_slist_append(headers, hdr);
        if (headers == NULL) { rc = CN_ERR_NOMEM; goto cleanup; }
    }

    if (client->compress) {
        headers = curl_slist_append(headers, "Content-Encoding: gzip");
        if (headers == NULL) { rc = CN_ERR_NOMEM; goto cleanup; }
    }

    /* ------------------------------------------------------------------
     * Configure the easy handle and perform the transfer.
     * ---------------------------------------------------------------- */
    {
        struct upload_buf ub = { body, 0u, body_len };

        if (curl_easy_setopt(client->handle, CURLOPT_HTTPHEADER, headers)
                != CURLE_OK) {
            rc = CN_ERR_NET;
            goto cleanup;
        }
        if (curl_easy_setopt(client->handle, CURLOPT_READDATA, &ub)
                != CURLE_OK) {
            rc = CN_ERR_NET;
            goto cleanup;
        }
        if (curl_easy_setopt(client->handle, CURLOPT_POSTFIELDSIZE_LARGE,
                             (curl_off_t)body_len) != CURLE_OK) {
            rc = CN_ERR_NET;
            goto cleanup;
        }

        CURLcode res = curl_easy_perform(client->handle);

        if (res == CURLE_OPERATION_TIMEDOUT) {
            CN_LOG_WARN("upload timed out after %lds: %s",
                        HTTP_TIMEOUT_SECS,
                        client->curl_errbuf[0] ? client->curl_errbuf
                                               : curl_easy_strerror(res));
            rc = CN_ERR_TIMEOUT;
            goto cleanup;
        }
        if (res != CURLE_OK) {
            CN_LOG_WARN("upload transfer failed: %s",
                        client->curl_errbuf[0] ? client->curl_errbuf
                                               : curl_easy_strerror(res));
            rc = CN_ERR_NET;
            goto cleanup;
        }

        long http_code = 0;
        (void)curl_easy_getinfo(client->handle, CURLINFO_RESPONSE_CODE,
                                &http_code);
        if (http_code < 200 || http_code >= 300) {
            CN_LOG_WARN("upload rejected by server: HTTP %ld", http_code);
            rc = CN_ERR_NET;
            goto cleanup;
        }
    }

cleanup:
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }
    free(gz_buf);
    free(file_buf);
    return rc;
}

void cn_http_client_destroy(cn_http_client_t **client)
{
    if (client == NULL || *client == NULL) {
        return;
    }

    curl_easy_cleanup((*client)->handle);
    free(*client);
    *client = NULL;
}
