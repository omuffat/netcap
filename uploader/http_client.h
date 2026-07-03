#ifndef CN_HTTP_CLIENT_H
#define CN_HTTP_CLIENT_H

#include <stdbool.h>
#include "../core/constants.h"
#include "../config/config.h"
#include "auth.h"

/* -------------------------------------------------------------------------
 * HTTP client handle (opaque)
 * ---------------------------------------------------------------------- */

/** Wraps a libcurl easy handle pre-configured for secure single-shot uploads. */
typedef struct cn_http_client cn_http_client_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief Initialize an HTTP client for uploading savefiles to a remote endpoint.
 *
 * Creates and configures a libcurl easy handle with the following fixed
 * security settings (never overridden after init):
 *   - CURLOPT_SSLVERSION     = CURL_SSLVERSION_TLSv1_3 (TLS 1.3 minimum, no fallback).
 *   - CURLOPT_SSL_VERIFYPEER = 1L (certificate chain verified).
 *   - CURLOPT_SSL_VERIFYHOST = 2L (hostname verified against the certificate).
 *
 * @security endpoint_url must use the "https://" scheme. This function returns
 *           CN_ERR_INVAL if the URL does not start with "https://". The TLS
 *           verification options above must never be disabled, including in
 *           debug or test builds. auth is used to build the Authorization
 *           header; it must remain valid for the lifetime of the client.
 *           When tls->client_cert_path and tls->client_key_path are both
 *           non-empty, mutual TLS is enabled; both must point to valid PEM files.
 *
 * @param[out] client        Set to the allocated client on success. Must not be NULL.
 * @param[in]  endpoint_url  HTTPS upload endpoint URL. Must not be NULL.
 *                           Must start with "https://". Length < CN_URL_MAX.
 * @param[in]  auth          Initialized auth context. Must not be NULL.
 *                           Ownership is not transferred; caller frees it.
 * @param[in]  tls           TLS configuration (CA bundle, optional mTLS paths).
 *                           May be NULL to use libcurl / system defaults.
 *                           If non-NULL, string lengths must be < CN_PATH_MAX.
 * @param[in]  compress      When true, the file body is gzip-compressed in
 *                           memory before upload and Content-Encoding: gzip is
 *                           added to the request.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if client, endpoint_url, or auth is NULL; the URL
 *                       scheme is not "https://"; URL or a TLS path is too long.
 * @return CN_ERR_NOMEM  if allocation fails.
 * @return CN_ERR_NET    if curl_global_init() or curl_easy_init() fails.
 */
cn_err_t cn_http_client_init(cn_http_client_t **client,
                              const char *endpoint_url,
                              cn_auth_ctx_t *auth,
                              const cn_tls_config_t *tls,
                              bool compress)
    __attribute__((warn_unused_result));

/**
 * @brief Upload a savefile to the configured HTTPS endpoint with a single POST.
 *
 * Reads file_path entirely into memory, optionally gzip-compresses it, and
 * sends the result as the POST body. The following headers are always sent:
 *   - Content-Type: application/octet-stream
 *   - Authorization: Bearer <token>
 *   - X-Netcap-Iface:     <iface_name>
 *   - X-Netcap-Device:    <device>
 *   - X-Netcap-Filename:  <filename>
 * When the client was initialized with compress=true:
 *   - Content-Encoding: gzip
 * Retry logic is the caller's responsibility.
 *
 * @security file_path, iface_name, device, and filename originate from trusted
 *           sources (local savefile path, interface name, system hostname,
 *           savefile basename). None are derived from captured packet data.
 *           String lengths are validated against their CN_*_MAX limits.
 *
 * @param[in,out] client     Initialized client. Must not be NULL.
 * @param[in]     file_path  Path to the savefile to upload. Must not be NULL.
 *                           Length must be < CN_PATH_MAX.
 * @param[in]     iface_name Capture interface name. Must not be NULL.
 *                           Length must be < CN_IFACE_NAME_MAX.
 * @param[in]     device     Capture host name. Must not be NULL.
 *                           Length must be < CN_HOST_NAME_MAX.
 * @param[in]     filename   Savefile basename (no directory component).
 *                           Must not be NULL. Length must be < CN_PATH_MAX.
 *
 * @return CN_OK on success (HTTP 2xx response received from the server).
 * @return CN_ERR_INVAL   if any parameter is NULL or a string exceeds its limit.
 * @return CN_ERR_IO      if the file cannot be opened or read.
 * @return CN_ERR_NOMEM   if memory allocation fails (not retried).
 * @return CN_ERR_NET     if the transfer fails or the server returns non-2xx.
 * @return CN_ERR_TIMEOUT if the request exceeds the configured timeout.
 */
cn_err_t cn_http_client_post_file(cn_http_client_t *client,
                                   const char *file_path,
                                   const char *iface_name,
                                   const char *device,
                                   const char *filename)
    __attribute__((warn_unused_result));

/**
 * @brief Clean up and free an HTTP client handle.
 *
 * Calls curl_easy_cleanup() and frees internal state. Sets *client to NULL.
 *
 * @param[in,out] client  Pointer to a client handle. Must not be NULL.
 *                        *client may be NULL (no-op).
 */
void cn_http_client_destroy(cn_http_client_t **client);

#endif /* CN_HTTP_CLIENT_H */
