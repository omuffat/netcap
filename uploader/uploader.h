#ifndef CN_UPLOADER_H
#define CN_UPLOADER_H

#include "../core/constants.h"
#include "../config/config.h"

/* =========================================================================
 * Public API
 * ====================================================================== */

/**
 * @brief Upload a savefile to the configured HTTPS endpoint.
 *
 * Reads file_path into memory and POSTs it to cfg->endpoint_url with bearer
 * token authentication and the following metadata headers:
 *   - X-Netcap-Iface:    iface_name
 *   - X-Netcap-Device:   device
 *   - X-Netcap-Filename: basename of file_path
 *
 * Transient failures (CN_ERR_NET, CN_ERR_TIMEOUT) are retried up to
 * cfg->retry_max times using exponential backoff starting at
 * cfg->retry_delay_ms milliseconds (doubles each attempt, capped at 30 s).
 *
 * This function is synchronous and blocks until the upload completes, fails
 * permanently, or exhausts all retries. The caller is responsible for
 * invoking it from a dedicated upload worker thread.
 *
 * When cfg->compress is true, the file is gzip-compressed in memory before
 * being sent and Content-Encoding: gzip is set on the request. The savefile
 * on disk is never modified.
 *
 * All internal resources (auth context, HTTP client) are created and destroyed
 * within this call; the caller owns only file_path, iface_name, device, and cfg.
 *
 * @security cfg->endpoint_url must start with "https://"; this is enforced
 *           by the HTTP client layer. cfg->auth_token is transmitted in the
 *           Authorization header over TLS 1.3 minimum only. file_path must
 *           point to a local savefile; it is never sent over the network.
 *
 * @param[in] file_path   Path to the savefile to upload. Must not be NULL.
 *                        Length must be < CN_PATH_MAX.
 * @param[in] iface_name  Capture interface name for X-Netcap-Iface.
 *                        Must not be NULL. Length must be < CN_IFACE_NAME_MAX.
 * @param[in] device      Capture host name for X-Netcap-Device.
 *                        Must not be NULL. Length must be < CN_HOST_NAME_MAX.
 * @param[in] cfg         Upload configuration. Must not be NULL.
 *                        cn_upload_is_enabled(cfg) must return true.
 *
 * @return CN_OK          if the file was uploaded successfully (HTTP 2xx).
 * @return CN_ERR_INVAL   if any pointer is NULL; file_path or iface_name
 *                        exceed their CN_*_MAX limits; or upload is not enabled.
 * @return CN_ERR_IO      if the savefile cannot be opened or read.
 * @return CN_ERR_NOMEM   if memory allocation fails (not retried).
 * @return CN_ERR_NET     if the upload fails after all retries.
 * @return CN_ERR_TIMEOUT if the upload times out after all retries.
 */
cn_err_t cn_upload_file(const char *file_path, const char *iface_name,
                         const char *device, const cn_upload_config_t *cfg)
    __attribute__((warn_unused_result));

#endif /* CN_UPLOADER_H */
