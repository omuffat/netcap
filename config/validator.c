#include "validator.h"

#include <string.h>

cn_err_t cn_validator_check(const cn_config_t *config)
{
    if (config == NULL) {
        return CN_ERR_INVAL;
    }

    /* ------------------------------------------------------------------
     * Interface array
     * ---------------------------------------------------------------- */

    if (config->iface_count > CN_IFACE_COUNT_MAX) {
        return CN_ERR_INVAL;
    }

    for (uint32_t i = 0; i < config->iface_count; i++) {
        const cn_iface_config_t *iface = &config->interfaces[i];

        if (iface->name[0] == '\0') {
            return CN_ERR_INVAL; /* Interface name is required. */
        }

        if (iface->ring_size < CN_RING_SIZE_MIN
                || iface->ring_size > CN_RING_SIZE_MAX
                || iface->ring_size % 4096u != 0u) {
            return CN_ERR_INVAL;
        }

        if (iface->snaplen <= 0
                || (uint32_t)iface->snaplen > CN_PKT_SIZE_MAX) {
            return CN_ERR_INVAL;
        }
    }

    /* ------------------------------------------------------------------
     * Savefile settings (always required)
     * ---------------------------------------------------------------- */

    if (config->savefile_dir[0] == '\0') {
        return CN_ERR_INVAL;
    }

    if (config->savefile_rotation_secs < CN_SAVEFILE_ROTATION_SECS_MIN
            || config->savefile_rotation_secs > CN_SAVEFILE_ROTATION_SECS_MAX) {
        return CN_ERR_INVAL;
    }

    if (config->savefile_max_count < CN_SAVEFILE_MAX_COUNT_MIN
            || config->savefile_max_count > CN_SAVEFILE_MAX_COUNT_MAX) {
        return CN_ERR_INVAL;
    }

    /* ------------------------------------------------------------------
     * Service paths and identity (always required)
     * ---------------------------------------------------------------- */

    if (config->ring_dir[0] == '\0') {
        return CN_ERR_INVAL;
    }

    /* device is always set by cn_parser_load() (from TOML or gethostname()). */
    if (config->device[0] == '\0') {
        return CN_ERR_INVAL;
    }

    /* ------------------------------------------------------------------
     * Upload settings (only when upload is enabled)
     * ---------------------------------------------------------------- */

    if (cn_upload_is_enabled(&config->upload)) {
        const cn_upload_config_t *up = &config->upload;

        if (strncmp(up->endpoint_url, "https://", 8) != 0) {
            return CN_ERR_INVAL; /* Upload endpoint must use HTTPS. */
        }

        if (up->chunk_size == 0 || up->chunk_size > CN_CHUNK_SIZE_MAX) {
            return CN_ERR_INVAL;
        }

        if (up->worker_count == 0
                || up->worker_count > CN_UPLOAD_WORKERS_MAX) {
            return CN_ERR_INVAL;
        }

        /* mTLS: client certificate and key must be set together. */
        int has_cert = (up->tls.client_cert_path[0] != '\0');
        int has_key  = (up->tls.client_key_path[0]  != '\0');
        if (has_cert != has_key) {
            return CN_ERR_INVAL;
        }
    }

    return CN_OK;
}
