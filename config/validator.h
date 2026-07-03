#ifndef CN_VALIDATOR_H
#define CN_VALIDATOR_H

#include "config.h"
#include "../core/constants.h"

/**
 * @brief Validate the semantic constraints of a parsed cn_config_t.
 *
 * Performs range and consistency checks that go beyond TOML syntax.
 *
 * Always checked:
 *   - iface_count <= CN_IFACE_COUNT_MAX (0 is valid: service runs, no capture).
 *   - For each interface entry (when iface_count > 0):
 *       - name is non-empty and its length < CN_IFACE_NAME_MAX.
 *       - ring_size in [CN_RING_SIZE_MIN, CN_RING_SIZE_MAX] and a
 *         multiple of 4096 (minimum page size).
 *       - snaplen in (0, CN_PKT_SIZE_MAX].
 *   - savefile_dir is non-empty and < CN_PATH_MAX.
 *   - savefile_rotation_secs in [CN_SAVEFILE_ROTATION_SECS_MIN,
 *                                 CN_SAVEFILE_ROTATION_SECS_MAX].
 *   - savefile_max_count in [CN_SAVEFILE_MAX_COUNT_MIN,
 *                             CN_SAVEFILE_MAX_COUNT_MAX].
 *   - ring_dir is non-empty and < CN_PATH_MAX.
 *
 * Checked only when upload is enabled (cn_upload_is_enabled() == true):
 *   - endpoint_url starts with "https://" and length < CN_URL_MAX.
 *   - chunk_size in (0, CN_CHUNK_SIZE_MAX].
 *   - worker_count in (0, CN_UPLOAD_WORKERS_MAX].
 *   - If client_cert_path is set, client_key_path must also be set,
 *     and vice versa (mTLS requires both or neither).
 *
 * @param[in] config  Populated configuration to validate. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if config is NULL or any constraint is violated.
 */
cn_err_t cn_validator_check(const cn_config_t *config)
    __attribute__((warn_unused_result));

#endif /* CN_VALIDATOR_H */
