#ifndef CN_PARSER_H
#define CN_PARSER_H

#include "config.h"
#include "../core/constants.h"
#include <stdio.h>

/**
 * @brief Parse a TOML configuration file and populate a cn_config_t structure.
 *
 * Opens path in read-only mode, reads its entire content, and uses tomlc99
 * to parse it into *config. Unknown TOML keys are ignored (forward-compatible
 * parsing). String fields in the output are always NUL-terminated and bounded
 * by their respective CN_*_MAX constants; values that exceed the limit cause
 * CN_ERR_OVERFLOW to be returned without modifying *config further.
 *
 * Callers must invoke cn_validator_check() on the result before using the
 * configuration, as this function performs only syntactic parsing.
 *
 * @security path must be validated against CN_PATH_MAX by the caller. The
 *           file is opened O_RDONLY. auth_token, if present in the file,
 *           is stored in config->upload.auth_token; the caller is responsible
 *           for clearing this field before passing config to untrusted code.
 *
 * @param[out] config  Configuration structure to populate. Must not be NULL.
 *                     The structure is zeroed before parsing begins.
 * @param[in]  path    Absolute path of the TOML file. Must not be NULL.
 *                     Length must be < CN_PATH_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL    if config or path is NULL, or path is too long.
 * @return CN_ERR_IO       if the file cannot be opened or read.
 * @return CN_ERR_OVERFLOW if any string field exceeds its CN_*_MAX limit.
 * @return CN_ERR_INVAL    if the TOML file contains a syntax error.
 */
cn_err_t cn_parser_load(cn_config_t *config, const char *path)
    __attribute__((warn_unused_result));

/**
 * @brief Serialise a cn_config_t to a TOML file, replacing any existing file.
 *
 * Writes every field in config to path as a well-formed TOML document.
 * The file is written atomically: output goes to a temporary file in the same
 * directory as path, then renamed over it. This prevents a partial write from
 * leaving a corrupted config file.
 *
 * Fields whose values match their CN_DEFAULT_* value are still written (the
 * output is always a complete, self-contained file). Sections that are empty
 * or disabled (e.g. [upload] when endpoint_url is absent) are omitted.
 *
 * The output is intentionally round-trip safe with cn_parser_load(): loading
 * the file written by this function must produce an identical cn_config_t.
 *
 * @security path is opened with mode 0600 so that auth_token is not world-
 *           readable. The caller is responsible for ensuring path resides in a
 *           directory that is not writable by untrusted users.
 *
 * @param[in] config  Configuration to serialise. Must not be NULL.
 * @param[in] path    Destination file path. Must not be NULL.
 *                    Length must be < CN_PATH_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL    if config or path is NULL, or path is too long.
 * @return CN_ERR_IO       if the file cannot be created, written, or renamed.
 * @return CN_ERR_OVERFLOW if a temporary path cannot be constructed.
 */
cn_err_t cn_parser_save(const cn_config_t *config, const char *path)
    __attribute__((warn_unused_result));

/**
 * @brief Warn about upload-related keys found outside the [upload] section.
 *
 * When the [upload] section header is accidentally commented out, keys such as
 * endpoint_url and auth_token land at the TOML top level and are silently
 * ignored by cn_parser_load(). This function detects that pattern and writes
 * a human-readable warning to out, listing each stray key by name.
 *
 * No output is produced when [upload] is present (keys are correctly scoped)
 * or when none of the known upload keys appear at the top level.
 *
 * Intended for use by diagnostic commands (e.g. "netcap-ctl config check")
 * and error paths where upload is unexpectedly disabled.
 *
 * @param[in] path  Path to the TOML configuration file. Must not be NULL.
 * @param[in] out   Output stream for warnings (typically stderr). Must not be NULL.
 *
 * @return Number of stray upload keys found (0 = none found, no output written).
 * @return -1 if the file cannot be opened or parsed (no output written).
 */
int cn_parser_warn_stray_upload_keys(const char *path, FILE *out);

#endif /* CN_PARSER_H */
