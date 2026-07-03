/*
 * cn_parser_save() uses rename(2) for atomic file replacement (POSIX.1-2008).
 * Expose rename without switching the whole translation unit to GNU dialect.
 */
#define _POSIX_C_SOURCE 200809L

#include "parser.h"
#include "../core/str.h"
#include "../core/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#  include <unistd.h>  /* unlink(), gethostname() */
#else
#  include <io.h>
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h> /* GetComputerNameA() */
#  define unlink _unlink
#endif

#include <toml.h>

/* =========================================================================
 * Internal helpers
 * ====================================================================== */

/*
 * Copy a tomlc99 string datum into dst[dst_size], then free the datum string.
 * If datum.ok == 0 the key was absent: dst is left unchanged (caller has
 * already set the default) and CN_OK is returned.
 * Returns CN_ERR_OVERFLOW when the value is too long for the destination.
 *
 * Preconditions: dst != NULL, dst_size > 0.
 */
static cn_err_t copy_str_field(char *dst, size_t dst_size, toml_datum_t datum)
{
    if (!datum.ok) {
        return CN_OK; /* Key absent — keep the caller-supplied default. */
    }

    cn_err_t rc;

    if (cn_strnlen(datum.u.s, dst_size) >= dst_size) {
        rc = CN_ERR_OVERFLOW;
    } else {
        /* Length was validated above; cn_strlcpy cannot fail here. */
        cn_err_t rc_cpy = cn_strlcpy(dst, datum.u.s, dst_size);
        (void)rc_cpy;
        rc = CN_OK;
    }

    free(datum.u.s); /* Always free the tomlc99-allocated string. */
    return rc;
}

/* -------------------------------------------------------------------------
 * [upload.tls]
 * Preconditions: tls != NULL, upload_tbl != NULL.
 * ---------------------------------------------------------------------- */
static cn_err_t parse_tls(cn_tls_config_t *tls, toml_table_t *upload_tbl)
{
    toml_table_t *tls_tbl = toml_table_in(upload_tbl, "tls");
    if (tls_tbl == NULL) {
        return CN_OK; /* Optional sub-section — defaults already set. */
    }

    cn_err_t rc;

    rc = copy_str_field(tls->ca_cert_path, CN_PATH_MAX,
                        toml_string_in(tls_tbl, "ca_cert_path"));
    if (rc != CN_OK) {
        return rc;
    }

    rc = copy_str_field(tls->client_cert_path, CN_PATH_MAX,
                        toml_string_in(tls_tbl, "client_cert_path"));
    if (rc != CN_OK) {
        return rc;
    }

    return copy_str_field(tls->client_key_path, CN_PATH_MAX,
                          toml_string_in(tls_tbl, "client_key_path"));
}

/* -------------------------------------------------------------------------
 * [upload]
 * Preconditions: up != NULL, root != NULL.
 * ---------------------------------------------------------------------- */
static cn_err_t parse_upload(cn_upload_config_t *up, toml_table_t *root)
{
    toml_table_t *tbl = toml_table_in(root, "upload");
    if (tbl == NULL) {
        return CN_OK; /* Optional section — defaults already set. */
    }

    cn_err_t rc;
    toml_datum_t d;

    rc = copy_str_field(up->endpoint_url, CN_URL_MAX,
                        toml_string_in(tbl, "endpoint_url"));
    if (rc != CN_OK) {
        return rc;
    }

    rc = copy_str_field(up->auth_token, CN_AUTH_TOKEN_MAX,
                        toml_string_in(tbl, "auth_token"));
    if (rc != CN_OK) {
        return rc;
    }

    d = toml_int_in(tbl, "chunk_size");
    if (d.ok) {
        up->chunk_size = (uint32_t)d.u.i;
    }

    d = toml_int_in(tbl, "retry_max");
    if (d.ok) {
        up->retry_max = (uint32_t)d.u.i;
    }

    d = toml_int_in(tbl, "retry_delay_ms");
    if (d.ok) {
        up->retry_delay_ms = (uint32_t)d.u.i;
    }

    d = toml_int_in(tbl, "worker_count");
    if (d.ok) {
        up->worker_count = (uint32_t)d.u.i;
    }

    d = toml_bool_in(tbl, "capture_upload_traffic");
    if (d.ok) {
        up->capture_upload_traffic = (d.u.b != 0);
    }

    d = toml_bool_in(tbl, "compress");
    if (d.ok) {
        up->compress = (d.u.b != 0);
    }

    d = toml_bool_in(tbl, "auto");
    if (d.ok) {
        up->auto_upload = (d.u.b != 0);
    }

    return parse_tls(&up->tls, tbl);
}

/* -------------------------------------------------------------------------
 * One [[interfaces]] array element.
 * Preconditions: iface != NULL, tbl != NULL.
 * ---------------------------------------------------------------------- */
static cn_err_t parse_iface(cn_iface_config_t *iface, toml_table_t *tbl)
{
    cn_err_t rc;
    toml_datum_t d;

    rc = copy_str_field(iface->name, CN_IFACE_NAME_MAX,
                        toml_string_in(tbl, "name"));
    if (rc != CN_OK) {
        return rc;
    }

    rc = copy_str_field(iface->bpf_filter, CN_BPF_FILTER_MAX,
                        toml_string_in(tbl, "bpf_filter"));
    if (rc != CN_OK) {
        return rc;
    }

    d = toml_int_in(tbl, "ring_size");
    if (d.ok) {
        iface->ring_size = (uint32_t)d.u.i;
    }

    d = toml_int_in(tbl, "snaplen");
    if (d.ok) {
        iface->snaplen = (int)d.u.i;
    }

    d = toml_bool_in(tbl, "enabled");
    if (d.ok) {
        iface->enabled = (d.u.b != 0);
    }
    /* If "enabled" is absent the default (true) set during cn_config_init()
     * is preserved — no action needed. */

    return CN_OK;
}

/* =========================================================================
 * Internal initialiser — fills config with every CN_DEFAULT_* value.
 * Called before TOML parsing so that absent keys automatically carry
 * the correct default without any extra logic in the parse helpers.
 * ====================================================================== */
static void cn_config_init(cn_config_t *config)
{
    memset(config, 0, sizeof(*config));

    /* Top-level paths — compile-time constants, cannot overflow CN_PATH_MAX. */
    cn_err_t rc_ring = cn_strlcpy(config->ring_dir, CN_DEFAULT_RING_DIR, CN_PATH_MAX);
    (void)rc_ring;
    cn_err_t rc_save = cn_strlcpy(config->savefile_dir, CN_DEFAULT_SAVEFILE_DIR,
                                   CN_PATH_MAX);
    (void)rc_save;

    /* Savefile rotation */
    config->savefile_rotation_secs = CN_DEFAULT_SAVEFILE_ROTATION_SECS;
    config->savefile_max_count     = CN_DEFAULT_SAVEFILE_MAX_COUNT;

    /* Service */
    config->log_level = CN_DEFAULT_LOG_LEVEL;
    /* device is zeroed by memset; cn_parser_load() fills it from the TOML
     * field or from gethostname() when the key is absent. */

    /* Upload defaults (applied even when upload is disabled, so that if the
     * user later adds endpoint_url + auth_token, the remaining fields already
     * hold sensible values). */
    config->upload.chunk_size              = CN_DEFAULT_CHUNK_SIZE;
    config->upload.retry_max               = CN_DEFAULT_RETRY_MAX;
    config->upload.retry_delay_ms          = CN_DEFAULT_RETRY_DELAY_MS;
    config->upload.worker_count            = CN_DEFAULT_WORKER_COUNT;
    config->upload.capture_upload_traffic  = CN_DEFAULT_CAPTURE_UPLOAD_TRAFFIC;
    config->upload.compress                = CN_DEFAULT_COMPRESS;
    config->upload.auto_upload             = CN_DEFAULT_AUTO_UPLOAD;
    /* TLS string fields are already zeroed (empty = system defaults). */

    /* Per-interface defaults are applied in parse_iface() for entries that
     * exist in the TOML, and pre-populated here for completeness. */
    for (uint32_t i = 0; i < CN_IFACE_COUNT_MAX; i++) {
        config->interfaces[i].ring_size = CN_DEFAULT_RING_SIZE;
        config->interfaces[i].snaplen   = CN_DEFAULT_SNAPLEN;
        config->interfaces[i].enabled   = CN_DEFAULT_IFACE_ENABLED;
        /* name and bpf_filter are empty strings from memset — correct
         * defaults (name = required, bpf_filter = no filter). */
    }
}

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_parser_load(cn_config_t *config, const char *path)
{
    if (config == NULL || path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }

    /* Fill every field with its default before touching the TOML file.
     * Any key present in the file overrides the default. */
    cn_config_init(config);

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        CN_LOG_ERROR("cannot open config file \"%s\": %s", path,
                     CN_LOG_OS_ERR);
        return CN_ERR_IO;
    }

    char          errbuf[256];
    toml_table_t *root = toml_parse_file(fp, errbuf, (int)sizeof(errbuf));
    fclose(fp);

    if (root == NULL) {
        CN_LOG_ERROR("TOML parse error in \"%s\": %s", path, errbuf);
        return CN_ERR_INVAL;
    }

    cn_err_t     rc = CN_OK;
    toml_datum_t d;

    /* ------------------------------------------------------------------
     * Top-level string fields
     * ---------------------------------------------------------------- */

    rc = copy_str_field(config->ring_dir, CN_PATH_MAX,
                        toml_string_in(root, "ring_dir"));
    if (rc != CN_OK) {
        goto done;
    }

    rc = copy_str_field(config->savefile_dir, CN_PATH_MAX,
                        toml_string_in(root, "savefile_dir"));
    if (rc != CN_OK) {
        goto done;
    }

    rc = copy_str_field(config->device, CN_HOST_NAME_MAX,
                        toml_string_in(root, "device"));
    if (rc != CN_OK) {
        goto done;
    }

    /* ------------------------------------------------------------------
     * Top-level integer / boolean fields
     * ---------------------------------------------------------------- */

    d = toml_int_in(root, "log_level");
    if (d.ok) {
        config->log_level = (uint32_t)d.u.i;
    }

    d = toml_int_in(root, "savefile_rotation_secs");
    if (d.ok) {
        config->savefile_rotation_secs = (uint32_t)d.u.i;
    }

    d = toml_int_in(root, "savefile_max_count");
    if (d.ok) {
        config->savefile_max_count = (uint32_t)d.u.i;
    }

    /* ------------------------------------------------------------------
     * [[interfaces]] array
     * ---------------------------------------------------------------- */

    {
        toml_array_t *ifaces = toml_array_in(root, "interfaces");
        if (ifaces != NULL) {
            int n = toml_array_nelem(ifaces);
            if (n < 0 || n > (int)CN_IFACE_COUNT_MAX) {
                rc = CN_ERR_OVERFLOW;
                goto done;
            }
            config->iface_count = (uint32_t)n;

            for (int i = 0; i < n; i++) {
                toml_table_t *tbl = toml_table_at(ifaces, i);
                if (tbl == NULL) {
                    rc = CN_ERR_INVAL;
                    goto done;
                }
                rc = parse_iface(&config->interfaces[i], tbl);
                if (rc != CN_OK) {
                    goto done;
                }
            }
        }
        /* If [[interfaces]] is absent, iface_count stays 0 — valid state. */
    }

    /* ------------------------------------------------------------------
     * [upload]
     * ---------------------------------------------------------------- */

    rc = parse_upload(&config->upload, root);
    if (rc != CN_OK) {
        goto done;
    }

    /* ------------------------------------------------------------------
     * Resolve device name — use gethostname() when the TOML key is absent.
     * Short hostname only: never perform a DNS lookup for the FQDN.
     * ---------------------------------------------------------------- */
    if (config->device[0] == '\0') {
#ifndef _WIN32
        if (gethostname(config->device, CN_HOST_NAME_MAX) != 0) {
            cn_err_t rc_host = cn_strlcpy(config->device, "unknown",
                                          CN_HOST_NAME_MAX);
            (void)rc_host;
        }
#else
        DWORD sz = (DWORD)CN_HOST_NAME_MAX;
        if (!GetComputerNameA(config->device, &sz)) {
            cn_err_t rc_host = cn_strlcpy(config->device, "unknown",
                                          CN_HOST_NAME_MAX);
            (void)rc_host;
        }
#endif
        /* Guarantee NUL termination regardless of platform behaviour. */
        config->device[CN_HOST_NAME_MAX - 1u] = '\0';
    }

done:
    toml_free(root);
    return rc;
}

/* =========================================================================
 * cn_parser_save — write a cn_config_t back to a TOML file.
 *
 * Strategy: write to a temporary file in the same directory, then rename(2)
 * over the destination.  On failure the temporary file is unlinked so that
 * a partial write is never left on disk.
 * ====================================================================== */

/*
 * Build a temporary path by appending ".tmp" to dst_path.
 * Returns CN_ERR_OVERFLOW when dst_path + 4 bytes would exceed CN_PATH_MAX.
 * Preconditions: tmp_buf != NULL (size CN_PATH_MAX), dst_path != NULL.
 */
static cn_err_t make_tmp_path(char *tmp_buf, const char *dst_path)
{
    size_t len = cn_strnlen(dst_path, CN_PATH_MAX);
    if (len >= CN_PATH_MAX) {
        return CN_ERR_OVERFLOW;
    }
    /* Need room for ".tmp" (4 chars) + NUL terminator. */
    if (len + 4u >= CN_PATH_MAX) {
        return CN_ERR_OVERFLOW;
    }
    /* Both copies are safe: lengths were validated above. */
    cn_err_t rc_t1 = cn_strlcpy(tmp_buf, dst_path, CN_PATH_MAX);
    (void)rc_t1;
    cn_err_t rc_t2 = cn_strlcpy(tmp_buf + len, ".tmp", CN_PATH_MAX - len);
    (void)rc_t2;
    return CN_OK;
}

/*
 * Write one [[interfaces]] table entry to fp.
 * Preconditions: fp != NULL, iface != NULL.
 * Returns CN_ERR_IO if any fprintf call fails.
 */
static cn_err_t write_iface(FILE *fp, const cn_iface_config_t *iface)
{
    if (fprintf(fp, "[[interfaces]]\n") < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "name    = \"%s\"\n", iface->name) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "enabled = %s\n", iface->enabled ? "true" : "false") < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "ring_size = %u\n", iface->ring_size) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "snaplen   = %d\n", iface->snaplen) < 0) {
        return CN_ERR_IO;
    }
    /* Omit bpf_filter when empty (default: no filter). */
    if (iface->bpf_filter[0] != '\0') {
        if (fprintf(fp, "bpf_filter = \"%s\"\n", iface->bpf_filter) < 0) {
            return CN_ERR_IO;
        }
    }
    if (fprintf(fp, "\n") < 0) {
        return CN_ERR_IO;
    }
    return CN_OK;
}

/*
 * Write the [upload.tls] sub-section when at least one TLS path is set.
 * Preconditions: fp != NULL, tls != NULL.
 */
static cn_err_t write_tls(FILE *fp, const cn_tls_config_t *tls)
{
    int has_ca   = (tls->ca_cert_path[0]    != '\0');
    int has_cert = (tls->client_cert_path[0] != '\0');
    int has_key  = (tls->client_key_path[0]  != '\0');

    if (!has_ca && !has_cert && !has_key) {
        return CN_OK; /* Nothing to write. */
    }

    if (fprintf(fp, "\n[upload.tls]\n") < 0) {
        return CN_ERR_IO;
    }
    if (has_ca) {
        if (fprintf(fp, "ca_cert_path    = \"%s\"\n", tls->ca_cert_path) < 0) {
            return CN_ERR_IO;
        }
    }
    if (has_cert) {
        if (fprintf(fp, "client_cert_path = \"%s\"\n", tls->client_cert_path) < 0) {
            return CN_ERR_IO;
        }
    }
    if (has_key) {
        if (fprintf(fp, "client_key_path  = \"%s\"\n", tls->client_key_path) < 0) {
            return CN_ERR_IO;
        }
    }
    return CN_OK;
}

/*
 * Write the [upload] section.  Omitted entirely when upload is disabled.
 * Preconditions: fp != NULL, up != NULL.
 */
static cn_err_t write_upload(FILE *fp, const cn_upload_config_t *up)
{
    if (!cn_upload_is_enabled(up)) {
        return CN_OK; /* Upload disabled — nothing to write. */
    }

    if (fprintf(fp, "[upload]\n") < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "endpoint_url = \"%s\"\n", up->endpoint_url) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "auth_token   = \"%s\"\n", up->auth_token) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "chunk_size    = %u\n", up->chunk_size) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "retry_max     = %u\n", up->retry_max) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "retry_delay_ms = %u\n", up->retry_delay_ms) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "worker_count  = %u\n", up->worker_count) < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "capture_upload_traffic = %s\n",
                up->capture_upload_traffic ? "true" : "false") < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "compress               = %s\n",
                up->compress ? "true" : "false") < 0) {
        return CN_ERR_IO;
    }
    if (fprintf(fp, "auto                   = %s\n",
                up->auto_upload ? "true" : "false") < 0) {
        return CN_ERR_IO;
    }

    return write_tls(fp, &up->tls);
}

cn_err_t cn_parser_save(const cn_config_t *config, const char *path)
{
    if (config == NULL || path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }

    char tmp_path[CN_PATH_MAX];
    cn_err_t rc = make_tmp_path(tmp_path, path);
    if (rc != CN_OK) {
        return rc;
    }

#ifndef _WIN32
    FILE *fp = fopen(tmp_path, "w");
#else
    /* On Windows fopen does not support the mode 0600 restriction; the
     * installer is responsible for restricting the directory ACL. */
    FILE *fp = fopen(tmp_path, "w");
#endif
    if (fp == NULL) {
        return CN_ERR_IO;
    }

    rc = CN_OK;

    /* ------------------------------------------------------------------
     * Service-level fields
     * ---------------------------------------------------------------- */
    if (fprintf(fp, "# netcap configuration\n\n") < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }
    if (fprintf(fp, "log_level = %u\n", config->log_level) < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }
    if (config->device[0] != '\0') {
        if (fprintf(fp, "device    = \"%s\"\n", config->device) < 0) {
            rc = CN_ERR_IO;
            goto cleanup;
        }
    }
    if (fprintf(fp, "\n") < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }

    /* ------------------------------------------------------------------
     * Paths
     * ---------------------------------------------------------------- */
    if (fprintf(fp, "ring_dir     = \"%s\"\n", config->ring_dir) < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }
    if (fprintf(fp, "savefile_dir = \"%s\"\n", config->savefile_dir) < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }
    if (fprintf(fp, "\n") < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }

    /* ------------------------------------------------------------------
     * Savefile rotation
     * ---------------------------------------------------------------- */
    if (fprintf(fp, "savefile_rotation_secs = %u\n",
                config->savefile_rotation_secs) < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }
    if (fprintf(fp, "savefile_max_count     = %u\n\n",
                config->savefile_max_count) < 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }

    /* ------------------------------------------------------------------
     * [[interfaces]]
     * ---------------------------------------------------------------- */
    for (uint32_t i = 0; i < config->iface_count; i++) {
        rc = write_iface(fp, &config->interfaces[i]);
        if (rc != CN_OK) {
            goto cleanup;
        }
    }

    /* ------------------------------------------------------------------
     * [upload]
     * ---------------------------------------------------------------- */
    rc = write_upload(fp, &config->upload);
    if (rc != CN_OK) {
        goto cleanup;
    }

    if (fflush(fp) != 0) {
        rc = CN_ERR_IO;
        goto cleanup;
    }

    fclose(fp);
    fp = NULL;

    /* Atomic replacement: rename temp file over destination. */
    if (rename(tmp_path, path) != 0) {
        (void)unlink(tmp_path);
        return CN_ERR_IO;
    }

    return CN_OK;

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    (void)unlink(tmp_path);
    return rc;
}

/* =========================================================================
 * cn_parser_warn_stray_upload_keys
 * ====================================================================== */

int cn_parser_warn_stray_upload_keys(const char *path, FILE *out)
{
    if (path == NULL || out == NULL) {
        return -1;
    }

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    char          errbuf[256];
    toml_table_t *root = toml_parse_file(fp, errbuf, (int)sizeof(errbuf));
    fclose(fp);

    if (root == NULL) {
        return -1; /* Already reported as invalid by cn_parser_load(). */
    }

    /*
     * Only relevant when [upload] is absent — if the section is present the
     * keys are correctly scoped and there is nothing to warn about.
     */
    int count = 0;

    /*
     * Check for upload keys at the TOML top level (missing [upload] header).
     */
    if (toml_table_in(root, "upload") == NULL) {
        static const char * const top_keys[] = {
            "endpoint_url",
            "auth_token",
            "chunk_size",
            "retry_max",
            "retry_delay_ms",
            "worker_count",
            "compress",
            "capture_upload_traffic",
            NULL
        };

        for (int i = 0; top_keys[i] != NULL; i++) {
            toml_datum_t ds = toml_string_in(root, top_keys[i]);
            if (ds.ok) {
                free(ds.u.s);
            } else {
                toml_datum_t di = toml_int_in(root, top_keys[i]);
                toml_datum_t db = toml_bool_in(root, top_keys[i]);
                if (!di.ok && !db.ok) {
                    continue;
                }
            }

            if (count == 0) {
                (void)fprintf(out,
                    "Warning: the following upload key(s) appear at the top "
                    "level of '%s' but there is no [upload] section —\n"
                    "  they are silently ignored. Did you forget to uncomment "
                    "\"[upload]\"?\n",
                    path);
            }
            (void)fprintf(out, "  - %s\n", top_keys[i]);
            count++;
        }
    }

    /*
     * Check for TLS keys inside [upload] but outside [upload.tls]
     * (missing [upload.tls] header while [upload] is present).
     */
    {
        toml_table_t *upload_tbl = toml_table_in(root, "upload");
        if (upload_tbl != NULL && toml_table_in(upload_tbl, "tls") == NULL) {
            static const char * const tls_keys[] = {
                "ca_cert_path",
                "client_cert_path",
                "client_key_path",
                NULL
            };

            int tls_count = 0;
            for (int i = 0; tls_keys[i] != NULL; i++) {
                toml_datum_t ds = toml_string_in(upload_tbl, tls_keys[i]);
                if (!ds.ok) {
                    continue;
                }
                free(ds.u.s);

                if (tls_count == 0) {
                    (void)fprintf(out,
                        "Warning: the following TLS key(s) appear in [upload] "
                        "in '%s' but there is no [upload.tls] section —\n"
                        "  they are silently ignored. Did you forget to "
                        "uncomment \"[upload.tls]\"?\n",
                        path);
                }
                (void)fprintf(out, "  - %s\n", tls_keys[i]);
                tls_count++;
                count++;
            }
        }
    }

    toml_free(root);
    return count;
}
