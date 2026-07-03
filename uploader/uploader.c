/*
 * cn_upload_file() — synchronous single-shot upload orchestrator.
 *
 * Ties together auth and HTTP client:
 *   1. Initialise auth context and HTTP client from cfg.
 *   2. POST the entire savefile with retry on transient failure.
 *   3. Destroy all resources before returning.
 *
 * Retry policy:
 *   - CN_ERR_NET and CN_ERR_TIMEOUT are considered transient; retried up to
 *     cfg->retry_max times.
 *   - CN_ERR_NOMEM and CN_ERR_IO are not transient; propagated immediately.
 *   - Backoff doubles on each attempt (base = cfg->retry_delay_ms), capped
 *     at 30 000 ms.
 *
 * nanosleep(2) requires _POSIX_C_SOURCE 200809L on Linux/macOS.
 * On Windows, Sleep() is used instead.
 */
#ifndef _WIN32
#  define _POSIX_C_SOURCE 200809L
#endif

#include "uploader.h"
#include "auth.h"
#include "http_client.h"
#include "../core/str.h"

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <time.h>
#endif

#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Sleep for ms milliseconds. Precondition: ms > 0. */
static void sleep_ms(uint32_t ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000L);
    (void)nanosleep(&ts, NULL);
#endif
}

/*
 * Compute the backoff delay for a given retry attempt (0-indexed).
 * Doubles the base delay each time, capped at 30 000 ms.
 * Precondition: base_ms > 0.
 */
static uint32_t backoff_ms(uint32_t base_ms, uint32_t attempt)
{
    uint32_t delay = base_ms;
    for (uint32_t i = 0u; i < attempt; i++) {
        if (delay >= 15000u) {
            return 30000u;
        }
        delay *= 2u;
    }
    return (delay > 30000u) ? 30000u : delay;
}

/*
 * Extract the basename from a file path (last component after '/' or '\').
 * Returns a pointer into path — never allocates.
 * Precondition: path != NULL.
 */
static const char *basename_of(const char *path)
{
    const char *p = strrchr(path, '/');
#ifdef _WIN32
    const char *q = strrchr(path, '\\');
    if (q != NULL && (p == NULL || q > p)) {
        p = q;
    }
#endif
    return (p != NULL) ? p + 1 : path;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_upload_file(const char *file_path, const char *iface_name,
                         const char *device, const cn_upload_config_t *cfg)
{
    if (file_path == NULL || iface_name == NULL || device == NULL || cfg == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(file_path,  CN_PATH_MAX)       >= CN_PATH_MAX)      { return CN_ERR_INVAL; }
    if (cn_strnlen(iface_name, CN_IFACE_NAME_MAX)  >= CN_IFACE_NAME_MAX) { return CN_ERR_INVAL; }
    if (cn_strnlen(device,     CN_HOST_NAME_MAX)   >= CN_HOST_NAME_MAX) { return CN_ERR_INVAL; }
    if (!cn_upload_is_enabled(cfg)) {
        return CN_ERR_INVAL;
    }

    const char *filename = basename_of(file_path);

    cn_auth_ctx_t    *auth   = NULL;
    cn_http_client_t *client = NULL;
    cn_err_t          rc     = CN_OK;

    rc = cn_auth_init(&auth, cfg->auth_token);
    if (rc != CN_OK) {
        goto done;
    }

    rc = cn_http_client_init(&client, cfg->endpoint_url, auth,
                              &cfg->tls, cfg->compress);
    if (rc != CN_OK) {
        goto done;
    }

    for (uint32_t attempt = 0u; attempt <= cfg->retry_max; attempt++) {
        if (attempt > 0u) {
            sleep_ms(backoff_ms(cfg->retry_delay_ms, attempt - 1u));
        }

        rc = cn_http_client_post_file(client, file_path, iface_name,
                                       device, filename);
        if (rc == CN_OK) {
            break;
        }
        /* IO and memory errors are not transient — stop immediately. */
        if (rc == CN_ERR_IO || rc == CN_ERR_NOMEM) {
            break;
        }
        /* CN_ERR_NET, CN_ERR_TIMEOUT: transient — retry after backoff. */
    }

done:
    cn_http_client_destroy(&client);
    cn_auth_destroy(&auth);
    return rc;
}
