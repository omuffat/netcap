#ifndef CN_PLATFORM_H
#define CN_PLATFORM_H

/*
 * Internal interface between main.c and platform-specific files.
 * Not part of the public API — do not include from outside service/.
 */

#include "../core/constants.h"

/* -------------------------------------------------------------------------
 * Service lifecycle notifications.
 *
 * Called by main.c at well-defined points in the service lifecycle.
 * Each platform (systemd.c / launchd.c / winsvc.c) provides its own
 * implementation.  All functions are safe to call even when the platform
 * integration is inactive (e.g. NOTIFY_SOCKET not set).
 * ---------------------------------------------------------------------- */

/**
 * @brief Notify the platform supervisor that the service is fully started.
 *
 * systemd: sends READY=1 via $NOTIFY_SOCKET.
 * Windows: sets service status to SERVICE_RUNNING.
 * launchd: no-op.
 */
cn_err_t cn_platform_notify_ready(void)
    __attribute__((warn_unused_result));

/**
 * @brief Send a periodic watchdog keepalive to the platform supervisor.
 *
 * Must be called at least once per watchdog interval (typically every
 * CN_IPC_RECV_TIMEOUT_S seconds from the IPC loop).
 *
 * systemd: sends WATCHDOG=1 via $NOTIFY_SOCKET.
 * Windows / launchd: no-op.
 */
cn_err_t cn_platform_notify_watchdog(void)
    __attribute__((warn_unused_result));

/**
 * @brief Notify the platform supervisor that the service is about to stop.
 *
 * systemd: sends STOPPING=1 via $NOTIFY_SOCKET.
 * Windows: sets service status to SERVICE_STOP_PENDING.
 * launchd: no-op.
 */
cn_err_t cn_platform_notify_stopping(void)
    __attribute__((warn_unused_result));

/* -------------------------------------------------------------------------
 * Shared service entry point.
 *
 * Implements the complete service lifecycle: load config, init interfaces,
 * run the IPC event loop, and shut down cleanly.
 *
 * Called by main() on POSIX (after signal setup) and by ServiceMain() on
 * Windows (after the control handler is registered).
 *
 * @param[in] config_path  Path to the TOML config file, or NULL to use
 *                         CN_DEFAULT_CONFIG_PATH.
 *
 * @return 0 on clean stop, 1 on fatal error.
 * ---------------------------------------------------------------------- */
int cn_service_run(const char *config_path);

/* -------------------------------------------------------------------------
 * Stop / reload requests.
 *
 * Called from signal handlers (POSIX) or ServiceCtrlHandler (Windows).
 * Safe to call from any context — implementations only write a volatile flag.
 * ---------------------------------------------------------------------- */

/** Request a graceful service stop. */
void cn_service_request_stop(void);

/**
 * Request a config reload.  The service will stop cleanly; the OS service
 * manager is expected to restart it so it picks up the new configuration.
 */
void cn_service_request_reload(void);

#endif /* CN_PLATFORM_H */
