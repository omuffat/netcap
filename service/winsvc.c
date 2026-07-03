/*
 * Windows Service integration.
 *
 * Provides:
 *   - ServiceMain()          — entry point called by StartServiceCtrlDispatcher
 *   - ServiceCtrlHandler()   — handles SERVICE_CONTROL_STOP
 *   - cn_platform_notify_*() — update SERVICE_STATUS via SetServiceStatus
 *
 * The service is registered as SERVICE_WIN32_OWN_PROCESS with
 * SERVICE_DELAYED_AUTO_START set by the installer (not by this code).
 *
 * v1 limitation: pause/resume controls are not implemented.
 */
#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "platform.h"
#include "../config/config.h"  /* CN_DEFAULT_CONFIG_PATH */

/* -------------------------------------------------------------------------
 * Globals — written by ServiceCtrlHandler, read by the service main loop.
 * ---------------------------------------------------------------------- */

static SERVICE_STATUS_HANDLE g_svc_handle = NULL;

static SERVICE_STATUS g_svc_status = {
    .dwServiceType             = SERVICE_WIN32_OWN_PROCESS,
    .dwCurrentState            = SERVICE_START_PENDING,
    .dwControlsAccepted        = 0,
    .dwWin32ExitCode           = NO_ERROR,
    .dwServiceSpecificExitCode = 0,
    .dwCheckPoint              = 0,
    .dwWaitHint                = 5000, /* 5 s — used during start/stop */
};

/* -------------------------------------------------------------------------
 * Internal helper — update the service status and report it.
 * ---------------------------------------------------------------------- */

static void set_service_status(DWORD state, DWORD controls_accepted)
{
    g_svc_status.dwCurrentState    = state;
    g_svc_status.dwControlsAccepted = controls_accepted;
    if (g_svc_handle != NULL) {
        SetServiceStatus(g_svc_handle, &g_svc_status);
    }
}

/* -------------------------------------------------------------------------
 * Service control handler — invoked by the SCM in a separate thread.
 * ---------------------------------------------------------------------- */

static VOID WINAPI ServiceCtrlHandler(DWORD ctrl)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        set_service_status(SERVICE_STOP_PENDING, 0);
        cn_service_request_stop();
        break;
    default:
        break;
    }
}

/* -------------------------------------------------------------------------
 * ServiceMain — entry point called by StartServiceCtrlDispatcher.
 * ---------------------------------------------------------------------- */

VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    (void)argc;
    (void)argv;

    g_svc_handle = RegisterServiceCtrlHandlerA("netcap", ServiceCtrlHandler);
    if (g_svc_handle == NULL) {
        return;
    }

    set_service_status(SERVICE_START_PENDING, 0);

    /*
     * Use the default config path when running as a Windows Service.
     * Interactive/debug mode uses command-line args (handled in main()).
     */
    int rc = cn_service_run(CN_DEFAULT_CONFIG_PATH);
    g_svc_status.dwWin32ExitCode = (rc == 0) ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR;
    g_svc_status.dwServiceSpecificExitCode = (DWORD)rc;
    set_service_status(SERVICE_STOPPED, 0);
}

/* =========================================================================
 * Public API (platform.h)
 * ====================================================================== */

cn_err_t cn_platform_notify_ready(void)
{
    set_service_status(SERVICE_RUNNING,
                       SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    return CN_OK;
}

cn_err_t cn_platform_notify_watchdog(void)
{
    /* Windows does not have an equivalent watchdog mechanism. */
    return CN_OK;
}

cn_err_t cn_platform_notify_stopping(void)
{
    set_service_status(SERVICE_STOP_PENDING, 0);
    return CN_OK;
}

#endif /* _WIN32 */
