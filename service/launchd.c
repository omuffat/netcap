/*
 * launchd service integration — macOS.
 *
 * launchd monitors the service process directly and restarts it according
 * to the plist KeepAlive key.  No in-process notification protocol is
 * required: the daemon simply starts, runs, and exits.  All three
 * notification functions are therefore no-ops.
 *
 * Service lifecycle (configured in the launchd plist, not here):
 *   - RunAtLoad      = true
 *   - KeepAlive      = true   (restart on any exit)
 *   - WaitForDebugger = false
 *   - NetworkState   = true   (wait for network before launch)
 */
#include "platform.h"

cn_err_t cn_platform_notify_ready(void)
{
    return CN_OK;
}

cn_err_t cn_platform_notify_watchdog(void)
{
    return CN_OK;
}

cn_err_t cn_platform_notify_stopping(void)
{
    return CN_OK;
}
