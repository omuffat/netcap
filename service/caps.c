#include "caps.h"
#include "../core/log.h"

#ifdef __linux__

#include <sys/capability.h>
#include <sys/prctl.h>

cn_err_t cn_caps_drop(void)
{
    /*
     * Replace the process capability set with an empty set, dropping all
     * capabilities including CAP_NET_RAW.  Must be called after all pcap
     * handles are open and before any untrusted data (captured packets)
     * is processed.
     */
    cap_t empty = cap_init();
    if (empty == NULL) {
        CN_LOG_ERROR("cap_init: %s", CN_LOG_OS_ERR);
        return CN_ERR_PERM;
    }

    if (cap_set_proc(empty) != 0) {
        CN_LOG_ERROR("cap_set_proc: %s", CN_LOG_OS_ERR);
        cap_free(empty);
        return CN_ERR_PERM;
    }
    cap_free(empty);

    /*
     * Prevent future privilege re-acquisition via setuid/setcap on any
     * exec'd child.  PR_SET_NO_NEW_PRIVS requires Linux 3.5+.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        CN_LOG_ERROR("prctl(PR_SET_NO_NEW_PRIVS): %s", CN_LOG_OS_ERR);
        return CN_ERR_PERM;
    }

    return CN_OK;
}

#else /* macOS, Windows, other POSIX */

/*
 * On macOS, privilege separation is handled by the sandbox/entitlements
 * model outside the process boundary.  On Windows, the service account
 * ACL is configured by the installer.  In both cases nothing is required
 * inside the process.
 */
cn_err_t cn_caps_drop(void)
{
    return CN_OK;
}

#endif /* __linux__ */
