#ifndef CN_CAPS_H
#define CN_CAPS_H

#include "../core/constants.h"

/**
 * @brief Drop CAP_NET_RAW and all other non-essential capabilities.
 *
 * Must be called after all pcap handles have been successfully opened and
 * before the capture threads are started. After this call the process retains
 * no elevated network capabilities, limiting the blast radius of any
 * subsequent memory-safety vulnerability.
 *
 * On Linux this uses libcap (cap_set_proc()). On macOS and Windows this
 * function is a no-op that returns CN_OK, as the equivalent privilege model
 * differs per platform (pledge/sandbox on macOS; service account ACLs on
 * Windows are configured outside the process).
 *
 * @security This function must be called exactly once, after pcap handles are
 *           open and before any untrusted data (captured packets) is processed.
 *           Failure to call it is a security defect.
 *
 * @return CN_OK on success.
 * @return CN_ERR_PERM if the capability drop fails (Linux only).
 */
cn_err_t cn_caps_drop(void)
    __attribute__((warn_unused_result));

#endif /* CN_CAPS_H */
