/*
 * systemd service notifications — sd_notify protocol over a Unix datagram
 * socket written to $NOTIFY_SOCKET.
 *
 * Implemented without a libsystemd dependency: the protocol is a single
 * datagram of newline-separated KEY=VALUE pairs sent to the path in
 * $NOTIFY_SOCKET.  If the variable is unset the service is not managed by
 * systemd and all functions silently return CN_OK.
 *
 * Reference: sd_notify(3), systemd.service(5).
 */
#define _POSIX_C_SOURCE 200809L

#include "platform.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Internal helper — send one datagram to $NOTIFY_SOCKET.
 * Returns CN_OK if the variable is unset (not a systemd unit) or on success.
 * ---------------------------------------------------------------------- */

static cn_err_t sd_notify_send(const char *msg)
{
    const char *notify_socket = getenv("NOTIFY_SOCKET");
    if (notify_socket == NULL || notify_socket[0] == '\0') {
        return CN_OK; /* Not running under systemd. */
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        return CN_ERR_IO;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    /*
     * NOTIFY_SOCKET may be an abstract socket (starts with '@') or a
     * filesystem path.  Abstract sockets use a NUL byte as the first
     * character of sun_path.
     */
    if (notify_socket[0] == '@') {
        addr.sun_path[0] = '\0';
        strncpy(addr.sun_path + 1, notify_socket + 1,
                sizeof(addr.sun_path) - 2u);
    } else {
        strncpy(addr.sun_path, notify_socket, sizeof(addr.sun_path) - 1u);
    }

    size_t msg_len = strlen(msg);
    ssize_t sent = sendto(fd, msg, msg_len, MSG_NOSIGNAL,
                          (struct sockaddr *)&addr, sizeof(addr));
    (void)close(fd);

    return (sent == (ssize_t)msg_len) ? CN_OK : CN_ERR_IO;
}

/* =========================================================================
 * Public API (platform.h)
 * ====================================================================== */

cn_err_t cn_platform_notify_ready(void)
{
    return sd_notify_send("READY=1\n");
}

cn_err_t cn_platform_notify_watchdog(void)
{
    return sd_notify_send("WATCHDOG=1\n");
}

cn_err_t cn_platform_notify_stopping(void)
{
    return sd_notify_send("STOPPING=1\n");
}
