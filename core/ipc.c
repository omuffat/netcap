#include "ipc.h"
#include "log.h"
#include "str.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#  include <unistd.h>
#  include <errno.h>
#  include <grp.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/un.h>
#  include <sys/select.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* =========================================================================
 * Wire-format helpers — explicit little-endian serialisation.
 * ====================================================================== */

/* Write a uint16_t in little-endian byte order into buf[0..1]. */
static void put_u16_le(uint8_t *buf, uint16_t v)
{
    buf[0] = (uint8_t)( v        & 0xFFu);
    buf[1] = (uint8_t)((v >>  8) & 0xFFu);
}

/* Write a uint32_t in little-endian byte order into buf[0..3]. */
static void put_u32_le(uint8_t *buf, uint32_t v)
{
    buf[0] = (uint8_t)( v        & 0xFFu);
    buf[1] = (uint8_t)((v >>  8) & 0xFFu);
    buf[2] = (uint8_t)((v >> 16) & 0xFFu);
    buf[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* Read a uint16_t from little-endian bytes. */
static uint16_t get_u16_le(const uint8_t *buf)
{
    return (uint16_t)((uint16_t)buf[0] | ((uint16_t)buf[1] << 8));
}

/* Read a uint32_t from little-endian bytes. */
static uint32_t get_u32_le(const uint8_t *buf)
{
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] <<  8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

/* Serialised header size: type(2) + reserved(2) + payload_len(4) = 8 bytes. */
#define IPC_HDR_WIRE_SIZE  8u

/* Maximum number of concurrent GUI/CLI clients. */
#define CN_IPC_MAX_CLIENTS 8

/* Server recv timeout in seconds. */
#define CN_IPC_RECV_TIMEOUT_S  5

/* =========================================================================
 * POSIX implementation (Unix domain sockets)
 * ====================================================================== */

#ifndef _WIN32

/* -------------------------------------------------------------------------
 * Opaque handle definitions
 * ---------------------------------------------------------------------- */

struct cn_ipc_server {
    int  listen_fd;
    int  client_fds[CN_IPC_MAX_CLIENTS]; /* -1 = slot unused */
    char socket_path[CN_PATH_MAX];
};

struct cn_ipc_client {
    int fd;
};

/* -------------------------------------------------------------------------
 * POSIX internal helpers
 * ---------------------------------------------------------------------- */

/*
 * recv_all: read exactly len bytes from fd into buf.
 * Returns CN_ERR_IO on any read error or connection close.
 */
static cn_err_t recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p         = (uint8_t *)buf;
    size_t   remaining = len;

    while (remaining > 0) {
        ssize_t n = recv(fd, p, remaining, 0);
        if (n <= 0) {
            return CN_ERR_IO;
        }
        p         += (size_t)n;
        remaining -= (size_t)n;
    }
    return CN_OK;
}

/*
 * send_all: write exactly len bytes from buf to fd.
 * Uses MSG_NOSIGNAL where available to suppress SIGPIPE.
 */
static cn_err_t send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p         = (const uint8_t *)buf;
    size_t         remaining = len;

    while (remaining > 0) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(fd, p, remaining, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, p, remaining, 0);
#endif
        if (n <= 0) {
            return CN_ERR_IO;
        }
        p         += (size_t)n;
        remaining -= (size_t)n;
    }
    return CN_OK;
}

/*
 * send_frame: serialise a message header + payload and write it to fd.
 * Preconditions: fd >= 0, payload may be NULL only if payload_len == 0.
 */
static cn_err_t send_frame(int fd, cn_ipc_msg_type_t type,
                           const void *payload, uint32_t payload_len)
{
    uint8_t hdr[IPC_HDR_WIRE_SIZE];
    put_u16_le(hdr + 0, (uint16_t)type);
    put_u16_le(hdr + 2, 0u);             /* reserved = 0 */
    put_u32_le(hdr + 4, payload_len);

    cn_err_t rc = send_all(fd, hdr, IPC_HDR_WIRE_SIZE);
    if (rc != CN_OK) {
        return rc;
    }
    if (payload_len > 0 && payload != NULL) {
        rc = send_all(fd, payload, (size_t)payload_len);
    }
    return rc;
}

/*
 * recv_frame: read one complete message from fd.
 * Blocks until data is available; no timeout at this layer (select() is
 * used by the caller to implement the timeout).
 * Preconditions: buf != NULL, buf_size >= CN_IPC_MSG_MAX.
 */
static cn_err_t recv_frame(int fd, cn_ipc_msg_type_t *out_type,
                           void *buf, size_t buf_size, uint32_t *out_len)
{
    uint8_t  raw[IPC_HDR_WIRE_SIZE];
    cn_err_t rc = recv_all(fd, raw, IPC_HDR_WIRE_SIZE);
    if (rc != CN_OK) {
        return rc;
    }

    uint32_t payload_len = get_u32_le(raw + 4);
    if (payload_len > CN_IPC_MSG_MAX) {
        return CN_ERR_IO; /* Oversized payload — treat as protocol error. */
    }
    if (payload_len > buf_size) {
        return CN_ERR_OVERFLOW;
    }

    *out_type = (cn_ipc_msg_type_t)get_u16_le(raw + 0);
    *out_len  = payload_len;

    if (payload_len > 0) {
        rc = recv_all(fd, buf, (size_t)payload_len);
    }
    return rc;
}

/*
 * server_add_client: add fd to the server's client list.
 * Returns false if the list is full (caller should close fd).
 */
static bool server_add_client(cn_ipc_server_t *s, int fd)
{
    for (int i = 0; i < CN_IPC_MAX_CLIENTS; i++) {
        if (s->client_fds[i] < 0) {
            s->client_fds[i] = fd;
            return true;
        }
    }
    return false;
}

/* server_remove_client: close and remove a client by slot index. */
static void server_remove_client(cn_ipc_server_t *s, int idx)
{
    if (s->client_fds[idx] >= 0) {
        (void)close(s->client_fds[idx]);
        s->client_fds[idx] = -1;
    }
}

/* -------------------------------------------------------------------------
 * Public API — server (POSIX)
 * ---------------------------------------------------------------------- */

cn_err_t cn_ipc_server_create(cn_ipc_server_t **server,
                              const char *socket_path)
{
    if (server == NULL || socket_path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(socket_path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }

    cn_ipc_server_t *s = (cn_ipc_server_t *)malloc(sizeof(*s));
    if (s == NULL) {
        return CN_ERR_NOMEM;
    }
    memset(s, 0, sizeof(*s));

    s->listen_fd = -1;
    for (int i = 0; i < CN_IPC_MAX_CLIENTS; i++) {
        s->client_fds[i] = -1;
    }
    /* Length was validated above; this cannot overflow. */
    cn_err_t rc_cpy = cn_strlcpy(s->socket_path, socket_path, CN_PATH_MAX);
    (void)rc_cpy;

    /* Remove a stale socket file if present. */
    (void)unlink(socket_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        free(s);
        return CN_ERR_IO;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t rc_sun = cn_strlcpy(addr.sun_path, socket_path,
                                sizeof(addr.sun_path));
    if (rc_sun >= sizeof(addr.sun_path)) {
        (void)close(fd);
        free(s);
        return CN_ERR_INVAL;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        CN_LOG_ERROR("bind(\"%s\"): %s", socket_path, CN_LOG_OS_ERR);
        (void)close(fd);
        free(s);
        return CN_ERR_IO;
    }

    /*
     * Set socket ownership to root:CN_IPC_SOCKET_GROUP with mode 0660 so
     * that members of the netcap group can connect without root privileges.
     * If the group does not exist, log a warning and fall back to 0600
     * (root-only), which keeps the service functional.
     */
    {
        struct group *grp = getgrnam(CN_IPC_SOCKET_GROUP);
        if (grp == NULL) {
            CN_LOG_WARN("group \"%s\" not found — IPC socket will be "
                        "accessible to root only; add users to the \"%s\" "
                        "group to allow unprivileged netcap-ctl access",
                        CN_IPC_SOCKET_GROUP, CN_IPC_SOCKET_GROUP);
        } else {
            if (chown(socket_path, (uid_t)-1, grp->gr_gid) != 0) {
                CN_LOG_WARN("chown(\"%s\", netcap): %s — socket may be "
                            "inaccessible to non-root users",
                            socket_path, CN_LOG_OS_ERR);
            } else if (chmod(socket_path, 0660) != 0) {
                CN_LOG_WARN("chmod(\"%s\", 0660): %s — socket may be "
                            "inaccessible to non-root users",
                            socket_path, CN_LOG_OS_ERR);
            }
        }
    }

    if (listen(fd, CN_IPC_MAX_CLIENTS) != 0) {
        CN_LOG_ERROR("listen(\"%s\"): %s", socket_path, CN_LOG_OS_ERR);
        (void)unlink(socket_path);
        (void)close(fd);
        free(s);
        return CN_ERR_IO;
    }

    s->listen_fd = fd;
    *server = s;
    return CN_OK;
}

cn_err_t cn_ipc_server_send(cn_ipc_server_t *server, cn_ipc_msg_type_t type,
                            const void *payload, uint32_t payload_len)
{
    if (server == NULL) {
        return CN_ERR_INVAL;
    }
    if (payload_len > CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }

    int sent = 0;
    for (int i = 0; i < CN_IPC_MAX_CLIENTS; i++) {
        if (server->client_fds[i] < 0) {
            continue;
        }
        cn_err_t rc = send_frame(server->client_fds[i], type,
                                 payload, payload_len);
        if (rc == CN_OK) {
            sent++;
        } else {
            /* Disconnect the failing client silently. */
            server_remove_client(server, i);
        }
    }

    return (sent > 0) ? CN_OK : CN_ERR_IO;
}

cn_err_t cn_ipc_server_recv(cn_ipc_server_t *server,
                            cn_ipc_msg_type_t *out_type,
                            void *buf, size_t buf_size, uint32_t *out_len)
{
    if (server == NULL || out_type == NULL || buf == NULL || out_len == NULL) {
        return CN_ERR_INVAL;
    }
    if (buf_size < CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }

    struct timeval tv;
    tv.tv_sec  = CN_IPC_RECV_TIMEOUT_S;
    tv.tv_usec = 0;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(server->listen_fd, &rfds);
    int maxfd = server->listen_fd;

    for (int i = 0; i < CN_IPC_MAX_CLIENTS; i++) {
        if (server->client_fds[i] >= 0) {
            FD_SET(server->client_fds[i], &rfds);
            if (server->client_fds[i] > maxfd) {
                maxfd = server->client_fds[i];
            }
        }
    }

    int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
        return CN_ERR_IO;
    }
    if (ret == 0) {
        return CN_ERR_TIMEOUT;
    }

    /* Accept any new connections first. */
    if (FD_ISSET(server->listen_fd, &rfds)) {
        int client_fd = accept(server->listen_fd, NULL, NULL);
        if (client_fd >= 0) {
            if (!server_add_client(server, client_fd)) {
                /* Client list full — reject the connection. */
                (void)close(client_fd);
            }
        }
        /* If a client is also ready to send, fall through to read it. */
    }

    /* Read from the first ready client. */
    for (int i = 0; i < CN_IPC_MAX_CLIENTS; i++) {
        if (server->client_fds[i] >= 0
                && FD_ISSET(server->client_fds[i], &rfds)) {
            cn_err_t rc = recv_frame(server->client_fds[i], out_type,
                                     buf, buf_size, out_len);
            if (rc != CN_OK) {
                server_remove_client(server, i);
            }
            return rc;
        }
    }

    /*
     * Only a new connection arrived (no existing client had data ready).
     * Report timeout so the caller loops back for the next message.
     */
    return CN_ERR_TIMEOUT;
}

void cn_ipc_server_destroy(cn_ipc_server_t **server)
{
    if (server == NULL || *server == NULL) {
        return;
    }

    cn_ipc_server_t *s = *server;
    *server = NULL;

    for (int i = 0; i < CN_IPC_MAX_CLIENTS; i++) {
        server_remove_client(s, i);
    }
    if (s->listen_fd >= 0) {
        (void)close(s->listen_fd);
    }
    (void)unlink(s->socket_path);
    free(s);
}

/* -------------------------------------------------------------------------
 * Public API — client (POSIX)
 * ---------------------------------------------------------------------- */

cn_err_t cn_ipc_client_connect(cn_ipc_client_t **client,
                               const char *socket_path)
{
    if (client == NULL || socket_path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(socket_path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }

    cn_ipc_client_t *c = (cn_ipc_client_t *)malloc(sizeof(*c));
    if (c == NULL) {
        return CN_ERR_NOMEM;
    }

    c->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c->fd < 0) {
        free(c);
        return CN_ERR_IO;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t rc_sun2 = cn_strlcpy(addr.sun_path, socket_path,
                                 sizeof(addr.sun_path));
    if (rc_sun2 >= sizeof(addr.sun_path)) {
        (void)close(c->fd);
        free(c);
        return CN_ERR_INVAL;
    }

    if (connect(c->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        (void)close(c->fd);
        free(c);
        return CN_ERR_IO;
    }

    *client = c;
    return CN_OK;
}

cn_err_t cn_ipc_client_send(cn_ipc_client_t *client, cn_ipc_msg_type_t type,
                            const void *payload, uint32_t payload_len)
{
    if (client == NULL) {
        return CN_ERR_INVAL;
    }
    if (payload_len > CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }
    return send_frame(client->fd, type, payload, payload_len);
}

cn_err_t cn_ipc_client_recv(cn_ipc_client_t *client,
                            cn_ipc_msg_type_t *out_type,
                            void *buf, size_t buf_size, uint32_t *out_len)
{
    if (client == NULL || out_type == NULL || buf == NULL || out_len == NULL) {
        return CN_ERR_INVAL;
    }
    if (buf_size < CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }

    struct timeval tv;
    tv.tv_sec  = CN_IPC_RECV_TIMEOUT_S;
    tv.tv_usec = 0;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(client->fd, &rfds);

    int ret = select(client->fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
        return CN_ERR_IO;
    }
    if (ret == 0) {
        return CN_ERR_TIMEOUT;
    }

    return recv_frame(client->fd, out_type, buf, buf_size, out_len);
}

void cn_ipc_client_destroy(cn_ipc_client_t **client)
{
    if (client == NULL || *client == NULL) {
        return;
    }

    if ((*client)->fd >= 0) {
        (void)close((*client)->fd);
    }
    free(*client);
    *client = NULL;
}

/* =========================================================================
 * Windows implementation (Named Pipes)
 *
 * v1 limitation: one client at a time per server instance.
 * Full multi-client support requires overlapped I/O (future work).
 * ====================================================================== */

#else /* _WIN32 */

struct cn_ipc_server {
    HANDLE pipe;
    int    connected;           /* 1 if a client is currently connected. */
    char   pipe_name[CN_PATH_MAX];
};

struct cn_ipc_client {
    HANDLE pipe;
};

/* -------------------------------------------------------------------------
 * Windows internal helpers
 * ---------------------------------------------------------------------- */

/*
 * win_recv_all: read exactly len bytes from a Named Pipe handle into buf.
 */
static cn_err_t win_recv_all(HANDLE h, void *buf, DWORD len)
{
    uint8_t *p         = (uint8_t *)buf;
    DWORD    remaining = len;

    while (remaining > 0) {
        DWORD n = 0;
        if (!ReadFile(h, p, remaining, &n, NULL) || n == 0) {
            return CN_ERR_IO;
        }
        p         += n;
        remaining -= n;
    }
    return CN_OK;
}

/*
 * win_send_all: write exactly len bytes from buf to a Named Pipe handle.
 */
static cn_err_t win_send_all(HANDLE h, const void *buf, DWORD len)
{
    const uint8_t *p         = (const uint8_t *)buf;
    DWORD          remaining = len;

    while (remaining > 0) {
        DWORD n = 0;
        if (!WriteFile(h, p, remaining, &n, NULL) || n == 0) {
            return CN_ERR_IO;
        }
        p         += n;
        remaining -= n;
    }
    return CN_OK;
}

static cn_err_t win_send_frame(HANDLE h, cn_ipc_msg_type_t type,
                               const void *payload, uint32_t payload_len)
{
    uint8_t hdr[IPC_HDR_WIRE_SIZE];
    put_u16_le(hdr + 0, (uint16_t)type);
    put_u16_le(hdr + 2, 0u);
    put_u32_le(hdr + 4, payload_len);

    cn_err_t rc = win_send_all(h, hdr, (DWORD)IPC_HDR_WIRE_SIZE);
    if (rc != CN_OK) {
        return rc;
    }
    if (payload_len > 0 && payload != NULL) {
        rc = win_send_all(h, payload, (DWORD)payload_len);
    }
    return rc;
}

static cn_err_t win_recv_frame(HANDLE h, cn_ipc_msg_type_t *out_type,
                               void *buf, size_t buf_size, uint32_t *out_len)
{
    uint8_t  raw[IPC_HDR_WIRE_SIZE];
    cn_err_t rc = win_recv_all(h, raw, (DWORD)IPC_HDR_WIRE_SIZE);
    if (rc != CN_OK) {
        return rc;
    }

    uint32_t payload_len = get_u32_le(raw + 4);
    if (payload_len > CN_IPC_MSG_MAX || payload_len > (uint32_t)buf_size) {
        return CN_ERR_IO;
    }

    *out_type = (cn_ipc_msg_type_t)get_u16_le(raw + 0);
    *out_len  = payload_len;

    if (payload_len > 0) {
        rc = win_recv_all(h, buf, (DWORD)payload_len);
    }
    return rc;
}

/* -------------------------------------------------------------------------
 * Public API — server (Windows Named Pipe)
 * ---------------------------------------------------------------------- */

cn_err_t cn_ipc_server_create(cn_ipc_server_t **server,
                              const char *socket_path)
{
    if (server == NULL || socket_path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(socket_path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }

    cn_ipc_server_t *s = (cn_ipc_server_t *)malloc(sizeof(*s));
    if (s == NULL) {
        return CN_ERR_NOMEM;
    }
    memset(s, 0, sizeof(*s));
    (void)cn_strlcpy(s->pipe_name, socket_path, CN_PATH_MAX);

    s->pipe = CreateNamedPipeA(
        socket_path,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        (DWORD)CN_IPC_MSG_MAX + (DWORD)IPC_HDR_WIRE_SIZE,
        (DWORD)CN_IPC_MSG_MAX + (DWORD)IPC_HDR_WIRE_SIZE,
        0,    /* default timeout */
        NULL  /* default security */
    );

    if (s->pipe == INVALID_HANDLE_VALUE) {
        free(s);
        return CN_ERR_IO;
    }

    *server = s;
    return CN_OK;
}

cn_err_t cn_ipc_server_send(cn_ipc_server_t *server, cn_ipc_msg_type_t type,
                            const void *payload, uint32_t payload_len)
{
    if (server == NULL) {
        return CN_ERR_INVAL;
    }
    if (payload_len > CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }
    if (!server->connected) {
        return CN_ERR_IO;
    }
    return win_send_frame(server->pipe, type, payload, payload_len);
}

cn_err_t cn_ipc_server_recv(cn_ipc_server_t *server,
                            cn_ipc_msg_type_t *out_type,
                            void *buf, size_t buf_size, uint32_t *out_len)
{
    if (server == NULL || out_type == NULL || buf == NULL || out_len == NULL) {
        return CN_ERR_INVAL;
    }
    if (buf_size < CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }

    if (!server->connected) {
        /* Block until a client connects (no timeout in v1 on Windows). */
        if (!ConnectNamedPipe(server->pipe, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_PIPE_CONNECTED) {
                return CN_ERR_IO;
            }
        }
        server->connected = 1;
    }

    cn_err_t rc = win_recv_frame(server->pipe, out_type, buf, buf_size, out_len);
    if (rc != CN_OK) {
        /* Disconnect and reset for the next client. */
        DisconnectNamedPipe(server->pipe);
        server->connected = 0;
    }
    return rc;
}

void cn_ipc_server_destroy(cn_ipc_server_t **server)
{
    if (server == NULL || *server == NULL) {
        return;
    }

    cn_ipc_server_t *s = *server;
    *server = NULL;

    if (s->connected) {
        DisconnectNamedPipe(s->pipe);
    }
    if (s->pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(s->pipe);
    }
    free(s);
}

/* -------------------------------------------------------------------------
 * Public API — client (Windows Named Pipe)
 * ---------------------------------------------------------------------- */

cn_err_t cn_ipc_client_connect(cn_ipc_client_t **client,
                               const char *socket_path)
{
    if (client == NULL || socket_path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(socket_path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }

    cn_ipc_client_t *c = (cn_ipc_client_t *)malloc(sizeof(*c));
    if (c == NULL) {
        return CN_ERR_NOMEM;
    }

    c->pipe = CreateFileA(
        socket_path,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        0, NULL
    );

    if (c->pipe == INVALID_HANDLE_VALUE) {
        free(c);
        return CN_ERR_IO;
    }

    /* Switch to byte-read mode (server may have created in message mode). */
    DWORD mode = PIPE_READMODE_BYTE;
    if (!SetNamedPipeHandleState(c->pipe, &mode, NULL, NULL)) {
        CloseHandle(c->pipe);
        free(c);
        return CN_ERR_IO;
    }

    *client = c;
    return CN_OK;
}

cn_err_t cn_ipc_client_send(cn_ipc_client_t *client, cn_ipc_msg_type_t type,
                            const void *payload, uint32_t payload_len)
{
    if (client == NULL) {
        return CN_ERR_INVAL;
    }
    if (payload_len > CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }
    return win_send_frame(client->pipe, type, payload, payload_len);
}

cn_err_t cn_ipc_client_recv(cn_ipc_client_t *client,
                            cn_ipc_msg_type_t *out_type,
                            void *buf, size_t buf_size, uint32_t *out_len)
{
    if (client == NULL || out_type == NULL || buf == NULL || out_len == NULL) {
        return CN_ERR_INVAL;
    }
    if (buf_size < CN_IPC_MSG_MAX) {
        return CN_ERR_INVAL;
    }

    /*
     * Implement the receive timeout via WaitForSingleObject on the pipe
     * handle.  Named Pipes support WaitNamedPipe for connect but not for
     * data-ready; use PeekNamedPipe to poll with a busy-wait.
     *
     * v1 limitation: this polls every 10 ms up to the timeout.  Overlapped
     * I/O would be more efficient but significantly more complex.
     */
    DWORD deadline_ms = CN_IPC_RECV_TIMEOUT_S * 1000u;
    DWORD elapsed_ms  = 0;

    while (elapsed_ms < deadline_ms) {
        DWORD avail = 0;
        if (!PeekNamedPipe(client->pipe, NULL, 0, NULL, &avail, NULL)) {
            return CN_ERR_IO;
        }
        if (avail >= (DWORD)IPC_HDR_WIRE_SIZE) {
            break;
        }
        Sleep(10);
        elapsed_ms += 10;
    }

    if (elapsed_ms >= deadline_ms) {
        return CN_ERR_TIMEOUT;
    }

    return win_recv_frame(client->pipe, out_type, buf, buf_size, out_len);
}

void cn_ipc_client_destroy(cn_ipc_client_t **client)
{
    if (client == NULL || *client == NULL) {
        return;
    }

    if ((*client)->pipe != INVALID_HANDLE_VALUE) {
        CloseHandle((*client)->pipe);
    }
    free(*client);
    *client = NULL;
}

#endif /* _WIN32 */
