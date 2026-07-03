#ifndef CN_IPC_H
#define CN_IPC_H

#include <stddef.h>
#include <stdint.h>
#include "constants.h"

/* -------------------------------------------------------------------------
 * Message type codes
 * ---------------------------------------------------------------------- */

/**
 * IPC message types exchanged between the service and GUI/CLI clients.
 * Stored as uint16_t on the wire (little-endian).
 */
typedef enum {
    CN_IPC_MSG_PING          = 0x0001, /* Health-check request. No payload. */
    CN_IPC_MSG_PONG          = 0x0002, /* Health-check reply. No payload. */
    CN_IPC_MSG_STATUS_REQ    = 0x0010, /* Request a service status snapshot. */
    CN_IPC_MSG_STATUS_RESP   = 0x0011, /* Service status snapshot (payload: cn_ipc_status_t). */
    CN_IPC_MSG_CAPTURE_START = 0x0020, /* Start capture on an interface (payload: interface name). */
    CN_IPC_MSG_CAPTURE_STOP  = 0x0021, /* Stop capture on an interface (payload: interface name). */
    CN_IPC_MSG_CAPTURE_EVENT = 0x0022, /* Async state-change notification from service to clients. */
    CN_IPC_MSG_CONFIG_RELOAD = 0x0030, /* Request the service to reload its TOML config file. */
    CN_IPC_MSG_ERROR         = 0x00FF, /* Error response. Payload is a int32_t cn_err_t. */
} cn_ipc_msg_type_t;

/* -------------------------------------------------------------------------
 * Wire-format header
 * ---------------------------------------------------------------------- */

/**
 * Fixed-size header prepended to every IPC message on the wire.
 * The payload (payload_len bytes) immediately follows in the byte stream.
 * All multi-byte fields are little-endian.
 */
typedef struct __attribute__((packed)) {
    uint16_t type;         /* cn_ipc_msg_type_t cast to uint16_t. */
    uint16_t reserved;     /* Must be zero on send; ignored on receive. */
    uint32_t payload_len;  /* Payload length in bytes. 0 if no payload.
                              Must be <= CN_IPC_MSG_MAX. */
} cn_ipc_header_t;

/* -------------------------------------------------------------------------
 * Status payload (CN_IPC_MSG_STATUS_RESP)
 * ---------------------------------------------------------------------- */

/** Per-interface capture state included in a status response. */
typedef struct {
    char     iface_name[CN_IFACE_NAME_MAX]; /* Interface name. */
    uint8_t  capturing;                     /* 1 if capture is active, 0 otherwise. */
    uint8_t  uploading;                     /* 1 if an upload is in progress, 0 otherwise. */
    uint8_t  _pad[2];                       /* Explicit padding for alignment. */
    uint64_t pkts_written;                  /* Packets written to the ring since start. */
    uint64_t bytes_written;                 /* Bytes written to the ring since start. */
} cn_ipc_iface_status_t;

/** Full service status snapshot (payload of CN_IPC_MSG_STATUS_RESP). */
typedef struct {
    uint32_t              iface_count;                    /* Number of valid entries in ifaces[]. */
    uint8_t               _pad[4];                        /* Explicit padding for alignment. */
    cn_ipc_iface_status_t ifaces[CN_IFACE_COUNT_MAX];    /* Per-interface status entries. */
} cn_ipc_status_t;

/* -------------------------------------------------------------------------
 * Server handle (service side) — opaque
 * ---------------------------------------------------------------------- */

/** Listens for incoming GUI/CLI connections on a Unix socket or Named Pipe. */
typedef struct cn_ipc_server cn_ipc_server_t;

/**
 * Unix group that is granted access to the IPC socket (mode 0660).
 * Members of this group can run netcap-ctl without elevated privileges.
 * On Windows this constant is unused (Named Pipe ACLs apply instead).
 */
#define CN_IPC_SOCKET_GROUP "netcap"

/**
 * @brief Create and bind an IPC server endpoint.
 *
 * On Linux/macOS: creates a Unix domain socket at socket_path, owned by
 * root:CN_IPC_SOCKET_GROUP with mode 0660 so that group members can connect
 * without elevated privileges.
 * On Windows: creates a Named Pipe at socket_path
 * (e.g., "\\\\.\\pipe\\netcap").
 *
 * @security socket_path must be validated against CN_PATH_MAX. The socket
 *           is restricted to the CN_IPC_SOCKET_GROUP group (0660). Do not
 *           place the socket in a world-writable directory.
 *
 * @param[out] server       Set to the allocated server on success. Must not be NULL.
 * @param[in]  socket_path  Unix socket path or Named Pipe name. Must not be NULL.
 *                          Length must be < CN_PATH_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if server or socket_path is NULL, or path too long.
 * @return CN_ERR_IO     if the socket or pipe cannot be created or bound.
 * @return CN_ERR_NOMEM  if allocation fails.
 */
cn_err_t cn_ipc_server_create(cn_ipc_server_t **server, const char *socket_path)
    __attribute__((warn_unused_result));

/**
 * @brief Broadcast an IPC message to all currently connected clients.
 *
 * Serializes type and payload into a wire frame and writes it to every
 * connected client. Clients that fail mid-send are silently disconnected.
 *
 * @param[in,out] server       Bound server. Must not be NULL.
 * @param[in]     type         Message type to send.
 * @param[in]     payload      Payload buffer. May be NULL only if payload_len == 0.
 * @param[in]     payload_len  Payload size in bytes. Must be <= CN_IPC_MSG_MAX.
 *
 * @return CN_OK if at least one client received the message.
 * @return CN_ERR_INVAL if server is NULL or payload_len > CN_IPC_MSG_MAX.
 * @return CN_ERR_IO    if no clients are connected or all sends fail.
 */
cn_err_t cn_ipc_server_send(cn_ipc_server_t *server, cn_ipc_msg_type_t type,
                            const void *payload, uint32_t payload_len)
    __attribute__((warn_unused_result));

/**
 * @brief Receive one IPC message from a client (blocking).
 *
 * Reads the cn_ipc_header_t then the payload into buf. Blocks until a
 * complete message arrives or an error or timeout occurs.
 *
 * @param[in,out] server    Bound server. Must not be NULL.
 * @param[out]    out_type  Filled with the received message type. Must not be NULL.
 * @param[out]    buf       Payload destination buffer. Must not be NULL.
 * @param[in]     buf_size  Capacity of buf. Must be >= CN_IPC_MSG_MAX.
 * @param[out]    out_len   Set to the number of payload bytes received. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL   if any pointer is NULL or buf_size < CN_IPC_MSG_MAX.
 * @return CN_ERR_IO      if the connection closes or a read error occurs.
 * @return CN_ERR_TIMEOUT if no message arrives within the configured timeout.
 */
cn_err_t cn_ipc_server_recv(cn_ipc_server_t *server, cn_ipc_msg_type_t *out_type,
                            void *buf, size_t buf_size, uint32_t *out_len)
    __attribute__((warn_unused_result));

/**
 * @brief Destroy the IPC server and release all resources.
 *
 * Closes all client connections, removes the socket file or Named Pipe name,
 * and frees internal state. Sets *server to NULL on return.
 *
 * @param[in,out] server  Pointer to a server handle. Must not be NULL.
 *                        *server may be NULL (no-op).
 */
void cn_ipc_server_destroy(cn_ipc_server_t **server);

/* -------------------------------------------------------------------------
 * Client handle (GUI / CLI side) — opaque
 * ---------------------------------------------------------------------- */

/** Used by the GUI and CLI to connect to and communicate with the service. */
typedef struct cn_ipc_client cn_ipc_client_t;

/**
 * @brief Connect to the netcap service IPC endpoint.
 *
 * @security socket_path must be validated against CN_PATH_MAX.
 *
 * @param[out] client      Set to the allocated client on success. Must not be NULL.
 * @param[in]  socket_path Unix socket path or Named Pipe name. Must not be NULL.
 *                         Length must be < CN_PATH_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if client or socket_path is NULL, or path too long.
 * @return CN_ERR_IO     if the connection cannot be established.
 * @return CN_ERR_NOMEM  if allocation fails.
 */
cn_err_t cn_ipc_client_connect(cn_ipc_client_t **client, const char *socket_path)
    __attribute__((warn_unused_result));

/**
 * @brief Send a message to the service.
 *
 * @param[in,out] client      Connected client. Must not be NULL.
 * @param[in]     type        Message type.
 * @param[in]     payload     Payload buffer. May be NULL only if payload_len == 0.
 * @param[in]     payload_len Payload size in bytes. Must be <= CN_IPC_MSG_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if client is NULL or payload_len > CN_IPC_MSG_MAX.
 * @return CN_ERR_IO    if the send fails or the connection is closed.
 */
cn_err_t cn_ipc_client_send(cn_ipc_client_t *client, cn_ipc_msg_type_t type,
                            const void *payload, uint32_t payload_len)
    __attribute__((warn_unused_result));

/**
 * @brief Receive one message from the service (blocking).
 *
 * @param[in,out] client    Connected client. Must not be NULL.
 * @param[out]    out_type  Filled with the received message type. Must not be NULL.
 * @param[out]    buf       Payload destination buffer. Must not be NULL.
 * @param[in]     buf_size  Capacity of buf. Must be >= CN_IPC_MSG_MAX.
 * @param[out]    out_len   Set to the number of payload bytes received. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL   if any pointer is NULL or buf_size < CN_IPC_MSG_MAX.
 * @return CN_ERR_IO      if the connection closes or a read error occurs.
 * @return CN_ERR_TIMEOUT if no message arrives within the configured timeout.
 */
cn_err_t cn_ipc_client_recv(cn_ipc_client_t *client, cn_ipc_msg_type_t *out_type,
                            void *buf, size_t buf_size, uint32_t *out_len)
    __attribute__((warn_unused_result));

/**
 * @brief Disconnect from the service and free the client handle.
 *
 * Sets *client to NULL on return.
 *
 * @param[in,out] client  Pointer to a client handle. Must not be NULL.
 *                        *client may be NULL (no-op).
 */
void cn_ipc_client_destroy(cn_ipc_client_t **client);

#endif /* CN_IPC_H */
