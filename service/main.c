/*
 * GCC 10+ does not suppress warn_unused_result via (void) cast.
 * Use DISCARD() to explicitly store and discard the return value for calls
 * where the error genuinely cannot be propagated (signal handlers, event
 * callbacks, fire-and-forget IPC sends, best-effort shutdown paths).
 */
#define DISCARD(x)  do { cn_err_t _r_ = (x); (void)_r_; } while (0)

#include "platform.h"
#include "caps.h"
#include "savefile.h"
#include "upload_queue.h"

#include "../core/constants.h"
#include "../core/ring.h"
#include "../core/capture.h"
#include "../core/ipc.h"
#include "../core/str.h"
#include "../core/log.h"
#include "../config/parser.h"
#include "../config/validator.h"
#include "../config/config.h"
#include "../uploader/uploader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifndef _WIN32
#  include <unistd.h>
#  include <netdb.h>
#  include <arpa/inet.h>
#  include <pthread.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <ws2tcpip.h>
   /* Forward declaration of the Windows service entry point. */
   VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv);
#endif

/* =========================================================================
 * Global stop / reload flags.
 *
 * Written by signal handlers (POSIX) or ServiceCtrlHandler (Windows) and
 * by the IPC CONFIG_RELOAD handler.  Read by the IPC event loop.
 * ====================================================================== */

static volatile sig_atomic_t g_stop   = 0;
static volatile sig_atomic_t g_reload = 0;

void cn_service_request_stop(void)
{
    g_stop = 1;
}

void cn_service_request_reload(void)
{
    g_reload = 1;
    g_stop   = 1;
}

/* =========================================================================
 * Per-interface runtime state
 * ====================================================================== */

typedef struct {
    cn_ring_t           ring;
    cn_capture_ctx_t   *capture;
    cn_savefile_ctx_t  *savefile;
    bool                running;  /* true = capture + savefile threads active */
} cn_iface_state_t;

static cn_iface_state_t  g_ifaces[CN_IFACE_COUNT_MAX];
static uint32_t          g_iface_count = 0;
static cn_ipc_server_t  *g_ipc_server  = NULL;
static cn_config_t       g_config;

/* =========================================================================
 * Automatic upload worker
 * ====================================================================== */

static cn_upload_queue_t *g_upload_queue          = NULL;
static bool               g_upload_worker_started = false;

#ifndef _WIN32
static pthread_t g_upload_worker_thread;
#else
static HANDLE    g_upload_worker_thread = NULL;
#endif

/*
 * upload_worker: pops entries from the upload queue and calls cn_upload_file()
 * until the queue is shut down and drained.
 */
#ifndef _WIN32
static void *upload_worker(void *arg)
#else
static DWORD WINAPI upload_worker(LPVOID arg)
#endif
{
    (void)arg;

    char file_path[CN_PATH_MAX];
    char iface_name[CN_IFACE_NAME_MAX];

    while (cn_upload_queue_pop(g_upload_queue, file_path, iface_name) == CN_OK) {
        CN_LOG_INFO("auto-upload starting: \"%s\" (iface %s)",
                    file_path, iface_name);
        cn_err_t rc = cn_upload_file(file_path, iface_name,
                                     g_config.device,
                                     &g_config.upload);
        if (rc == CN_OK) {
            CN_LOG_INFO("auto-upload complete: \"%s\"", file_path);
        } else {
            CN_LOG_WARN("auto-upload failed for \"%s\" (iface %s): error %d",
                        file_path, iface_name, (int)rc);
        }
    }

#ifndef _WIN32
    return NULL;
#else
    return 0;
#endif
}

/* =========================================================================
 * Signal handling (POSIX only)
 * ====================================================================== */

#ifndef _WIN32
static void signal_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)sigaction(SIGINT,  &sa, NULL);

    /* Ignore SIGPIPE — broken IPC client connections must not kill the daemon. */
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa, NULL);
}
#endif

/* =========================================================================
 * BPF upload exclusion injection
 *
 * When upload is enabled and capture_upload_traffic == false, resolve the
 * hostname in endpoint_url and prepend "not host <ip>" to each interface's
 * BPF filter.  DNS failure is non-fatal: the service starts without the
 * exclusion and logs a warning.
 * ====================================================================== */

/*
 * parse_hostname: extract the hostname from "https://hostname/path".
 * Writes at most out_size-1 bytes to out (always NUL-terminates).
 * Returns CN_ERR_INVAL if the URL does not start with "https://".
 */
static cn_err_t parse_hostname(char *out, size_t out_size,
                               const char *url)
{
    const char *start = strstr(url, "://");
    if (start == NULL) {
        return CN_ERR_INVAL;
    }
    start += 3;

    size_t i = 0;
    while (start[i] != '\0' && start[i] != '/' && start[i] != ':'
               && i < out_size - 1u) {
        out[i] = start[i];
        i++;
    }
    out[i] = '\0';
    return (i > 0) ? CN_OK : CN_ERR_INVAL;
}

/*
 * resolve_exclusion_ip: resolve hostname to its first IPv4 address.
 * Writes the dotted-decimal string into ip_out (size >= INET_ADDRSTRLEN).
 * Returns CN_ERR_NET on failure.
 */
static cn_err_t resolve_exclusion_ip(char *ip_out, const char *hostname)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0 || res == NULL) {
        return CN_ERR_NET;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
#ifndef _WIN32
    const char *p = inet_ntop(AF_INET, &sin->sin_addr, ip_out, INET_ADDRSTRLEN);
#else
    const char *p = InetNtopA(AF_INET, &sin->sin_addr, ip_out, INET_ADDRSTRLEN);
#endif
    freeaddrinfo(res);
    return (p != NULL) ? CN_OK : CN_ERR_NET;
}

/*
 * build_effective_bpf: combine the user's BPF filter with the upload
 * exclusion (if applicable).  Out buffer is CN_BPF_FILTER_MAX * 2 to
 * accommodate the combined expression.
 *
 * Writes the effective filter into out[out_size].  Always NUL-terminates.
 */
static void build_effective_bpf(char *out, size_t out_size,
                                 const char *user_filter,
                                 const char *excl_ip)
{
    if (excl_ip == NULL || excl_ip[0] == '\0') {
        DISCARD(cn_strlcpy(out, user_filter, out_size));
        return;
    }

    if (user_filter[0] != '\0') {
        (void)snprintf(out, out_size,
                       "not host %s and (%s)", excl_ip, user_filter);
    } else {
        (void)snprintf(out, out_size, "not host %s", excl_ip);
    }
}

/* =========================================================================
 * IPC message handlers
 * ====================================================================== */

/* Handle PING — respond with PONG. */
static void handle_ping(void)
{
    DISCARD(cn_ipc_server_send(g_ipc_server, CN_IPC_MSG_PONG, NULL, 0));
}

/* Handle STATUS_REQ — broadcast a cn_ipc_status_t snapshot. */
static void handle_status_req(void)
{
    cn_ipc_status_t status;
    memset(&status, 0, sizeof(status));
    status.iface_count = g_iface_count;

    for (uint32_t i = 0; i < g_iface_count; i++) {
        cn_ipc_iface_status_t *s = &status.ifaces[i];
        const cn_iface_config_t *cfg = &g_config.interfaces[i];

        DISCARD(cn_strlcpy(s->iface_name, cfg->name, CN_IFACE_NAME_MAX));
        s->capturing = g_ifaces[i].running ? 1u : 0u;

        if (g_ifaces[i].running && g_ifaces[i].capture != NULL) {
            cn_capture_stats_t stats;
            if (cn_capture_get_stats(g_ifaces[i].capture, &stats) == CN_OK) {
                s->pkts_written  = stats.pkts_written;
                s->bytes_written = stats.bytes_written;
            }
        }
    }

    DISCARD(cn_ipc_server_send(g_ipc_server, CN_IPC_MSG_STATUS_RESP,
                               &status, (uint32_t)sizeof(status)));
}

/*
 * find_iface: return the index of the interface with the given name,
 * or -1 if not found.
 */
static int find_iface(const char *name)
{
    for (uint32_t i = 0; i < g_iface_count; i++) {
        if (strncmp(g_config.interfaces[i].name, name,
                    CN_IFACE_NAME_MAX) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Handle CAPTURE_START — start capture on the named interface. */
static void handle_capture_start(const uint8_t *payload, uint32_t len)
{
    if (len == 0 || len >= CN_IFACE_NAME_MAX) {
        return;
    }

    char name[CN_IFACE_NAME_MAX];
    memcpy(name, payload, len);
    name[len] = '\0';

    int idx = find_iface(name);
    if (idx < 0 || g_ifaces[idx].running) {
        return;
    }

    if (cn_savefile_start(g_ifaces[idx].savefile) == CN_OK
            && cn_capture_start(g_ifaces[idx].capture) == CN_OK) {
        g_ifaces[idx].running = true;
        DISCARD(cn_ipc_server_send(g_ipc_server,
                                   CN_IPC_MSG_CAPTURE_EVENT, NULL, 0));
    }
}

/* Handle CAPTURE_STOP — stop capture on the named interface. */
static void handle_capture_stop(const uint8_t *payload, uint32_t len)
{
    if (len == 0 || len >= CN_IFACE_NAME_MAX) {
        return;
    }

    char name[CN_IFACE_NAME_MAX];
    memcpy(name, payload, len);
    name[len] = '\0';

    int idx = find_iface(name);
    if (idx < 0 || !g_ifaces[idx].running) {
        return;
    }

    /* Stop capture first (no more ring writes), then drain via savefile. */
    DISCARD(cn_capture_stop(g_ifaces[idx].capture));
    DISCARD(cn_savefile_stop(g_ifaces[idx].savefile));
    g_ifaces[idx].running = false;
    DISCARD(cn_ipc_server_send(g_ipc_server, CN_IPC_MSG_CAPTURE_EVENT, NULL, 0));
}

/* =========================================================================
 * Shutdown — stop all interfaces and release resources.
 * ====================================================================== */

static void service_shutdown(void)
{
    DISCARD(cn_platform_notify_stopping());

    for (uint32_t i = 0; i < g_iface_count; i++) {
        if (g_ifaces[i].running) {
            DISCARD(cn_capture_stop(g_ifaces[i].capture));
            DISCARD(cn_savefile_stop(g_ifaces[i].savefile));
            g_ifaces[i].running = false;
        }
        cn_capture_destroy(&g_ifaces[i].capture);
        cn_savefile_destroy(&g_ifaces[i].savefile);
        cn_ring_destroy(&g_ifaces[i].ring);
    }

    /* All savefile workers have stopped — no more pushes to the upload queue.
     * Shut down the queue (drains remaining entries) and join the worker. */
    if (g_upload_queue != NULL) {
        cn_upload_queue_shutdown(g_upload_queue);
        if (g_upload_worker_started) {
#ifndef _WIN32
            (void)pthread_join(g_upload_worker_thread, NULL);
#else
            (void)WaitForSingleObject(g_upload_worker_thread, INFINITE);
            CloseHandle(g_upload_worker_thread);
            g_upload_worker_thread = NULL;
#endif
            g_upload_worker_started = false;
        }
        cn_upload_queue_destroy(&g_upload_queue);
    }

    if (g_ipc_server != NULL) {
        cn_ipc_server_destroy(&g_ipc_server);
    }
}

/* =========================================================================
 * cn_service_run — complete service lifecycle.
 * Called by main() on POSIX and by ServiceMain() on Windows.
 * ====================================================================== */

int cn_service_run(const char *config_path)
{
    /* Initialise logging at ERROR level before the config is loaded so that
     * early startup failures are always visible. */
    cn_log_init(CN_LOG_LEVEL_ERROR);

    if (config_path == NULL) {
        config_path = CN_DEFAULT_CONFIG_PATH;
    }

    CN_LOG_INFO("starting (config: %s)", config_path);

    /* ------------------------------------------------------------------ */
    /* 1. Load and validate configuration.                                  */
    /* ------------------------------------------------------------------ */

    if (cn_parser_load(&g_config, config_path) != CN_OK) {
        CN_LOG_ERROR("failed to load configuration from \"%s\"", config_path);
        cn_log_destroy();
        return 1;
    }
    if (cn_validator_check(&g_config) != CN_OK) {
        CN_LOG_ERROR("configuration validation failed");
        cn_log_destroy();
        return 1;
    }

    /* Apply the configured log level now that the config is valid. */
    cn_log_init((cn_log_level_t)g_config.log_level);

    /* ------------------------------------------------------------------ */
    /* 2. Resolve upload exclusion IP (non-fatal if DNS fails).             */
    /* ------------------------------------------------------------------ */

    char excl_ip[INET_ADDRSTRLEN];
    excl_ip[0] = '\0';

    if (cn_upload_is_enabled(&g_config.upload)
            && !g_config.upload.capture_upload_traffic) {
        char hostname[256];
        if (parse_hostname(hostname, sizeof(hostname),
                           g_config.upload.endpoint_url) == CN_OK) {
            if (resolve_exclusion_ip(excl_ip, hostname) != CN_OK) {
                CN_LOG_WARN("could not resolve upload endpoint hostname "
                            "\"%s\" — upload traffic will not be excluded "
                            "from capture", hostname);
                excl_ip[0] = '\0';
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* 2a. Create upload queue when auto-upload is enabled.                */
    /* ------------------------------------------------------------------ */

    if (g_config.upload.auto_upload && cn_upload_is_enabled(&g_config.upload)) {
        if (cn_upload_queue_create(&g_upload_queue) != CN_OK) {
            CN_LOG_ERROR("failed to create upload queue");
            cn_log_destroy();
            return 1;
        }
        CN_LOG_INFO("automatic upload enabled");
    }

    /* ------------------------------------------------------------------ */
    /* 3. Initialize rings and capture contexts (requires CAP_NET_RAW).    */
    /* ------------------------------------------------------------------ */

    g_iface_count = g_config.iface_count;
    memset(g_ifaces, 0, sizeof(g_ifaces));

    for (uint32_t i = 0; i < g_iface_count; i++) {
        const cn_iface_config_t *cfg = &g_config.interfaces[i];

        /* Build ring file path: <ring_dir>/ring_<iface>.bin */
        char ring_path[CN_PATH_MAX];
        int n = snprintf(ring_path, sizeof(ring_path),
                         "%s/ring_%s.bin",
                         g_config.ring_dir, cfg->name);
        if (n < 0 || (size_t)n >= sizeof(ring_path)) {
            CN_LOG_ERROR("ring path too long for interface \"%s\"", cfg->name);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }

        CN_LOG_INFO("initialising ring buffer: %s", ring_path);
        if (cn_ring_init(&g_ifaces[i].ring, ring_path,
                         (size_t)cfg->ring_size) != CN_OK) {
            CN_LOG_ERROR("failed to initialise ring buffer at \"%s\"",
                         ring_path);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }

        /* Build the effective BPF filter (user filter + upload exclusion). */
        char effective_bpf[CN_BPF_FILTER_MAX * 2u];
        build_effective_bpf(effective_bpf, sizeof(effective_bpf),
                            cfg->bpf_filter, excl_ip);

        CN_LOG_INFO("opening capture on interface \"%s\" (snaplen=%d, "
                    "bpf=\"%s\")",
                    cfg->name, cfg->snaplen,
                    effective_bpf[0] != '\0' ? effective_bpf : "(none)");
        if (cn_capture_init(&g_ifaces[i].capture,
                            cfg->name,
                            &g_ifaces[i].ring,
                            cfg->snaplen,
                            (effective_bpf[0] != '\0') ? effective_bpf : NULL)
                != CN_OK) {
            CN_LOG_ERROR("failed to open capture on interface \"%s\"",
                         cfg->name);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }

        int link_type = cn_capture_get_link_type(g_ifaces[i].capture);

        if (cn_savefile_init(&g_ifaces[i].savefile,
                             &g_ifaces[i].ring,
                             g_config.savefile_dir,
                             cfg->name,
                             link_type,
                             (uint32_t)cfg->snaplen,
                             g_config.savefile_rotation_secs,
                             g_config.savefile_max_count,
                             g_upload_queue) != CN_OK) {
            CN_LOG_ERROR("failed to initialise savefile writer for \"%s\"",
                         cfg->name);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }
    }

    /* ------------------------------------------------------------------ */
    /* 4. Start savefile writers for enabled interfaces.                   */
    /*                                                                      */
    /* Savefiles are opened here, before privilege drop, so that the       */
    /* captures directory can be writable by the invoking user even when    */
    /* the service runs as root (which loses CAP_DAC_OVERRIDE after drop). */
    /* ------------------------------------------------------------------ */

    for (uint32_t i = 0; i < g_iface_count; i++) {
        if (!g_config.interfaces[i].enabled) {
            continue;
        }
        if (cn_savefile_start(g_ifaces[i].savefile) != CN_OK) {
            CN_LOG_ERROR("failed to start savefile writer for \"%s\"",
                         g_config.interfaces[i].name);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }
    }

    /* ------------------------------------------------------------------ */
    /* 5. Create the IPC server while still root so that chown/chmod       */
    /*    succeed and group members can connect after privilege drop.       */
    /* ------------------------------------------------------------------ */

    if (cn_ipc_server_create(&g_ipc_server,
                             CN_DEFAULT_IPC_SOCKET_PATH) != CN_OK) {
        CN_LOG_ERROR("failed to create IPC server at \"%s\"",
                     CN_DEFAULT_IPC_SOCKET_PATH);
        service_shutdown();
        cn_log_destroy();
        return 1;
    }
    CN_LOG_INFO("IPC server listening at \"%s\"", CN_DEFAULT_IPC_SOCKET_PATH);

    /* ------------------------------------------------------------------ */
    /* 6. Drop elevated privileges.                                         */
    /*                                                                      */
    /* All pcap handles are open, the first savefile is created, and the  */
    /* IPC socket is bound and chowned.  Drop capabilities before starting */
    /* capture threads so that no elevated privilege is held while         */
    /* processing untrusted packet data.                                   */
    /* ------------------------------------------------------------------ */

    if (cn_caps_drop() != CN_OK) {
        CN_LOG_ERROR("failed to drop elevated privileges");
        service_shutdown();
        cn_log_destroy();
        return 1;
    }
    CN_LOG_INFO("elevated privileges dropped");

    /* ------------------------------------------------------------------ */
    /* 5a. Verify directory writability with post-drop credentials.        */
    /*                                                                      */
    /* Rotation opens new savefiles from the worker thread, so the         */
    /* savefile directory must remain writable after the privilege drop.   */
    /* Catching this here avoids a silent failure 3 minutes into capture.  */
    /* ------------------------------------------------------------------ */

#ifndef _WIN32
    if (access(g_config.savefile_dir, W_OK) != 0) {
        CN_LOG_ERROR("savefile directory \"%s\" is not writable after "
                     "privilege drop: %s — fix ownership or permissions "
                     "(e.g. chown root:root %s)",
                     g_config.savefile_dir, CN_LOG_OS_ERR,
                     g_config.savefile_dir);
        service_shutdown();
        cn_log_destroy();
        return 1;
    }
    if (access(g_config.ring_dir, W_OK) != 0) {
        CN_LOG_ERROR("ring directory \"%s\" is not writable after "
                     "privilege drop: %s — fix ownership or permissions "
                     "(e.g. chown root:root %s)",
                     g_config.ring_dir, CN_LOG_OS_ERR,
                     g_config.ring_dir);
        service_shutdown();
        cn_log_destroy();
        return 1;
    }
#endif

    /* ------------------------------------------------------------------ */
    /* 7. Start capture threads for enabled interfaces.                    */
    /* ------------------------------------------------------------------ */

    for (uint32_t i = 0; i < g_iface_count; i++) {
        if (!g_config.interfaces[i].enabled) {
            continue;
        }
        if (cn_capture_start(g_ifaces[i].capture) != CN_OK) {
            CN_LOG_ERROR("failed to start capture thread for \"%s\"",
                         g_config.interfaces[i].name);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }
        g_ifaces[i].running = true;
        CN_LOG_INFO("capture started on interface \"%s\"",
                    g_config.interfaces[i].name);
    }

    /* ------------------------------------------------------------------ */
    /* 7a. Start the upload worker thread if auto-upload is enabled.       */
    /* ------------------------------------------------------------------ */

    if (g_upload_queue != NULL) {
#ifndef _WIN32
        if (pthread_create(&g_upload_worker_thread, NULL,
                           upload_worker, NULL) != 0) {
            CN_LOG_ERROR("failed to start upload worker thread: %s",
                         CN_LOG_OS_ERR);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }
#else
        g_upload_worker_thread = CreateThread(NULL, 0, upload_worker,
                                              NULL, 0, NULL);
        if (g_upload_worker_thread == NULL) {
            CN_LOG_ERROR("failed to start upload worker thread: %s",
                         CN_LOG_OS_ERR);
            service_shutdown();
            cn_log_destroy();
            return 1;
        }
#endif
        g_upload_worker_started = true;
        CN_LOG_INFO("upload worker thread started");
    }

    DISCARD(cn_platform_notify_ready());
    CN_LOG_INFO("service ready");

    /* ------------------------------------------------------------------ */
    /* 7. IPC event loop.                                                   */
    /* ------------------------------------------------------------------ */

    uint8_t  msg_buf[CN_IPC_MSG_MAX];
    uint32_t msg_len;
    cn_ipc_msg_type_t msg_type;

    while (!g_stop) {
        cn_err_t rc = cn_ipc_server_recv(g_ipc_server, &msg_type,
                                         msg_buf, sizeof(msg_buf), &msg_len);

        if (rc == CN_ERR_TIMEOUT) {
            DISCARD(cn_platform_notify_watchdog());
            continue;
        }
        if (rc != CN_OK) {
            continue; /* Transient error — loop and try again. */
        }

        switch (msg_type) {
        case CN_IPC_MSG_PING:
            handle_ping();
            break;

        case CN_IPC_MSG_STATUS_REQ:
            handle_status_req();
            break;

        case CN_IPC_MSG_CAPTURE_START:
            handle_capture_start(msg_buf, msg_len);
            break;

        case CN_IPC_MSG_CAPTURE_STOP:
            handle_capture_stop(msg_buf, msg_len);
            break;

        case CN_IPC_MSG_CONFIG_RELOAD:
            cn_service_request_reload();
            break;

        default:
            /* Unknown message type — ignore. */
            break;
        }
    }

    /* ------------------------------------------------------------------ */
    /* 8. Clean shutdown.                                                   */
    /* ------------------------------------------------------------------ */

    CN_LOG_INFO("shutting down");
    service_shutdown();
    CN_LOG_INFO("stopped");
    cn_log_destroy();

    /*
     * Exit code 0 for both normal stop and config reload.
     * On reload, the OS service manager (systemd Restart=on-success,
     * launchd KeepAlive, Windows SCM auto-restart) will restart the service
     * and it will load the updated config file.
     */
    return 0;
}

/* =========================================================================
 * main() — platform dispatch
 * ====================================================================== */

int main(int argc, char *argv[])
{
    /* Parse the optional --config <path> argument. */
    const char *config_path = NULL;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            config_path = argv[i + 1];
            break;
        }
    }

#ifndef _WIN32
    setup_signals();
    return cn_service_run(config_path);

#else /* _WIN32 */
    /*
     * Attempt to connect to the Service Control Manager.  If the process
     * was not launched by the SCM, StartServiceCtrlDispatcher fails with
     * ERROR_FAILED_SERVICE_CONTROLLER_CONNECT — treat that as interactive
     * (debug) mode and run directly.
     */
    WSAData wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SERVICE_TABLE_ENTRY table[] = {
        { (LPSTR)"netcap", ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherA(table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* Interactive / debug mode. */
            int rc = cn_service_run(config_path);
            WSACleanup();
            return rc;
        }
        WSACleanup();
        return 1;
    }

    WSACleanup();
    return 0;
#endif /* _WIN32 */
}
