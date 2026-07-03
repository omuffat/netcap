/*
 * netcap-ctl — command-line interface for the netcap service.
 *
 * Usage:
 *   netcap-ctl [--config <path>] <command> [arguments]
 *
 * Commands that communicate with the running service via IPC:
 *   ping                  Verify the service is alive.
 *   status                Print per-interface capture statistics.
 *   start <iface>         Start capture on an interface.
 *   stop  <iface>         Stop capture on an interface.
 *   reload                Ask the service to restart with the current config.
 *
 * Commands that operate locally (no IPC):
 *   config check          Load and validate the configuration file.
 *   upload <file>         Upload a savefile to the configured endpoint.
 *
 * The --config flag sets the configuration file path used by 'config check'
 * and 'upload'.  IPC commands always connect to CN_DEFAULT_IPC_SOCKET_PATH.
 */
#include "../core/constants.h"
#include "../core/ipc.h"
#include "../config/parser.h"
#include "../config/validator.h"
#include "../config/config.h"
#include "../uploader/uploader.h"

#include "../core/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifndef _WIN32
#  include <unistd.h>
#else
#  include <io.h>
#  define access _access
#  define F_OK   0
#endif

/* -------------------------------------------------------------------------
 * Global config path — set by --config, defaults to CN_DEFAULT_CONFIG_PATH.
 * ---------------------------------------------------------------------- */

static const char *g_config_path = CN_DEFAULT_CONFIG_PATH;

/* =========================================================================
 * Formatting helpers
 * ====================================================================== */

/*
 * Format a byte count as a human-readable string into buf[n].
 * Always NUL-terminates.  Precondition: buf != NULL, n > 0.
 */
static void fmt_bytes(uint64_t bytes, char *buf, size_t n)
{
    if (bytes < 1024u) {
        (void)snprintf(buf, n, "%llu B", (unsigned long long)bytes);
    } else if (bytes < 1024u * 1024u) {
        (void)snprintf(buf, n, "%.1f KiB",
                       (double)bytes / 1024.0);
    } else if (bytes < 1024u * 1024u * 1024u) {
        (void)snprintf(buf, n, "%.1f MiB",
                       (double)bytes / (1024.0 * 1024.0));
    } else {
        (void)snprintf(buf, n, "%.1f GiB",
                       (double)bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

/* =========================================================================
 * IPC helpers
 * ====================================================================== */

/*
 * Connect to the service, send one message, wait for one response.
 * On return *out_type and resp_buf/resp_len are populated when rc == CN_OK.
 * resp_buf may be NULL (caller not interested in payload).
 *
 * Preconditions: out_type != NULL.
 */
static cn_err_t ipc_send_recv(cn_ipc_msg_type_t  send_type,
                               const void        *payload,
                               uint32_t           payload_len,
                               cn_ipc_msg_type_t *out_type,
                               uint8_t           *resp_buf,
                               uint32_t          *resp_len)
{
    cn_ipc_client_t *client = NULL;
    cn_err_t rc = cn_ipc_client_connect(&client, CN_DEFAULT_IPC_SOCKET_PATH);
    if (rc != CN_OK) {
        return rc;
    }

    rc = cn_ipc_client_send(client, send_type, payload, payload_len);
    if (rc != CN_OK) {
        goto done;
    }

    uint8_t  buf[CN_IPC_MSG_MAX];
    uint32_t len = 0;
    rc = cn_ipc_client_recv(client, out_type, buf, sizeof(buf), &len);
    if (rc == CN_OK) {
        if (resp_buf != NULL && len > 0) {
            memcpy(resp_buf, buf, len);
        }
        if (resp_len != NULL) {
            *resp_len = len;
        }
    }

done:
    cn_ipc_client_destroy(&client);
    return rc;
}

/*
 * Connect to the service and send one message without waiting for a response.
 * Used for CONFIG_RELOAD where the service exits immediately after receipt.
 */
static cn_err_t ipc_send_only(cn_ipc_msg_type_t send_type,
                               const void       *payload,
                               uint32_t          payload_len)
{
    cn_ipc_client_t *client = NULL;
    cn_err_t rc = cn_ipc_client_connect(&client, CN_DEFAULT_IPC_SOCKET_PATH);
    if (rc != CN_OK) {
        return rc;
    }
    rc = cn_ipc_client_send(client, send_type, payload, payload_len);
    cn_ipc_client_destroy(&client);
    return rc;
}

/*
 * Print the cn_err_t extracted from a CN_IPC_MSG_ERROR payload.
 * Precondition: buf != NULL.
 */
static void print_ipc_error(const uint8_t *buf, uint32_t len)
{
    int32_t code = 0;
    if (len >= sizeof(int32_t)) {
        memcpy(&code, buf, sizeof(int32_t));
    }
    (void)fprintf(stderr, "Service error: %s (%d).\n",
                  cn_err_str((cn_err_t)code), (int)code);
}

/* =========================================================================
 * Commands
 * ====================================================================== */

/* ping — health-check: send PING, expect PONG. */
static int cmd_ping(void)
{
    cn_ipc_msg_type_t resp_type;
    cn_err_t rc = ipc_send_recv(CN_IPC_MSG_PING, NULL, 0,
                                 &resp_type, NULL, NULL);
    if (rc == CN_ERR_TIMEOUT) {
        (void)fprintf(stderr,
            "Ping timed out — the service may not be running.\n");
        return 1;
    }
    if (rc != CN_OK) {
        (void)fprintf(stderr, "Connection failed: %s (%d).\n",
                      cn_err_str(rc), (int)rc);
        return 1;
    }
    if (resp_type != CN_IPC_MSG_PONG) {
        (void)fprintf(stderr,
            "Unexpected response (type 0x%04x).\n", (unsigned)resp_type);
        return 1;
    }
    (void)printf("Service is running.\n");
    return 0;
}

/* status — request a status snapshot and print a formatted table. */
static int cmd_status(void)
{
    cn_ipc_msg_type_t resp_type;
    uint8_t  resp_buf[CN_IPC_MSG_MAX];
    uint32_t resp_len = 0;

    cn_err_t rc = ipc_send_recv(CN_IPC_MSG_STATUS_REQ, NULL, 0,
                                 &resp_type, resp_buf, &resp_len);
    if (rc == CN_ERR_TIMEOUT) {
        (void)fprintf(stderr,
            "Request timed out — the service may not be running.\n");
        return 1;
    }
    if (rc != CN_OK) {
        (void)fprintf(stderr, "Connection failed: %s (%d).\n",
                      cn_err_str(rc), (int)rc);
        return 1;
    }
    if (resp_type == CN_IPC_MSG_ERROR) {
        print_ipc_error(resp_buf, resp_len);
        return 1;
    }
    if (resp_type != CN_IPC_MSG_STATUS_RESP) {
        (void)fprintf(stderr,
            "Unexpected response (type 0x%04x).\n", (unsigned)resp_type);
        return 1;
    }
    if (resp_len < sizeof(cn_ipc_status_t)) {
        (void)fprintf(stderr, "Malformed status response (truncated).\n");
        return 1;
    }

    cn_ipc_status_t status;
    memcpy(&status, resp_buf, sizeof(status));

    if (status.iface_count == 0) {
        (void)printf("No interfaces configured.\n");
        return 0;
    }

    /* Column widths: interface(20) status(12) packets(14) data(12) */
    (void)printf("%-20s %-12s %14s %12s\n",
                 "Interface", "Status", "Packets", "Data");
    (void)printf("%-20s %-12s %14s %12s\n",
                 "--------------------", "------------",
                 "--------------", "------------");

    for (uint32_t i = 0; i < status.iface_count; i++) {
        const cn_ipc_iface_status_t *s = &status.ifaces[i];
        const char *state = s->capturing ? "capturing" : "stopped";

        char data_buf[32];
        fmt_bytes(s->bytes_written, data_buf, sizeof(data_buf));

        (void)printf("%-20s %-12s %14llu %12s\n",
                     s->iface_name,
                     state,
                     (unsigned long long)s->pkts_written,
                     data_buf);
    }

    (void)printf("\n%u interface(s) configured.\n", status.iface_count);
    return 0;
}

/* start <iface> — request capture start on a named interface. */
static int cmd_start(const char *iface)
{
    size_t len = strlen(iface);
    if (len == 0 || len >= CN_IFACE_NAME_MAX) {
        (void)fprintf(stderr,
            "Error: interface name too long (max %u characters).\n",
            CN_IFACE_NAME_MAX - 1u);
        return 1;
    }

    cn_ipc_msg_type_t resp_type;
    uint8_t  resp_buf[CN_IPC_MSG_MAX];
    uint32_t resp_len = 0;

    cn_err_t rc = ipc_send_recv(CN_IPC_MSG_CAPTURE_START,
                                 iface, (uint32_t)len,
                                 &resp_type, resp_buf, &resp_len);
    if (rc == CN_ERR_TIMEOUT) {
        (void)fprintf(stderr,
            "No response from service (timed out).\n");
        return 1;
    }
    if (rc != CN_OK) {
        (void)fprintf(stderr, "Connection failed: %s (%d).\n",
                      cn_err_str(rc), (int)rc);
        return 1;
    }
    if (resp_type == CN_IPC_MSG_ERROR) {
        print_ipc_error(resp_buf, resp_len);
        return 1;
    }
    if (resp_type != CN_IPC_MSG_CAPTURE_EVENT) {
        (void)fprintf(stderr,
            "Unexpected response (type 0x%04x).\n", (unsigned)resp_type);
        return 1;
    }
    (void)printf("Capture started on %s.\n", iface);
    return 0;
}

/* stop <iface> — request capture stop on a named interface. */
static int cmd_stop(const char *iface)
{
    size_t len = strlen(iface);
    if (len == 0 || len >= CN_IFACE_NAME_MAX) {
        (void)fprintf(stderr,
            "Error: interface name too long (max %u characters).\n",
            CN_IFACE_NAME_MAX - 1u);
        return 1;
    }

    cn_ipc_msg_type_t resp_type;
    uint8_t  resp_buf[CN_IPC_MSG_MAX];
    uint32_t resp_len = 0;

    cn_err_t rc = ipc_send_recv(CN_IPC_MSG_CAPTURE_STOP,
                                 iface, (uint32_t)len,
                                 &resp_type, resp_buf, &resp_len);
    if (rc == CN_ERR_TIMEOUT) {
        (void)fprintf(stderr,
            "No response from service (timed out).\n");
        return 1;
    }
    if (rc != CN_OK) {
        (void)fprintf(stderr, "Connection failed: %s (%d).\n",
                      cn_err_str(rc), (int)rc);
        return 1;
    }
    if (resp_type == CN_IPC_MSG_ERROR) {
        print_ipc_error(resp_buf, resp_len);
        return 1;
    }
    if (resp_type != CN_IPC_MSG_CAPTURE_EVENT) {
        (void)fprintf(stderr,
            "Unexpected response (type 0x%04x).\n", (unsigned)resp_type);
        return 1;
    }
    (void)printf("Capture stopped on %s.\n", iface);
    return 0;
}

/*
 * reload — ask the service to exit cleanly so the OS service manager
 * restarts it with the current configuration file.
 * No response is expected: the service exits immediately on receipt.
 */
static int cmd_reload(void)
{
    cn_err_t rc = ipc_send_only(CN_IPC_MSG_CONFIG_RELOAD, NULL, 0);
    if (rc != CN_OK) {
        (void)fprintf(stderr, "Failed to send reload request: %s (%d).\n",
                      cn_err_str(rc), (int)rc);
        return 1;
    }
    (void)printf(
        "Reload requested. The service will restart with the current "
        "configuration.\n");
    return 0;
}

/* config check — load and validate the configuration file. */
static int cmd_config_check(void)
{
    cn_config_t config;
    cn_err_t rc = cn_parser_load(&config, g_config_path);
    if (rc != CN_OK) {
        (void)fprintf(stderr,
            "Error: failed to load configuration file '%s': %s (%d).\n",
            g_config_path, cn_err_str(rc), (int)rc);
        return 1;
    }

    (void)cn_parser_warn_stray_upload_keys(g_config_path, stderr);

    rc = cn_validator_check(&config);
    if (rc != CN_OK) {
        (void)fprintf(stderr,
            "Validation failed: %s (%d).\n", cn_err_str(rc), (int)rc);
        return 1;
    }

    (void)printf("OK\n");
    return 0;
}

/*
 * Extract the capture interface name from a savefile basename.
 * Filename format: netcap_<iface>_YYYY_MM_DD_HH_mm_SS.pcap
 * The timestamp suffix is always 25 characters: _YYYY_MM_DD_HH_mm_SS.pcap
 * Falls back to "unknown" when the name does not match the expected pattern.
 * Preconditions: filename != NULL, buf != NULL, buf_size > 0.
 */
static void extract_iface(const char *filename, char *buf, size_t buf_size)
{
    static const char PREFIX[]   = "netcap_";
    static const size_t PFX_LEN  = 7u;  /* strlen("netcap_") */
    static const size_t TS_LEN   = 25u; /* "_YYYY_MM_DD_HH_mm_SS.pcap" */

    /* Strip directory component. */
    const char *base = strrchr(filename, '/');
    if (base != NULL) {
        base++;
    } else {
        base = filename;
    }

    if (strncmp(base, PREFIX, PFX_LEN) != 0) {
        goto fallback;
    }

    size_t total = strlen(base + PFX_LEN);
    if (total <= TS_LEN) {
        goto fallback;
    }

    size_t iface_len = total - TS_LEN;
    if (iface_len >= buf_size) {
        iface_len = buf_size - 1u;
    }
    memcpy(buf, base + PFX_LEN, iface_len);
    buf[iface_len] = '\0';
    return;

fallback:
    strncpy(buf, "unknown", buf_size - 1u);
    buf[buf_size - 1u] = '\0';
}

/* upload <file> — upload a savefile using the configuration in g_config_path. */
static int cmd_upload(const char *file_path)
{
    cn_config_t config;
    cn_err_t rc = cn_parser_load(&config, g_config_path);
    if (rc != CN_OK) {
        (void)fprintf(stderr,
            "Error: failed to load configuration file '%s': %s (%d).\n",
            g_config_path, cn_err_str(rc), (int)rc);
        return 1;
    }

    if (!cn_upload_is_enabled(&config.upload)) {
        (void)cn_parser_warn_stray_upload_keys(g_config_path, stderr);
        (void)fprintf(stderr,
            "Error: upload is not configured. Set endpoint_url and "
            "auth_token in the [upload] section of %s.\n", g_config_path);
        return 1;
    }

    char iface_name[CN_IFACE_NAME_MAX];
    extract_iface(file_path, iface_name, sizeof(iface_name));

    (void)printf("Uploading %s ...\n", file_path);
    (void)fflush(stdout);

    rc = cn_upload_file(file_path, iface_name, config.device, &config.upload);
    if (rc != CN_OK) {
        if (rc == CN_ERR_IO && access(file_path, F_OK) != 0) {
            (void)fprintf(stderr,
                "Upload failed: file not found: %s\n", file_path);
        } else {
            (void)fprintf(stderr,
                "Upload failed: %s (%d).\n", cn_err_str(rc), (int)rc);
        }
        return 1;
    }

    (void)printf("Upload complete.\n");
    return 0;
}

/* =========================================================================
 * Usage
 * ====================================================================== */

static void print_usage(const char *prog)
{
    (void)fprintf(stderr,
        "Usage: %s [--config <path>] <command> [arguments]\n"
        "\n"
        "IPC commands (require the service to be running):\n"
        "  ping              Verify the service is alive.\n"
        "  status            Print per-interface capture statistics.\n"
        "  start <iface>     Start capture on a network interface.\n"
        "  stop  <iface>     Stop capture on a network interface.\n"
        "  reload            Restart the service with the current config.\n"
        "\n"
        "Local commands:\n"
        "  config check      Validate the configuration file.\n"
        "  upload <file>     Upload a savefile to the configured endpoint.\n"
        "\n"
        "Options:\n"
        "  --config <path>   Path to the TOML configuration file.\n"
        "                    Default: %s\n",
        prog, CN_DEFAULT_CONFIG_PATH);
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(int argc, char *argv[])
{
    cn_log_init(CN_LOG_LEVEL_WARN);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    int arg = 1;

    /* Parse optional global --config flag. */
    if (strcmp(argv[arg], "--config") == 0) {
        if (arg + 1 >= argc) {
            (void)fprintf(stderr,
                "Error: --config requires a path argument.\n");
            return 1;
        }
        g_config_path = argv[arg + 1];
        arg += 2;
    }

    if (arg >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[arg];
    arg++;

    if (strcmp(cmd, "ping") == 0) {
        return cmd_ping();
    }

    if (strcmp(cmd, "status") == 0) {
        return cmd_status();
    }

    if (strcmp(cmd, "start") == 0) {
        if (arg >= argc) {
            (void)fprintf(stderr,
                "Error: 'start' requires an interface name.\n");
            return 1;
        }
        return cmd_start(argv[arg]);
    }

    if (strcmp(cmd, "stop") == 0) {
        if (arg >= argc) {
            (void)fprintf(stderr,
                "Error: 'stop' requires an interface name.\n");
            return 1;
        }
        return cmd_stop(argv[arg]);
    }

    if (strcmp(cmd, "reload") == 0) {
        return cmd_reload();
    }

    if (strcmp(cmd, "config") == 0) {
        if (arg >= argc || strcmp(argv[arg], "check") != 0) {
            (void)fprintf(stderr,
                "Error: unknown config subcommand. "
                "Available: config check\n");
            return 1;
        }
        return cmd_config_check();
    }

    if (strcmp(cmd, "upload") == 0) {
        if (arg >= argc) {
            (void)fprintf(stderr,
                "Error: 'upload' requires a file path.\n");
            return 1;
        }
        return cmd_upload(argv[arg]);
    }

    (void)fprintf(stderr, "Error: unknown command '%s'.\n", cmd);
    print_usage(argv[0]);
    return 1;
}
