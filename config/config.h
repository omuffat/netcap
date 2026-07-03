#ifndef CN_CONFIG_H
#define CN_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include "../core/constants.h"

/* =========================================================================
 * Default values
 *
 * Every optional TOML field has a corresponding CN_DEFAULT_* macro.
 * The parser uses these when a key is absent from the file.
 * Required fields (endpoint_url, auth_token, interface name) have no
 * default — the service operates without them rather than hard-coding
 * sensitive or deployment-specific values.
 *
 * Path defaults are split between development and production builds.
 * Define CN_DEV_BUILD (via CMake -DCMAKE_BUILD_TYPE=Debug) to get
 * repository-relative paths suitable for local development and testing.
 * ====================================================================== */

/* -------------------------------------------------------------------------
 * Per-interface defaults
 * ---------------------------------------------------------------------- */

/** Default ring buffer size per interface: 64 MiB. */
#define CN_DEFAULT_RING_SIZE            (64u * 1024u * 1024u)

/** Default capture snaplen: full packet (no truncation). */
#define CN_DEFAULT_SNAPLEN              ((int)CN_PKT_SIZE_MAX)

/** Default BPF filter expression: capture everything. */
#define CN_DEFAULT_BPF_FILTER           ""

/** Default interface enabled state when the TOML key is absent. */
#define CN_DEFAULT_IFACE_ENABLED        true

/* -------------------------------------------------------------------------
 * Upload defaults (all optional — upload is disabled when endpoint_url
 * or auth_token is absent)
 * ---------------------------------------------------------------------- */

/** Default upload chunk size: 1 MiB. */
#define CN_DEFAULT_CHUNK_SIZE           (1u * 1024u * 1024u)

/**
 * Default for upload.compress.
 * false = savefiles are uploaded as-is (no compression).
 * true  = savefiles are gzip-compressed in a single stream before upload;
 *         Content-Encoding: gzip is set on the request.
 */
#define CN_DEFAULT_COMPRESS             false

/** Default maximum upload retry attempts on transient failure. */
#define CN_DEFAULT_RETRY_MAX            (3u)

/** Default initial retry backoff in milliseconds. */
#define CN_DEFAULT_RETRY_DELAY_MS       (1000u)

/** Default upload worker thread count. */
#define CN_DEFAULT_WORKER_COUNT         (2u)

/**
 * Default for capture_upload_traffic.
 * false = traffic destined for the upload endpoint is excluded from capture.
 * The user must explicitly set this to true to capture upload traffic.
 */
#define CN_DEFAULT_CAPTURE_UPLOAD_TRAFFIC  false

/**
 * Default for upload.auto.
 * false = automatic upload disabled; the operator uses netcap-ctl upload.
 * true  = completed savefiles are enqueued for upload automatically on rotation.
 */
#define CN_DEFAULT_AUTO_UPLOAD  false

/* -------------------------------------------------------------------------
 * Savefile rotation defaults
 * ---------------------------------------------------------------------- */

/** Default savefile rotation period: 3 minutes. */
#define CN_DEFAULT_SAVEFILE_ROTATION_SECS  (180u)

/** Default maximum number of savefiles retained per interface. */
#define CN_DEFAULT_SAVEFILE_MAX_COUNT      (10u)

/* -------------------------------------------------------------------------
 * Service defaults
 * ---------------------------------------------------------------------- */

/** Default log verbosity level: 1 = WARN. */
#define CN_DEFAULT_LOG_LEVEL            (1u)

/**
 * Default device name used in upload headers.
 * An empty string instructs the parser to call gethostname() at load time.
 */
#define CN_DEFAULT_DEVICE               ""

/* -------------------------------------------------------------------------
 * Platform-specific path defaults
 *
 * CN_DEV_BUILD is defined by CMake when CMAKE_BUILD_TYPE=Debug.
 * All paths are relative to the repository root in that mode.
 * ---------------------------------------------------------------------- */

#ifdef CN_DEV_BUILD

/*
 * Development paths — all relative to the repository root.
 * The service binary must be run from the root of the repository,
 * or an explicit --config path must be provided.
 */
#  define CN_DEFAULT_CONFIG_DIR         "."
#  define CN_DEFAULT_CONFIG_PATH        "./netcap.toml"
#  define CN_DEFAULT_RING_DIR           "./rings"
#  define CN_DEFAULT_SAVEFILE_DIR       "./captures"

#  ifdef _WIN32
#    define CN_DEFAULT_IPC_SOCKET_PATH  "\\\\.\\pipe\\netcap"
#  else
#    define CN_DEFAULT_IPC_SOCKET_PATH  "/tmp/netcap.sock"
#  endif

#else /* production */

#  ifdef _WIN32
/*
 * Windows production paths.
 * ProgramData  — machine-wide config and data, survives user switches.
 * Program Files — install directory for the service binary itself.
 * The installer creates these directories and writes the initial config.
 */
#    define CN_DEFAULT_CONFIG_DIR       "C:\\ProgramData\\netcap"
#    define CN_DEFAULT_CONFIG_PATH      "C:\\ProgramData\\netcap\\netcap.toml"
#    define CN_DEFAULT_RING_DIR         "C:\\ProgramData\\netcap\\rings"
#    define CN_DEFAULT_SAVEFILE_DIR     "C:\\Program Files\\netcap\\data\\captures"
#    define CN_DEFAULT_IPC_SOCKET_PATH  "\\\\.\\pipe\\netcap"

#  elif defined(__APPLE__)
/*
 * macOS production paths.
 * /etc on macOS resolves to /private/etc (valid for system daemon config).
 * Using /etc/netcap keeps the layout identical to Linux, simplifying
 * cross-platform documentation and support scripts.
 */
#    define CN_DEFAULT_CONFIG_DIR       "/etc/netcap"
#    define CN_DEFAULT_CONFIG_PATH      "/etc/netcap/netcap.toml"
#    define CN_DEFAULT_RING_DIR         "/Library/Application Support/netcap/rings"
#    define CN_DEFAULT_SAVEFILE_DIR     "/Library/Application Support/netcap/captures"
#    define CN_DEFAULT_IPC_SOCKET_PATH  "/var/run/netcap/netcap.sock"

#  else /* Linux and other POSIX */
#    define CN_DEFAULT_CONFIG_DIR       "/etc/netcap"
#    define CN_DEFAULT_CONFIG_PATH      "/etc/netcap/netcap.toml"
#    define CN_DEFAULT_RING_DIR         "/var/lib/netcap/rings"
#    define CN_DEFAULT_SAVEFILE_DIR     "/usr/share/netcap/captures"
#    define CN_DEFAULT_IPC_SOCKET_PATH  "/run/netcap/netcap.sock"
#  endif

#endif /* CN_DEV_BUILD */

/* =========================================================================
 * Configuration structures
 * ====================================================================== */

/* -------------------------------------------------------------------------
 * Per-interface configuration
 * ---------------------------------------------------------------------- */

typedef struct {
    char     name[CN_IFACE_NAME_MAX];       /* Interface name, e.g. "eth0".
                                               Required — no default. */
    char     bpf_filter[CN_BPF_FILTER_MAX]; /* BPF filter expression.
                                               Default: CN_DEFAULT_BPF_FILTER (""). */
    uint32_t ring_size;                     /* Ring buffer size in bytes.
                                               Must be a power-of-two multiple of
                                               the system page size.
                                               Default: CN_DEFAULT_RING_SIZE. */
    int      snaplen;                       /* Maximum bytes captured per packet.
                                               Default: CN_DEFAULT_SNAPLEN. */
    bool     enabled;                       /* false = configured but not started.
                                               Default: CN_DEFAULT_IFACE_ENABLED. */
    uint8_t  _pad[3];                       /* Explicit padding. */
} cn_iface_config_t;

/* -------------------------------------------------------------------------
 * TLS configuration (used by the uploader)
 * ---------------------------------------------------------------------- */

typedef struct {
    char ca_cert_path[CN_PATH_MAX];     /* CA certificate bundle path.
                                           Default: "" = use system bundle. */
    char client_cert_path[CN_PATH_MAX]; /* Client certificate for mTLS.
                                           Default: "" = mTLS disabled. */
    char client_key_path[CN_PATH_MAX];  /* Client private key for mTLS.
                                           Default: "" = mTLS disabled. */
} cn_tls_config_t;

/* -------------------------------------------------------------------------
 * Upload configuration
 *
 * Upload is enabled only when BOTH endpoint_url and auth_token are
 * non-empty.  All other fields have defaults and are optional.
 * Use cn_upload_is_enabled() to test at runtime.
 * ---------------------------------------------------------------------- */

typedef struct {
    char     endpoint_url[CN_URL_MAX];      /* HTTPS upload endpoint.
                                               Optional — empty = upload disabled. */
    char     auth_token[CN_AUTH_TOKEN_MAX]; /* Bearer token for Authorization header.
                                               Optional — empty = upload disabled. */
    uint32_t chunk_size;                    /* Upload chunk size in bytes.
                                               Default: CN_DEFAULT_CHUNK_SIZE. */
    uint32_t retry_max;                     /* Max retry attempts on failure.
                                               Default: CN_DEFAULT_RETRY_MAX. */
    uint32_t retry_delay_ms;               /* Initial backoff in milliseconds.
                                               Default: CN_DEFAULT_RETRY_DELAY_MS. */
    uint32_t worker_count;                  /* Upload worker thread count.
                                               Default: CN_DEFAULT_WORKER_COUNT. */
    bool     capture_upload_traffic;        /* If false (default), traffic to
                                               endpoint_url is excluded from capture
                                               via an auto-injected BPF exclusion.
                                               Default: CN_DEFAULT_CAPTURE_UPLOAD_TRAFFIC. */
    bool     compress;                      /* If true, savefiles are gzip-compressed in a
                                               single stream before upload; Content-Encoding:
                                               gzip is set on the request. Savefiles on disk
                                               are never compressed.
                                               Default: CN_DEFAULT_COMPRESS. */
    bool     auto_upload;                   /* If true, each fully-rotated savefile is pushed
                                               to the upload queue automatically. Upload must
                                               also be enabled (endpoint_url + auth_token).
                                               Default: CN_DEFAULT_AUTO_UPLOAD. */
    uint8_t  _pad[1];                       /* Explicit padding. */
    cn_tls_config_t tls;                    /* TLS settings for upload requests. */
} cn_upload_config_t;

/* -------------------------------------------------------------------------
 * Top-level configuration
 * ---------------------------------------------------------------------- */

/** Complete service configuration loaded from the TOML file. */
typedef struct {
    cn_iface_config_t  interfaces[CN_IFACE_COUNT_MAX]; /* Per-interface settings.
                                                          iface_count == 0 is valid
                                                          (service runs, no capture). */
    uint32_t           iface_count;                    /* Number of valid entries. */
    cn_upload_config_t upload;                         /* Upload settings (optional). */
    char               ring_dir[CN_PATH_MAX];          /* Ring file directory.
                                                          Default: CN_DEFAULT_RING_DIR. */
    char               savefile_dir[CN_PATH_MAX];      /* Capture save directory.
                                                          Default: CN_DEFAULT_SAVEFILE_DIR. */
    char               device[CN_HOST_NAME_MAX];       /* Short hostname sent as X-Netcap-Device
                                                          in upload requests. Optional in TOML:
                                                          if absent, set from gethostname() at
                                                          load time. Never empty after a
                                                          successful cn_parser_load(). */
    uint32_t           savefile_rotation_secs;         /* Rotation period in seconds.
                                                          Default: CN_DEFAULT_SAVEFILE_ROTATION_SECS. */
    uint32_t           savefile_max_count;             /* Max savefiles per interface.
                                                          Default: CN_DEFAULT_SAVEFILE_MAX_COUNT. */
    uint32_t           log_level;                      /* 0=ERROR 1=WARN 2=INFO 3=DEBUG.
                                                          Default: CN_DEFAULT_LOG_LEVEL. */
    uint8_t            _pad[4];                        /* Explicit padding. */
} cn_config_t;

/* =========================================================================
 * Inline helpers
 * ====================================================================== */

/**
 * @brief Return true if upload is fully configured and enabled.
 *
 * Upload is enabled only when both endpoint_url and auth_token are
 * non-empty strings.  Either field being absent disables upload entirely.
 *
 * @param[in] up  Upload configuration. Must not be NULL.
 */
static inline bool cn_upload_is_enabled(const cn_upload_config_t *up)
{
    return up != NULL
        && up->endpoint_url[0] != '\0'
        && up->auth_token[0]   != '\0';
}

#endif /* CN_CONFIG_H */
