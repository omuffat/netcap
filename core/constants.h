#ifndef CN_CONSTANTS_H
#define CN_CONSTANTS_H

#include <stddef.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Error codes — returned by every cn_* function.
 * Always use these named constants; never use raw integers.
 * ---------------------------------------------------------------------- */

typedef enum {
    CN_OK           =  0,  /* Success. */
    CN_ERR_INVAL    = -1,  /* Invalid or NULL parameter. */
    CN_ERR_IO       = -2,  /* Input/output error. */
    CN_ERR_NOMEM    = -3,  /* Memory allocation failed. */
    CN_ERR_OVERFLOW = -4,  /* Value exceeds the associated CN_*_MAX limit. */
    CN_ERR_PERM     = -5,  /* Permission denied. */
    CN_ERR_NET      = -6,  /* Network or TLS error. */
    CN_ERR_TIMEOUT  = -7,  /* Operation timed out. */
} cn_err_t;

/* -------------------------------------------------------------------------
 * Ring buffer limits
 * ---------------------------------------------------------------------- */

/** Minimum ring buffer size (one 4 KiB page). */
#define CN_RING_SIZE_MIN    (4096u)

/** Maximum ring buffer size (256 MiB). Must be a multiple of the page size. */
#define CN_RING_SIZE_MAX    (256u * 1024u * 1024u)

/* -------------------------------------------------------------------------
 * Packet limits
 * ---------------------------------------------------------------------- */

/** Maximum number of bytes captured per packet. Matches the Ethernet MTU
 *  upper bound used by pcap (also the maximum caplen in a pcap record). */
#define CN_PKT_SIZE_MAX     (65535u)

/**
 * Maximum size of a single record written to the ring buffer.
 * Each record is prefixed with 12 bytes of pcap metadata (ts_sec 4,
 * ts_usec 4, orig_len 4) followed by up to CN_PKT_SIZE_MAX bytes of
 * captured packet data.  See capture.c for the record layout.
 */
#define CN_RING_RECORD_MAX  (12u + CN_PKT_SIZE_MAX)

/* -------------------------------------------------------------------------
 * Interface limits
 * ---------------------------------------------------------------------- */

/** Maximum number of network interfaces captured simultaneously. */
#define CN_IFACE_COUNT_MAX  (16u)

/** Maximum length of a network interface name, including the NUL terminator. */
#define CN_IFACE_NAME_MAX   (64u)

/* -------------------------------------------------------------------------
 * Upload limits
 * ---------------------------------------------------------------------- */

/** Maximum number of upload worker threads in the shared pool. */
#define CN_UPLOAD_WORKERS_MAX (8u)

/** Maximum size of a single upload chunk (8 MiB). */
#define CN_CHUNK_SIZE_MAX   (8u * 1024u * 1024u)

/* -------------------------------------------------------------------------
 * String / path limits
 * ---------------------------------------------------------------------- */

/** Maximum file path length, including the NUL terminator. */
#define CN_PATH_MAX         (4096u)

/** Maximum URL length, including the NUL terminator. */
#define CN_URL_MAX          (2048u)

/** Maximum BPF filter expression length, including the NUL terminator. */
#define CN_BPF_FILTER_MAX   (512u)

/** Maximum authentication token length, including the NUL terminator. */
#define CN_AUTH_TOKEN_MAX   (512u)

/** Maximum IPC message payload size in bytes. */
#define CN_IPC_MSG_MAX      (4096u)

/** Maximum log message length, including the NUL terminator. */
#define CN_LOG_MSG_MAX      (1024u)

/** Maximum device (host) name length, including the NUL terminator.
 *  Matches POSIX HOST_NAME_MAX + 1 (255 + 1). */
#define CN_HOST_NAME_MAX    (256u)

/* -------------------------------------------------------------------------
 * Savefile rotation limits
 * ---------------------------------------------------------------------- */

/** Minimum savefile rotation period in seconds (1 minute). */
#define CN_SAVEFILE_ROTATION_SECS_MIN  (60u)

/** Maximum savefile rotation period in seconds (24 hours). */
#define CN_SAVEFILE_ROTATION_SECS_MAX  (86400u)

/** Minimum number of savefiles kept per interface. */
#define CN_SAVEFILE_MAX_COUNT_MIN      (1u)

/** Maximum number of savefiles kept per interface. */
#define CN_SAVEFILE_MAX_COUNT_MAX      (1000u)

/** Maximum length of the savefile filename prefix, including NUL terminator. */
#define CN_SAVEFILE_PREFIX_MAX         (64u)

/* -------------------------------------------------------------------------
 * Error code to human-readable string.
 * ---------------------------------------------------------------------- */

/**
 * @brief Return a short human-readable description of a cn_err_t value.
 *
 * The returned pointer is a string literal; do not free it.
 *
 * @param[in] err  Error code to describe.
 * @return Pointer to a NUL-terminated description string.
 */
static inline const char *cn_err_str(cn_err_t err)
{
    switch (err) {
    case CN_OK:           return "success";
    case CN_ERR_INVAL:    return "invalid argument";
    case CN_ERR_IO:       return "I/O error";
    case CN_ERR_NOMEM:    return "out of memory";
    case CN_ERR_OVERFLOW: return "value overflow";
    case CN_ERR_PERM:     return "permission denied";
    case CN_ERR_NET:      return "network error";
    case CN_ERR_TIMEOUT:  return "operation timed out";
    default:              return "unknown error";
    }
}

#endif /* CN_CONSTANTS_H */
