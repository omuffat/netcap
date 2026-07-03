#ifndef CN_LOG_H
#define CN_LOG_H

/*
 * Lightweight logging for the netcap service daemon.
 *
 * Output destinations:
 *   - stderr (always) — captured by systemd/journald, launchd, and the
 *     Windows SCM when StandardError is configured, or printed directly
 *     in interactive / debug mode.
 *   - syslog (POSIX only, when CN_LOG_USE_SYSLOG is defined at build time).
 *   - OutputDebugStringA (Windows only) — visible in debuggers and
 *     DebugView without requiring a console.
 *
 * All functions are thread-safe.
 */

/* Log level values match the config log_level field. */
typedef enum {
    CN_LOG_LEVEL_ERROR = 0, /* Fatal and unrecoverable conditions.       */
    CN_LOG_LEVEL_WARN  = 1, /* Recoverable anomalies; default for prod.  */
    CN_LOG_LEVEL_INFO  = 2, /* Service lifecycle events.                 */
    CN_LOG_LEVEL_DEBUG = 3, /* Verbose; do not use in production.        */
} cn_log_level_t;

/**
 * @brief Initialize the logging subsystem.
 *
 * Must be called once before any CN_LOG_* macro.  Safe to call before the
 * config is loaded; in that case pass CN_LOG_LEVEL_ERROR so that only fatal
 * messages are emitted during early startup.  Call again after the config is
 * loaded to apply the configured log_level.
 *
 * On POSIX with syslog enabled, this opens the syslog connection with
 * LOG_DAEMON facility and LOG_PID | LOG_NDELAY options.
 *
 * @param[in] max_level  Highest severity level that will be emitted.
 */
void cn_log_init(cn_log_level_t max_level);

/**
 * @brief Emit a log message at the given severity level.
 *
 * Silently drops messages whose level exceeds the current max_level.
 * Thread-safe: the formatted line is written atomically to stderr.
 *
 * Output format: [YYYY-MM-DD HH:MM:SS] LEVEL netcapd: <message>
 *
 * @param[in] level  Severity of this message.
 * @param[in] fmt    printf-style format string.  Must not be NULL.
 */
#ifdef _MSC_VER
void cn_log(cn_log_level_t level, const char *fmt, ...);
#else
void cn_log(cn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
#endif

/**
 * @brief Tear down the logging subsystem.
 *
 * On POSIX with syslog enabled, closes the syslog connection.
 * Safe to call multiple times.
 */
void cn_log_destroy(void);

/* Convenience macros — preferred over calling cn_log() directly. */
#define CN_LOG_ERROR(...) cn_log(CN_LOG_LEVEL_ERROR, __VA_ARGS__)
#define CN_LOG_WARN(...)  cn_log(CN_LOG_LEVEL_WARN,  __VA_ARGS__)
#define CN_LOG_INFO(...)  cn_log(CN_LOG_LEVEL_INFO,  __VA_ARGS__)
#define CN_LOG_DEBUG(...) cn_log(CN_LOG_LEVEL_DEBUG, __VA_ARGS__)

/*
 * CN_LOG_OS_ERR — human-readable string describing the most recent OS error.
 *
 * Use this as a "%s" argument to CN_LOG_* immediately after a failing system
 * call, before any other call that might reset errno or GetLastError().
 *
 * POSIX:   strerror(errno)  — thread-safe on glibc and macOS.
 * Windows: FormatMessage(GetLastError()) in a thread-local buffer, with the
 *          numeric code appended in parentheses for easy MSDN look-up.
 */
#ifndef _WIN32
#  include <errno.h>
#  include <string.h>
#  define CN_LOG_OS_ERR  strerror(errno)
#else
   /* Implemented in log.c — returns a pointer to a thread-local buffer. */
   const char *cn_log_win_strerror(void);
#  define CN_LOG_OS_ERR  cn_log_win_strerror()
#endif

#endif /* CN_LOG_H */
