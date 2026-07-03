#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#  include <pthread.h>
#  ifdef CN_LOG_USE_SYSLOG
#    include <syslog.h>
#  endif
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* =========================================================================
 * Module state
 * ====================================================================== */

static cn_log_level_t g_max_level = CN_LOG_LEVEL_ERROR;

#ifndef _WIN32
/* Protects the stderr write + syslog call sequence. */
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
static CRITICAL_SECTION g_cs;
static int              g_cs_init = 0;

/*
 * cn_log_win_strerror: return a human-readable description of the last
 * Windows error (GetLastError()), with the numeric code appended.
 * Uses a thread-local buffer so concurrent callers cannot overwrite each
 * other's message before it is consumed by cn_log().
 */
#if defined(_MSC_VER)
static __declspec(thread) char _win_errbuf[512];
#else
static _Thread_local char _win_errbuf[512];
#endif

const char *cn_log_win_strerror(void)
{
    DWORD code = GetLastError();
    char  msg[400];
    msg[0] = '\0';

    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        msg, (DWORD)sizeof(msg), NULL);

    /* Strip trailing whitespace (FormatMessage appends \r\n). */
    while (n > 0 && (msg[n - 1] == '\n' || msg[n - 1] == '\r'
                     || msg[n - 1] == ' ')) {
        msg[--n] = '\0';
    }

    if (n == 0) {
        snprintf(_win_errbuf, sizeof(_win_errbuf),
                 "unknown error (%lu)", (unsigned long)code);
    } else {
        snprintf(_win_errbuf, sizeof(_win_errbuf),
                 "%s (%lu)", msg, (unsigned long)code);
    }

    return _win_errbuf;
}
#endif /* _WIN32 */

/* =========================================================================
 * Internal helpers
 * ====================================================================== */

/* Return the fixed-width level tag for the given level. */
static const char *level_tag(cn_log_level_t level)
{
    switch (level) {
    case CN_LOG_LEVEL_ERROR: return "ERROR";
    case CN_LOG_LEVEL_WARN:  return "WARN ";
    case CN_LOG_LEVEL_INFO:  return "INFO ";
    case CN_LOG_LEVEL_DEBUG: return "DEBUG";
    default:                 return "?????";
    }
}

#ifdef CN_LOG_USE_SYSLOG
/* Map cn_log_level_t to a syslog priority. */
static int level_to_syslog_prio(cn_log_level_t level)
{
    switch (level) {
    case CN_LOG_LEVEL_ERROR: return LOG_ERR;
    case CN_LOG_LEVEL_WARN:  return LOG_WARNING;
    case CN_LOG_LEVEL_INFO:  return LOG_INFO;
    case CN_LOG_LEVEL_DEBUG: return LOG_DEBUG;
    default:                 return LOG_INFO;
    }
}
#endif /* CN_LOG_USE_SYSLOG */

/* =========================================================================
 * Public API
 * ====================================================================== */

void cn_log_init(cn_log_level_t max_level)
{
    g_max_level = max_level;

#ifdef _WIN32
    if (!g_cs_init) {
        InitializeCriticalSection(&g_cs);
        g_cs_init = 1;
    }
#endif

#ifdef CN_LOG_USE_SYSLOG
    /* LOG_PID embeds the process id in every message.
     * LOG_NDELAY opens the connection immediately (avoids late-init races).
     * LOG_DAEMON is the conventional facility for background services. */
    openlog("netcapd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
}

void cn_log(cn_log_level_t level, const char *fmt, ...)
{
    if (level > g_max_level) {
        return;
    }

    /* Format the caller's message. */
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Build the timestamp string. */
    time_t now = time(NULL);
    char ts[20]; /* "YYYY-MM-DD HH:MM:SS\0" */
    {
        struct tm tm_buf;
#ifndef _WIN32
        localtime_r(&now, &tm_buf);
#else
        localtime_s(&tm_buf, &now);
#endif
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);
    }

    /* Write the full line atomically. */
#ifndef _WIN32
    pthread_mutex_lock(&g_mutex);
    fprintf(stderr, "[%s] %s netcapd: %s\n", ts, level_tag(level), msg);
    fflush(stderr);
    pthread_mutex_unlock(&g_mutex);

#  ifdef CN_LOG_USE_SYSLOG
    syslog(level_to_syslog_prio(level), "%s", msg);
#  endif

#else /* _WIN32 */
    char line[1200];
    snprintf(line, sizeof(line), "[%s] %s netcapd: %s\n",
             ts, level_tag(level), msg);

    if (g_cs_init) {
        EnterCriticalSection(&g_cs);
    }
    fprintf(stderr, "%s", line);
    fflush(stderr);
    if (g_cs_init) {
        LeaveCriticalSection(&g_cs);
    }

    /* Also route to the debugger / DebugView on Windows. */
    OutputDebugStringA(line);
#endif /* _WIN32 */
}

void cn_log_destroy(void)
{
#ifdef CN_LOG_USE_SYSLOG
    closelog();
#endif

#ifdef _WIN32
    if (g_cs_init) {
        DeleteCriticalSection(&g_cs);
        g_cs_init = 0;
    }
#endif
}
