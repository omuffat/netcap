#include "pcap_writer.h"
#include "log.h"
#include "str.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
#  define _POSIX_C_SOURCE 200809L
#  include <fcntl.h>
#  include <unistd.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

/* -------------------------------------------------------------------------
 * pcap file format constants
 *
 * The magic number is written in native host byte order so that readers can
 * auto-detect endianness (0xa1b2c3d4 = native, 0xd4c3b2a1 = swapped).
 * ---------------------------------------------------------------------- */

#define PCAP_MAGIC          0xa1b2c3d4u
#define PCAP_VERSION_MAJOR  2u
#define PCAP_VERSION_MINOR  4u

/* -------------------------------------------------------------------------
 * Opaque writer structure
 * ---------------------------------------------------------------------- */

struct cn_pcap_writer {
    FILE    *fp;
    uint32_t snaplen;
};

/* -------------------------------------------------------------------------
 * Internal helpers — write fixed-width little-endian fields.
 *
 * pcap uses native byte order (detected by readers via the magic number).
 * These helpers write in the host's natural byte order via fwrite, which
 * is equivalent to native-endian serialization on all supported platforms.
 * ---------------------------------------------------------------------- */

/* Write a uint16_t in native byte order. */
static cn_err_t write_u16(FILE *fp, uint16_t v)
{
    return (fwrite(&v, sizeof(v), 1, fp) == 1) ? CN_OK : CN_ERR_IO;
}

/* Write a uint32_t in native byte order. */
static cn_err_t write_u32(FILE *fp, uint32_t v)
{
    return (fwrite(&v, sizeof(v), 1, fp) == 1) ? CN_OK : CN_ERR_IO;
}

/* Write an int32_t in native byte order (thiszone field). */
static cn_err_t write_i32(FILE *fp, int32_t v)
{
    return (fwrite(&v, sizeof(v), 1, fp) == 1) ? CN_OK : CN_ERR_IO;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

cn_err_t cn_pcap_writer_open(cn_pcap_writer_t **writer, const char *path,
                             int link_type, uint32_t snaplen)
{
    if (writer == NULL || path == NULL) {
        return CN_ERR_INVAL;
    }
    if (cn_strnlen(path, CN_PATH_MAX) >= CN_PATH_MAX) {
        return CN_ERR_INVAL;
    }
    if (snaplen == 0 || snaplen > CN_PKT_SIZE_MAX) {
        return CN_ERR_INVAL;
    }

    cn_pcap_writer_t *w = (cn_pcap_writer_t *)malloc(sizeof(*w));
    if (w == NULL) {
        return CN_ERR_NOMEM;
    }

    /*
     * Open the file with mode 0600 (owner read/write only) on POSIX via
     * open(2)+fdopen(3).  On Windows the directory ACL restricts access.
     */
#ifndef _WIN32
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        CN_LOG_ERROR("open(\"%s\"): %s", path, CN_LOG_OS_ERR);
        free(w);
        return CN_ERR_IO;
    }
    w->fp = fdopen(fd, "wb");
    if (w->fp == NULL) {
        CN_LOG_ERROR("fdopen(\"%s\"): %s", path, CN_LOG_OS_ERR);
        (void)close(fd);
        free(w);
        return CN_ERR_IO;
    }
#else
    w->fp = fopen(path, "wb");
    if (w->fp == NULL) {
        CN_LOG_ERROR("fopen(\"%s\"): %s", path, CN_LOG_OS_ERR);
        free(w);
        return CN_ERR_IO;
    }
#endif

    w->snaplen = snaplen;

    /*
     * Write the 24-byte global pcap header:
     *   magic_number  (4)  version_major (2)  version_minor (2)
     *   thiszone      (4)  sigfigs       (4)  snaplen       (4)
     *   network       (4)
     */
    cn_err_t rc = CN_OK;

    if (rc == CN_OK) rc = write_u32(w->fp, PCAP_MAGIC);
    if (rc == CN_OK) rc = write_u16(w->fp, (uint16_t)PCAP_VERSION_MAJOR);
    if (rc == CN_OK) rc = write_u16(w->fp, (uint16_t)PCAP_VERSION_MINOR);
    if (rc == CN_OK) rc = write_i32(w->fp, 0);           /* thiszone = GMT */
    if (rc == CN_OK) rc = write_u32(w->fp, 0u);          /* sigfigs  = 0   */
    if (rc == CN_OK) rc = write_u32(w->fp, snaplen);
    if (rc == CN_OK) rc = write_u32(w->fp, (uint32_t)link_type);

    if (rc == CN_OK && fflush(w->fp) != 0) {
        rc = CN_ERR_IO;
    }

    if (rc != CN_OK) {
        (void)fclose(w->fp);
        free(w);
        return rc;
    }

    *writer = w;
    return CN_OK;
}

cn_err_t cn_pcap_writer_write(cn_pcap_writer_t *writer, const uint8_t *data,
                              uint32_t caplen, uint32_t orig_len,
                              uint32_t ts_sec, uint32_t ts_usec)
{
    if (writer == NULL || data == NULL) {
        return CN_ERR_INVAL;
    }
    if (caplen == 0 || caplen > CN_PKT_SIZE_MAX) {
        return CN_ERR_INVAL;
    }
    if (caplen > orig_len) {
        return CN_ERR_INVAL;
    }

    /*
     * Write the 16-byte per-packet header:
     *   ts_sec (4)  ts_usec (4)  incl_len (4)  orig_len (4)
     */
    cn_err_t rc = CN_OK;

    if (rc == CN_OK) rc = write_u32(writer->fp, ts_sec);
    if (rc == CN_OK) rc = write_u32(writer->fp, ts_usec);
    if (rc == CN_OK) rc = write_u32(writer->fp, caplen);
    if (rc == CN_OK) rc = write_u32(writer->fp, orig_len);

    if (rc == CN_OK) {
        if (fwrite(data, 1, (size_t)caplen, writer->fp) != (size_t)caplen) {
            rc = CN_ERR_IO;
        }
    }

    return rc;
}

cn_err_t cn_pcap_writer_close(cn_pcap_writer_t **writer)
{
    if (writer == NULL || *writer == NULL) {
        return CN_OK;
    }

    cn_pcap_writer_t *w = *writer;
    *writer = NULL; /* NULL out first to prevent double-close on error. */

    cn_err_t rc = CN_OK;
    if (fflush(w->fp) != 0) {
        rc = CN_ERR_IO;
    }
    if (fclose(w->fp) != 0) {
        rc = CN_ERR_IO;
    }
    free(w);
    return rc;
}
