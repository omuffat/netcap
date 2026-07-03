#ifndef CN_PCAP_WRITER_H
#define CN_PCAP_WRITER_H

#include <stddef.h>
#include <stdint.h>
#include "constants.h"

/* -------------------------------------------------------------------------
 * pcap file writer (opaque)
 * ---------------------------------------------------------------------- */

/** Handle for writing standard libpcap (.pcap) capture files. */
typedef struct cn_pcap_writer cn_pcap_writer_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief Open a new .pcap file for writing.
 *
 * Creates the file at path and writes the global pcap file header
 * (magic number, version, link type, snaplen). The file uses the
 * native host byte order for the magic number so that pcap readers
 * can detect endianness automatically.
 *
 * @security path must be validated against CN_PATH_MAX by the caller.
 *           The file is created with mode 0600 (owner read/write only).
 *           If the file already exists it is truncated.
 *
 * @param[out] writer    Set to the allocated writer on success. Must not be NULL.
 * @param[in]  path      Absolute destination path. Must not be NULL.
 *                       Length must be < CN_PATH_MAX.
 * @param[in]  link_type DLT_* link-layer type constant (e.g., DLT_EN10MB).
 * @param[in]  snaplen   Maximum bytes stored per packet record.
 *                       Must be > 0 and <= CN_PKT_SIZE_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL  if writer or path is NULL; snaplen is 0 or exceeds
 *                       CN_PKT_SIZE_MAX; or path is too long.
 * @return CN_ERR_IO     if the file cannot be created or the global header
 *                       cannot be written.
 * @return CN_ERR_NOMEM  if allocation fails.
 */
cn_err_t cn_pcap_writer_open(cn_pcap_writer_t **writer, const char *path,
                             int link_type, uint32_t snaplen)
    __attribute__((warn_unused_result));

/**
 * @brief Write one captured packet record to the open .pcap file.
 *
 * Writes a pcap per-packet header followed by caplen bytes from data.
 * orig_len records the original on-wire packet length (may differ from
 * caplen when the packet was truncated at capture time).
 *
 * @security data originates from libpcap (untrusted network input).
 *           caplen must be verified against CN_PKT_SIZE_MAX by the caller
 *           before this call. caplen must be <= orig_len.
 *
 * @param[in,out] writer   Open writer handle. Must not be NULL.
 * @param[in]     data     Packet bytes to store. Must not be NULL.
 * @param[in]     caplen   Number of bytes in data.
 *                         Must be > 0 and <= CN_PKT_SIZE_MAX.
 * @param[in]     orig_len Original on-wire length. Must be >= caplen.
 * @param[in]     ts_sec   Capture timestamp, whole seconds (Unix epoch).
 * @param[in]     ts_usec  Capture timestamp, microseconds fraction.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if writer or data is NULL; caplen is 0, exceeds
 *                       CN_PKT_SIZE_MAX, or is greater than orig_len.
 * @return CN_ERR_IO    if the write fails.
 */
cn_err_t cn_pcap_writer_write(cn_pcap_writer_t *writer, const uint8_t *data,
                              uint32_t caplen, uint32_t orig_len,
                              uint32_t ts_sec, uint32_t ts_usec)
    __attribute__((warn_unused_result));

/**
 * @brief Flush pending writes and close the .pcap file.
 *
 * Calls fflush() and then fclose() on the underlying FILE stream. Sets
 * *writer to NULL on return, even if fclose() fails, to prevent double-close.
 *
 * @param[in,out] writer  Pointer to an open writer. Must not be NULL.
 *                        *writer may be NULL (no-op).
 *
 * @return CN_OK on success.
 * @return CN_ERR_IO if fflush() or fclose() fails.
 */
cn_err_t cn_pcap_writer_close(cn_pcap_writer_t **writer)
    __attribute__((warn_unused_result));

#endif /* CN_PCAP_WRITER_H */
