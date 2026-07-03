#ifndef CN_RING_H
#define CN_RING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "constants.h"

/* -------------------------------------------------------------------------
 * Ring buffer structure
 * ---------------------------------------------------------------------- */

typedef struct {
    uint8_t  *base;        /* Base address of the mmap mapping. */
    size_t    size;        /* Total ring size in bytes. */
    uint64_t  write_head;  /* Write index (modulo size), written only by the pcap thread. */
    uint64_t  read_head;   /* Read index (modulo size), written only by msync_worker. */
    int       fd;          /* File descriptor for ring_<iface>.bin. */
    bool      mapped;      /* true if mmap is active; false if uninitialized or failed. */
} cn_ring_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief Initialize a ring buffer backed by a memory-mapped file.
 *
 * Creates or opens ring_<iface>.bin and maps it into memory. The file is
 * truncated or extended to exactly size bytes. size must be a multiple of
 * the system page size and must satisfy CN_RING_SIZE_MIN <= size <= CN_RING_SIZE_MAX.
 *
 * @security path must be validated by the caller against CN_PATH_MAX.
 *           The file is opened with O_CREAT | O_RDWR and mode 0600. Do not
 *           place ring files in world-writable directories. CAP_NET_RAW is
 *           not required by this function.
 *
 * @param[out] ring  Ring structure to initialize. Must not be NULL.
 * @param[in]  path  Absolute path of the backing file. Must not be NULL.
 *                   Length must be < CN_PATH_MAX.
 * @param[in]  size  Desired ring size in bytes. Must satisfy:
 *                   CN_RING_SIZE_MIN <= size <= CN_RING_SIZE_MAX and
 *                   size % page_size == 0.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if ring or path is NULL, or size is out of range.
 * @return CN_ERR_IO    if the file cannot be opened, resized, or mapped.
 * @return CN_ERR_NOMEM if the mmap call fails.
 */
cn_err_t cn_ring_init(cn_ring_t *ring, const char *path, size_t size)
    __attribute__((warn_unused_result));

/**
 * @brief Write a packet into the ring buffer.
 *
 * Copies len bytes from data into the next available slot. Each record is
 * prefixed with a 4-byte little-endian length field. Called exclusively from
 * the pcap capture thread associated with this ring.
 *
 * @security data originates from libpcap (untrusted network input). len must
 *           be checked against CN_PKT_SIZE_MAX by the caller before invoking
 *           this function. Do not call from more than one thread simultaneously.
 *
 * @param[in,out] ring  Initialized and mapped ring buffer. Must not be NULL.
 * @param[in]     data  Packet data. Must not be NULL.
 * @param[in]     len   Packet length in bytes. Must be > 0 and <= CN_PKT_SIZE_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL    if ring or data is NULL, or len is out of range.
 * @return CN_ERR_OVERFLOW if the ring is full (the packet is dropped).
 */
cn_err_t cn_ring_write(cn_ring_t *ring, const uint8_t *data, size_t len)
    __attribute__((warn_unused_result));

/**
 * @brief Read the next packet from the ring buffer into a caller-supplied buffer.
 *
 * Consumes the 4-byte length prefix and copies the packet body into buf.
 * The prefix is not included in the output. Called from msync_worker or
 * upload workers — never from the pcap thread.
 *
 * @security buf must point to a buffer of at least CN_PKT_SIZE_MAX bytes to
 *           accommodate any valid packet. Do not call from more than one
 *           reader thread simultaneously.
 *
 * @param[in,out] ring      Initialized and mapped ring buffer. Must not be NULL.
 * @param[out]    buf       Destination buffer. Must not be NULL.
 * @param[in]     buf_size  Capacity of buf in bytes. Must be >= CN_PKT_SIZE_MAX.
 * @param[out]    out_len   Set to the number of bytes written to buf on CN_OK.
 *                          Must not be NULL.
 *
 * @return CN_OK     if a packet was successfully read.
 * @return CN_ERR_INVAL if any pointer is NULL or buf_size < CN_PKT_SIZE_MAX.
 * @return CN_ERR_IO if the ring is empty (no data available).
 */
cn_err_t cn_ring_read(cn_ring_t *ring, uint8_t *buf, size_t buf_size,
                      size_t *out_len)
    __attribute__((warn_unused_result));

/**
 * @brief Return the number of unread bytes currently in the ring.
 *
 * Safe to call from any thread. Uses only relaxed reads of write_head
 * and read_head, so the result may be stale by the time the caller acts on it.
 *
 * @param[in] ring  Initialized ring buffer. Must not be NULL.
 *
 * @return Number of unread bytes, or 0 if ring is NULL or unmapped.
 */
size_t cn_ring_bytes_available(const cn_ring_t *ring);

/**
 * @brief Flush dirty pages of the ring buffer to the backing file on disk.
 *
 * Calls msync(MS_SYNC) on the modified region of the mapping. Should be
 * invoked periodically by the msync_worker thread. Must not be called from
 * the pcap capture thread.
 *
 * @param[in,out] ring  Initialized and mapped ring buffer. Must not be NULL.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if ring is NULL or ring->mapped is false.
 * @return CN_ERR_IO    if msync() fails.
 */
cn_err_t cn_ring_flush(cn_ring_t *ring)
    __attribute__((warn_unused_result));

/**
 * @brief Release all resources associated with a ring buffer.
 *
 * Unmaps the memory region and closes the file descriptor. Sets ring->mapped
 * to false. Safe to call on a partially initialized ring (e.g., if
 * cn_ring_init() failed after the file was opened but before mmap succeeded).
 *
 * @param[in,out] ring  Ring buffer to destroy. Must not be NULL.
 */
void cn_ring_destroy(cn_ring_t *ring);

#endif /* CN_RING_H */
