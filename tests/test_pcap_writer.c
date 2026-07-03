/*
 * test_pcap_writer.c — unit tests for core/pcap_writer.c
 *
 * Tests: NULL guards, snaplen validation, file creation, global pcap header
 * content (read-back verification), per-packet record content (read-back),
 * multiple packets, close idempotency.
 *
 * The test reads the raw binary file back to verify the exact wire layout
 * of the pcap global header and per-packet records.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "test_harness.h"
#include "../core/pcap_writer.h"
#include "../core/constants.h"

/* --------------------------------------------------------------------------
 * pcap file format constants (standard libpcap, host-byte-order magic)
 * -------------------------------------------------------------------------- */

#define PCAP_MAGIC_LE       UINT32_C(0xa1b2c3d4) /* little-endian host */
#define PCAP_MAGIC_BE       UINT32_C(0xd4c3b2a1) /* big-endian host    */
#define PCAP_VERSION_MAJOR  UINT16_C(2)
#define PCAP_VERSION_MINOR  UINT16_C(4)
#define PCAP_GLOBAL_HDR_LEN 24  /* bytes */
#define PCAP_PKT_HDR_LEN    16  /* bytes per packet header */
#define DLT_EN10MB          1

/* Read a little-endian uint32 from a byte buffer. */
static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Read a big-endian uint32 from a byte buffer. */
static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         |  (uint32_t)p[3];
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* --------------------------------------------------------------------------
 * Helper: read entire file into a heap buffer.
 * Caller must free() the result. Returns NULL on error. *len_out set.
 * -------------------------------------------------------------------------- */
static uint8_t *read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)sz;
    return buf;
}

/* --------------------------------------------------------------------------
 * NULL / invalid parameter tests
 * -------------------------------------------------------------------------- */

static void test_open_null_writer(void)
{
    cn_err_t rc = cn_pcap_writer_open(NULL, "/tmp/x", DLT_EN10MB, 65535);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_open_null_path(void)
{
    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, NULL, DLT_EN10MB, 65535);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(w == NULL);
}

static void test_open_snaplen_zero(void)
{
    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, "/tmp/x", DLT_EN10MB, 0);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(w == NULL);
}

static void test_open_snaplen_too_large(void)
{
    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, "/tmp/x", DLT_EN10MB,
                                      CN_PKT_SIZE_MAX + 1);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(w == NULL);
}

static void test_write_null_writer(void)
{
    const uint8_t data[4] = { 0 };
    cn_err_t rc = cn_pcap_writer_write(NULL, data, 4, 4, 0, 0);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_write_null_data(void)
{
    char path[] = "/tmp/netcap_test_pcap_XXXXXX";
    int fd = mkstemp(path); if (fd < 0) { EXPECT(0); return; } close(fd);

    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, path, DLT_EN10MB, 65535);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        rc = cn_pcap_writer_write(w, NULL, 4, 4, 0, 0);
        EXPECT_EQ(rc, CN_ERR_INVAL);
        rc = cn_pcap_writer_close(&w);
    }
    unlink(path);
}

static void test_write_caplen_zero(void)
{
    char path[] = "/tmp/netcap_test_pcap_XXXXXX";
    int fd = mkstemp(path); if (fd < 0) { EXPECT(0); return; } close(fd);

    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, path, DLT_EN10MB, 65535);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        const uint8_t data[4] = { 0 };
        rc = cn_pcap_writer_write(w, data, 0, 4, 0, 0);
        EXPECT_EQ(rc, CN_ERR_INVAL);
        rc = cn_pcap_writer_close(&w);
    }
    unlink(path);
}

static void test_write_caplen_exceeds_orig(void)
{
    char path[] = "/tmp/netcap_test_pcap_XXXXXX";
    int fd = mkstemp(path); if (fd < 0) { EXPECT(0); return; } close(fd);

    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, path, DLT_EN10MB, 65535);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        const uint8_t data[8] = { 0 };
        /* caplen (8) > orig_len (4) — invalid. */
        rc = cn_pcap_writer_write(w, data, 8, 4, 0, 0);
        EXPECT_EQ(rc, CN_ERR_INVAL);
        rc = cn_pcap_writer_close(&w);
    }
    unlink(path);
}

static void test_close_null(void)
{
    /* *writer == NULL must be a no-op. */
    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_close(&w);
    EXPECT_EQ(rc, CN_OK);
}

/* --------------------------------------------------------------------------
 * Global header read-back test
 * -------------------------------------------------------------------------- */

static void test_global_header(void)
{
    char path[] = "/tmp/netcap_test_pcap_XXXXXX";
    int fd = mkstemp(path); if (fd < 0) { EXPECT(0); return; } close(fd);

    const uint32_t snaplen   = 1500;
    const int      link_type = DLT_EN10MB;

    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, path, link_type, snaplen);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    rc = cn_pcap_writer_close(&w);
    EXPECT_EQ(rc, CN_OK);
    EXPECT(w == NULL);

    /* Read the raw file. */
    size_t file_len = 0;
    uint8_t *data = read_file(path, &file_len);
    EXPECT(data != NULL);
    EXPECT((long long)file_len >= (long long)PCAP_GLOBAL_HDR_LEN);

    if (data && file_len >= PCAP_GLOBAL_HDR_LEN) {
        uint32_t magic = read_le32(data);
        bool is_le = (magic == PCAP_MAGIC_LE);
        bool is_be = (magic == PCAP_MAGIC_BE);
        EXPECT(is_le || is_be);

        uint16_t vmaj, vmin;
        uint32_t slen, net;
        if (is_le) {
            vmaj = read_le16(data + 4);
            vmin = read_le16(data + 6);
            slen = read_le32(data + 16);
            net  = read_le32(data + 20);
        } else {
            vmaj = read_be16(data + 4);
            vmin = read_be16(data + 6);
            slen = read_be32(data + 16);
            net  = read_be32(data + 20);
        }
        EXPECT_EQ((long long)vmaj, (long long)PCAP_VERSION_MAJOR);
        EXPECT_EQ((long long)vmin, (long long)PCAP_VERSION_MINOR);
        EXPECT_EQ((long long)slen, (long long)snaplen);
        EXPECT_EQ((long long)net,  (long long)link_type);
    }
    free(data);
    unlink(path);
}

/* --------------------------------------------------------------------------
 * Packet record read-back test
 * -------------------------------------------------------------------------- */

static void test_packet_record(void)
{
    char path[] = "/tmp/netcap_test_pcap_XXXXXX";
    int fd = mkstemp(path); if (fd < 0) { EXPECT(0); return; } close(fd);

    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, path, DLT_EN10MB, 65535);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    /* Write a single packet. */
    const uint8_t pkt[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };
    const uint32_t caplen   = (uint32_t)sizeof(pkt);
    const uint32_t orig_len = caplen + 10;  /* simulated truncation */
    const uint32_t ts_sec   = 1700000000u;
    const uint32_t ts_usec  = 123456u;

    rc = cn_pcap_writer_write(w, pkt, caplen, orig_len, ts_sec, ts_usec);
    EXPECT_EQ(rc, CN_OK);

    rc = cn_pcap_writer_close(&w);
    EXPECT_EQ(rc, CN_OK);

    /* Read back and verify. */
    size_t file_len = 0;
    uint8_t *data = read_file(path, &file_len);
    EXPECT(data != NULL);

    size_t expected_size = PCAP_GLOBAL_HDR_LEN + PCAP_PKT_HDR_LEN + caplen;
    EXPECT_EQ((long long)file_len, (long long)expected_size);

    if (data && file_len == expected_size) {
        uint32_t magic = read_le32(data);
        bool is_le = (magic == PCAP_MAGIC_LE);

        const uint8_t *rec = data + PCAP_GLOBAL_HDR_LEN;
        uint32_t r_ts_sec, r_ts_usec, r_caplen, r_orig_len;
        if (is_le) {
            r_ts_sec   = read_le32(rec);
            r_ts_usec  = read_le32(rec + 4);
            r_caplen   = read_le32(rec + 8);
            r_orig_len = read_le32(rec + 12);
        } else {
            r_ts_sec   = read_be32(rec);
            r_ts_usec  = read_be32(rec + 4);
            r_caplen   = read_be32(rec + 8);
            r_orig_len = read_be32(rec + 12);
        }
        EXPECT_EQ((long long)r_ts_sec,   (long long)ts_sec);
        EXPECT_EQ((long long)r_ts_usec,  (long long)ts_usec);
        EXPECT_EQ((long long)r_caplen,   (long long)caplen);
        EXPECT_EQ((long long)r_orig_len, (long long)orig_len);
        EXPECT(memcmp(rec + PCAP_PKT_HDR_LEN, pkt, caplen) == 0);
    }
    free(data);
    unlink(path);
}

/* --------------------------------------------------------------------------
 * Multiple packets read-back test
 * -------------------------------------------------------------------------- */

static void test_multiple_packets(void)
{
    char path[] = "/tmp/netcap_test_pcap_XXXXXX";
    int fd = mkstemp(path); if (fd < 0) { EXPECT(0); return; } close(fd);

    cn_pcap_writer_t *w = NULL;
    cn_err_t rc = cn_pcap_writer_open(&w, path, DLT_EN10MB, 65535);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    const uint8_t pkt1[] = { 0x01, 0x02, 0x03 };
    const uint8_t pkt2[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
    const uint32_t ts1 = 1700000001u, us1 = 111u;
    const uint32_t ts2 = 1700000002u, us2 = 222u;

    EXPECT_EQ(cn_pcap_writer_write(w, pkt1, (uint32_t)sizeof(pkt1),
                                   (uint32_t)sizeof(pkt1), ts1, us1), CN_OK);
    EXPECT_EQ(cn_pcap_writer_write(w, pkt2, (uint32_t)sizeof(pkt2),
                                   (uint32_t)sizeof(pkt2), ts2, us2), CN_OK);
    EXPECT_EQ(cn_pcap_writer_close(&w), CN_OK);

    size_t file_len = 0;
    uint8_t *data = read_file(path, &file_len);
    EXPECT(data != NULL);

    size_t expected = PCAP_GLOBAL_HDR_LEN
                    + PCAP_PKT_HDR_LEN + sizeof(pkt1)
                    + PCAP_PKT_HDR_LEN + sizeof(pkt2);
    EXPECT_EQ((long long)file_len, (long long)expected);

    if (data && file_len == expected) {
        uint32_t magic = read_le32(data);
        bool is_le = (magic == PCAP_MAGIC_LE);

        /* Verify packet 1. */
        const uint8_t *rec = data + PCAP_GLOBAL_HDR_LEN;
        uint32_t r_ts1 = is_le ? read_le32(rec)     : read_be32(rec);
        uint32_t r_us1 = is_le ? read_le32(rec + 4) : read_be32(rec + 4);
        uint32_t r_cl1 = is_le ? read_le32(rec + 8) : read_be32(rec + 8);
        EXPECT_EQ((long long)r_ts1, (long long)ts1);
        EXPECT_EQ((long long)r_us1, (long long)us1);
        EXPECT_EQ((long long)r_cl1, (long long)sizeof(pkt1));
        EXPECT(memcmp(rec + PCAP_PKT_HDR_LEN, pkt1, sizeof(pkt1)) == 0);

        /* Verify packet 2. */
        rec = rec + PCAP_PKT_HDR_LEN + sizeof(pkt1);
        uint32_t r_ts2 = is_le ? read_le32(rec)     : read_be32(rec);
        uint32_t r_us2 = is_le ? read_le32(rec + 4) : read_be32(rec + 4);
        uint32_t r_cl2 = is_le ? read_le32(rec + 8) : read_be32(rec + 8);
        EXPECT_EQ((long long)r_ts2, (long long)ts2);
        EXPECT_EQ((long long)r_us2, (long long)us2);
        EXPECT_EQ((long long)r_cl2, (long long)sizeof(pkt2));
        EXPECT(memcmp(rec + PCAP_PKT_HDR_LEN, pkt2, sizeof(pkt2)) == 0);
    }
    free(data);
    unlink(path);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("test_pcap_writer\n");

    RUN_TEST(test_open_null_writer);
    RUN_TEST(test_open_null_path);
    RUN_TEST(test_open_snaplen_zero);
    RUN_TEST(test_open_snaplen_too_large);
    RUN_TEST(test_write_null_writer);
    RUN_TEST(test_write_null_data);
    RUN_TEST(test_write_caplen_zero);
    RUN_TEST(test_write_caplen_exceeds_orig);
    RUN_TEST(test_close_null);
    RUN_TEST(test_global_header);
    RUN_TEST(test_packet_record);
    RUN_TEST(test_multiple_packets);

    return TEST_RESULT();
}
