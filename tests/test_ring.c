/*
 * test_ring.c — unit tests for core/ring.c
 *
 * Tests: NULL guards, size validation, init/destroy, write/read roundtrip,
 * multiple packets, ring-empty returns CN_ERR_IO, flush, bytes_available,
 * oversized packet rejected.
 *
 * No root required — ring files are created in /tmp via mkstemp().
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_harness.h"
#include "../core/ring.h"
#include "../core/constants.h"

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/*
 * Smallest valid ring size: CN_RING_SIZE_MIN (4096).
 * All tests use this size unless testing size validation.
 */
#define TEST_RING_SIZE CN_RING_SIZE_MIN

/* Create a temp path, initialize a ring of TEST_RING_SIZE, return the path. */
static int setup_ring(cn_ring_t *ring, char *path_out)
{
    char tmpl[] = "/tmp/netcap_test_ring_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    close(fd);
    /* mkstemp creates the file; cn_ring_init will truncate/resize it. */
    memcpy(path_out, tmpl, sizeof(tmpl));

    cn_err_t rc = cn_ring_init(ring, path_out, TEST_RING_SIZE);
    return (rc == CN_OK) ? 0 : -1;
}

static void teardown_ring(cn_ring_t *ring, const char *path)
{
    cn_ring_destroy(ring);
    unlink(path);
}

/* --------------------------------------------------------------------------
 * NULL / invalid parameter tests
 * -------------------------------------------------------------------------- */

static void test_init_null_ring(void)
{
    cn_err_t rc = cn_ring_init(NULL, "/tmp/x", TEST_RING_SIZE);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_init_null_path(void)
{
    cn_ring_t ring;
    cn_err_t rc = cn_ring_init(&ring, NULL, TEST_RING_SIZE);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_init_size_zero(void)
{
    cn_ring_t ring;
    cn_err_t rc = cn_ring_init(&ring, "/tmp/x", 0);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_init_size_below_min(void)
{
    cn_ring_t ring;
    cn_err_t rc = cn_ring_init(&ring, "/tmp/x", CN_RING_SIZE_MIN - 1);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_init_size_above_max(void)
{
    cn_ring_t ring;
    cn_err_t rc = cn_ring_init(&ring, "/tmp/x", CN_RING_SIZE_MAX + 1);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_write_null_ring(void)
{
    const uint8_t data[4] = { 1, 2, 3, 4 };
    cn_err_t rc = cn_ring_write(NULL, data, 4);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_write_null_data(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    cn_err_t rc = cn_ring_write(&ring, NULL, 4);
    EXPECT_EQ(rc, CN_ERR_INVAL);

    teardown_ring(&ring, path);
}

static void test_write_zero_len(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    const uint8_t data[4] = { 0 };
    cn_err_t rc = cn_ring_write(&ring, data, 0);
    EXPECT_EQ(rc, CN_ERR_INVAL);

    teardown_ring(&ring, path);
}

static void test_write_len_too_large(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    const uint8_t data[1] = { 0 };
    cn_err_t rc = cn_ring_write(&ring, data, CN_PKT_SIZE_MAX + 1);
    EXPECT_EQ(rc, CN_ERR_OVERFLOW);

    teardown_ring(&ring, path);
}

static void test_read_null_ring(void)
{
    uint8_t buf[CN_PKT_SIZE_MAX];
    size_t out_len = 0;
    cn_err_t rc = cn_ring_read(NULL, buf, CN_PKT_SIZE_MAX, &out_len);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_read_null_buf(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    size_t out_len = 0;
    cn_err_t rc = cn_ring_read(&ring, NULL, CN_PKT_SIZE_MAX, &out_len);
    EXPECT_EQ(rc, CN_ERR_INVAL);

    teardown_ring(&ring, path);
}

static void test_read_buf_too_small(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    uint8_t buf[16];
    size_t out_len = 0;
    cn_err_t rc = cn_ring_read(&ring, buf, sizeof(buf), &out_len);
    EXPECT_EQ(rc, CN_ERR_INVAL);

    teardown_ring(&ring, path);
}

static void test_read_null_out_len(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    uint8_t buf[CN_PKT_SIZE_MAX];
    cn_err_t rc = cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);

    teardown_ring(&ring, path);
}

static void test_flush_null(void)
{
    cn_err_t rc = cn_ring_flush(NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

/* --------------------------------------------------------------------------
 * Functional tests
 * -------------------------------------------------------------------------- */

static void test_init_destroy(void)
{
    cn_ring_t ring;
    char path[64];
    cn_err_t rc = cn_ring_init(&ring, path, TEST_RING_SIZE);

    /* init requires a valid path that mkstemp provided — do it properly. */
    char tmpl[] = "/tmp/netcap_test_ring_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { EXPECT(0); return; }
    close(fd);

    memset(&ring, 0, sizeof(ring));
    rc = cn_ring_init(&ring, tmpl, TEST_RING_SIZE);
    EXPECT_EQ(rc, CN_OK);
    EXPECT(ring.mapped == true);
    EXPECT(ring.base != NULL);
    EXPECT_EQ((long long)ring.size, (long long)TEST_RING_SIZE);

    cn_ring_destroy(&ring);
    EXPECT(ring.mapped == false);
    unlink(tmpl);
}

static void test_read_empty(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    uint8_t buf[CN_PKT_SIZE_MAX];
    size_t out_len = 0;
    cn_err_t rc = cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len);
    EXPECT_EQ(rc, CN_ERR_IO);

    teardown_ring(&ring, path);
}

static void test_write_read_roundtrip(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    const uint8_t pkt[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };
    cn_err_t rc = cn_ring_write(&ring, pkt, sizeof(pkt));
    EXPECT_EQ(rc, CN_OK);

    uint8_t buf[CN_PKT_SIZE_MAX];
    size_t out_len = 0;
    rc = cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len);
    EXPECT_EQ(rc, CN_OK);
    EXPECT_EQ((long long)out_len, (long long)sizeof(pkt));
    EXPECT(memcmp(buf, pkt, sizeof(pkt)) == 0);

    /* Ring is now empty. */
    rc = cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len);
    EXPECT_EQ(rc, CN_ERR_IO);

    teardown_ring(&ring, path);
}

static void test_write_read_multiple(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    const uint8_t pkt1[] = { 0x01, 0x02, 0x03 };
    const uint8_t pkt2[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    const uint8_t pkt3[] = { 0xFF };

    EXPECT_EQ(cn_ring_write(&ring, pkt1, sizeof(pkt1)), CN_OK);
    EXPECT_EQ(cn_ring_write(&ring, pkt2, sizeof(pkt2)), CN_OK);
    EXPECT_EQ(cn_ring_write(&ring, pkt3, sizeof(pkt3)), CN_OK);

    uint8_t buf[CN_PKT_SIZE_MAX];
    size_t out_len = 0;

    EXPECT_EQ(cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len), CN_OK);
    EXPECT_EQ((long long)out_len, (long long)sizeof(pkt1));
    EXPECT(memcmp(buf, pkt1, sizeof(pkt1)) == 0);

    EXPECT_EQ(cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len), CN_OK);
    EXPECT_EQ((long long)out_len, (long long)sizeof(pkt2));
    EXPECT(memcmp(buf, pkt2, sizeof(pkt2)) == 0);

    EXPECT_EQ(cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len), CN_OK);
    EXPECT_EQ((long long)out_len, (long long)sizeof(pkt3));
    EXPECT(memcmp(buf, pkt3, sizeof(pkt3)) == 0);

    EXPECT_EQ(cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len), CN_ERR_IO);

    teardown_ring(&ring, path);
}

static void test_bytes_available(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    EXPECT_EQ((long long)cn_ring_bytes_available(&ring), 0LL);

    const uint8_t pkt[] = { 1, 2, 3, 4, 5 };
    EXPECT_EQ(cn_ring_write(&ring, pkt, sizeof(pkt)), CN_OK);
    EXPECT(cn_ring_bytes_available(&ring) > 0);

    uint8_t buf[CN_PKT_SIZE_MAX];
    size_t out_len = 0;
    EXPECT_EQ(cn_ring_read(&ring, buf, CN_PKT_SIZE_MAX, &out_len), CN_OK);
    EXPECT_EQ((long long)cn_ring_bytes_available(&ring), 0LL);

    teardown_ring(&ring, path);
}

static void test_bytes_available_null(void)
{
    /* Must not crash; returns 0. */
    size_t n = cn_ring_bytes_available(NULL);
    EXPECT_EQ((long long)n, 0LL);
}

static void test_flush(void)
{
    cn_ring_t ring;
    char path[64];
    if (setup_ring(&ring, path) != 0) { EXPECT(0); return; }

    const uint8_t pkt[] = { 0x10, 0x20, 0x30 };
    EXPECT_EQ(cn_ring_write(&ring, pkt, sizeof(pkt)), CN_OK);

    cn_err_t rc = cn_ring_flush(&ring);
    EXPECT_EQ(rc, CN_OK);

    teardown_ring(&ring, path);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("test_ring\n");

    RUN_TEST(test_init_null_ring);
    RUN_TEST(test_init_null_path);
    RUN_TEST(test_init_size_zero);
    RUN_TEST(test_init_size_below_min);
    RUN_TEST(test_init_size_above_max);
    RUN_TEST(test_write_null_ring);
    RUN_TEST(test_write_null_data);
    RUN_TEST(test_write_zero_len);
    RUN_TEST(test_write_len_too_large);
    RUN_TEST(test_read_null_ring);
    RUN_TEST(test_read_null_buf);
    RUN_TEST(test_read_buf_too_small);
    RUN_TEST(test_read_null_out_len);
    RUN_TEST(test_flush_null);
    RUN_TEST(test_init_destroy);
    RUN_TEST(test_read_empty);
    RUN_TEST(test_write_read_roundtrip);
    RUN_TEST(test_write_read_multiple);
    RUN_TEST(test_bytes_available);
    RUN_TEST(test_bytes_available_null);
    RUN_TEST(test_flush);

    return TEST_RESULT();
}
