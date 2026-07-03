/*
 * test_capture.c — unit tests for core/capture.c
 *
 * Only NULL / invalid parameter guard tests are implemented here.
 * Tests that require a live network interface (and therefore CAP_NET_RAW)
 * are excluded — no root is required to run this test binary.
 */

#include <stdio.h>
#include <string.h>
#include "test_harness.h"
#include "../core/capture.h"
#include "../core/constants.h"

/* --------------------------------------------------------------------------
 * cn_capture_init — NULL / invalid parameter guards
 * -------------------------------------------------------------------------- */

static void test_init_null_ctx(void)
{
    cn_ring_t ring;
    memset(&ring, 0, sizeof(ring));
    cn_err_t rc = cn_capture_init(NULL, "eth0", &ring, 65535, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_init_null_iface(void)
{
    cn_capture_ctx_t *ctx = NULL;
    cn_ring_t ring;
    memset(&ring, 0, sizeof(ring));
    cn_err_t rc = cn_capture_init(&ctx, NULL, &ring, 65535, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

static void test_init_null_ring(void)
{
    cn_capture_ctx_t *ctx = NULL;
    cn_err_t rc = cn_capture_init(&ctx, "eth0", NULL, 65535, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

static void test_init_snaplen_zero(void)
{
    cn_capture_ctx_t *ctx = NULL;
    cn_ring_t ring;
    memset(&ring, 0, sizeof(ring));
    cn_err_t rc = cn_capture_init(&ctx, "eth0", &ring, 0, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

static void test_init_snaplen_too_large(void)
{
    cn_capture_ctx_t *ctx = NULL;
    cn_ring_t ring;
    memset(&ring, 0, sizeof(ring));
    cn_err_t rc = cn_capture_init(&ctx, "eth0", &ring,
                                  (int)CN_PKT_SIZE_MAX + 1, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

static void test_init_iface_name_too_long(void)
{
    cn_capture_ctx_t *ctx = NULL;
    cn_ring_t ring;
    memset(&ring, 0, sizeof(ring));

    /* Build a name that is exactly CN_IFACE_NAME_MAX characters (no NUL). */
    char long_name[CN_IFACE_NAME_MAX + 1];
    memset(long_name, 'e', CN_IFACE_NAME_MAX);
    long_name[CN_IFACE_NAME_MAX] = '\0';

    cn_err_t rc = cn_capture_init(&ctx, long_name, &ring, 65535, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

/* --------------------------------------------------------------------------
 * cn_capture_start — NULL guard
 * -------------------------------------------------------------------------- */

static void test_start_null(void)
{
    cn_err_t rc = cn_capture_start(NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

/* --------------------------------------------------------------------------
 * cn_capture_stop — NULL guard
 * -------------------------------------------------------------------------- */

static void test_stop_null(void)
{
    cn_err_t rc = cn_capture_stop(NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

/* --------------------------------------------------------------------------
 * cn_capture_get_stats — NULL guards
 * -------------------------------------------------------------------------- */

static void test_get_stats_null_ctx(void)
{
    cn_capture_stats_t stats;
    cn_err_t rc = cn_capture_get_stats(NULL, &stats);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_get_stats_null_stats(void)
{
    /* ctx is non-NULL but not a valid initialized context; the function must
     * check stats != NULL before dereferencing ctx. */
    cn_capture_ctx_t *fake = (cn_capture_ctx_t *)1;
    cn_err_t rc = cn_capture_get_stats(fake, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

/* --------------------------------------------------------------------------
 * cn_capture_get_link_type — NULL guard
 * -------------------------------------------------------------------------- */

static void test_get_link_type_null(void)
{
    int lt = cn_capture_get_link_type(NULL);
    EXPECT_EQ(lt, -1);
}

/* --------------------------------------------------------------------------
 * cn_capture_destroy — NULL guard
 * -------------------------------------------------------------------------- */

static void test_destroy_null(void)
{
    cn_capture_ctx_t *ctx = NULL;
    cn_capture_destroy(&ctx);  /* Must not crash. */
    EXPECT(ctx == NULL);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("test_capture\n");

    RUN_TEST(test_init_null_ctx);
    RUN_TEST(test_init_null_iface);
    RUN_TEST(test_init_null_ring);
    RUN_TEST(test_init_snaplen_zero);
    RUN_TEST(test_init_snaplen_too_large);
    RUN_TEST(test_init_iface_name_too_long);
    RUN_TEST(test_start_null);
    RUN_TEST(test_stop_null);
    RUN_TEST(test_get_stats_null_ctx);
    RUN_TEST(test_get_stats_null_stats);
    RUN_TEST(test_get_link_type_null);
    RUN_TEST(test_destroy_null);

    return TEST_RESULT();
}
