/*
 * test_filter.c — unit tests for core/filter.c
 *
 * Tests: NULL guards, expression length validation, valid expression compile,
 * invalid BPF expression rejected, apply to pcap handle, destroy idempotency.
 *
 * Uses pcap_open_dead(DLT_EN10MB, 65535) to obtain a pcap handle that does
 * not require root or a live network interface.
 */

#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include "test_harness.h"
#include "../core/filter.h"
#include "../core/constants.h"

/* --------------------------------------------------------------------------
 * NULL / invalid parameter tests
 * -------------------------------------------------------------------------- */

static void test_compile_null_filter(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_err_t rc = cn_filter_compile(NULL, handle, "tcp");
    EXPECT_EQ(rc, CN_ERR_INVAL);

    pcap_close(handle);
}

static void test_compile_null_handle(void)
{
    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, NULL, "tcp");
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(f == NULL);
}

static void test_compile_null_expr(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(f == NULL);

    pcap_close(handle);
}

static void test_compile_empty_expr(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, "");
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(f == NULL);

    pcap_close(handle);
}

static void test_compile_expr_too_long(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    /* Build an expression of exactly CN_BPF_FILTER_MAX characters (no NUL). */
    char long_expr[CN_BPF_FILTER_MAX + 1];
    memset(long_expr, 'a', CN_BPF_FILTER_MAX);
    long_expr[CN_BPF_FILTER_MAX] = '\0';

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, long_expr);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(f == NULL);

    pcap_close(handle);
}

static void test_apply_null_filter(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_err_t rc = cn_filter_apply(NULL, handle);
    EXPECT_EQ(rc, CN_ERR_INVAL);

    pcap_close(handle);
}

static void test_apply_null_handle(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, "tcp");
    EXPECT_EQ(rc, CN_OK);
    pcap_close(handle);
    if (rc != CN_OK) return;

    rc = cn_filter_apply(f, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);

    cn_filter_destroy(&f);
}

static void test_destroy_null(void)
{
    cn_filter_t *f = NULL;
    cn_filter_destroy(&f);  /* Must not crash. */
    EXPECT(f == NULL);
}

/* --------------------------------------------------------------------------
 * Functional tests
 * -------------------------------------------------------------------------- */

static void test_compile_valid_tcp(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, "tcp");
    EXPECT_EQ(rc, CN_OK);
    EXPECT(f != NULL);

    cn_filter_destroy(&f);
    EXPECT(f == NULL);
    pcap_close(handle);
}

static void test_compile_valid_complex(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, "tcp port 443 or udp port 53");
    EXPECT_EQ(rc, CN_OK);
    EXPECT(f != NULL);

    cn_filter_destroy(&f);
    pcap_close(handle);
}

static void test_compile_invalid_expr(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, "not a valid bpf expression !!!");
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(f == NULL);

    pcap_close(handle);
}

static void test_compile_and_apply(void)
{
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!handle) { EXPECT(0); return; }

    cn_filter_t *f = NULL;
    cn_err_t rc = cn_filter_compile(&f, handle, "udp");
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { pcap_close(handle); return; }

    /* pcap_setfilter on a dead handle may succeed or fail depending on the
     * platform/libpcap version.  Either outcome is acceptable here; what
     * matters is that cn_filter_apply does not crash or corrupt state. */
    rc = cn_filter_apply(f, handle);
    (void)rc;

    cn_filter_destroy(&f);
    pcap_close(handle);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("test_filter\n");

    RUN_TEST(test_compile_null_filter);
    RUN_TEST(test_compile_null_handle);
    RUN_TEST(test_compile_null_expr);
    RUN_TEST(test_compile_empty_expr);
    RUN_TEST(test_compile_expr_too_long);
    RUN_TEST(test_apply_null_filter);
    RUN_TEST(test_apply_null_handle);
    RUN_TEST(test_destroy_null);
    RUN_TEST(test_compile_valid_tcp);
    RUN_TEST(test_compile_valid_complex);
    RUN_TEST(test_compile_invalid_expr);
    RUN_TEST(test_compile_and_apply);

    return TEST_RESULT();
}
