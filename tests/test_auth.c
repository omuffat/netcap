/*
 * test_auth.c — unit tests for uploader/auth.c
 *
 * Tests: init, get_header output, token length validation, overflow,
 * NULL guards, secure destroy (pointer nulled after destroy).
 */

#include <stdio.h>
#include <string.h>
#include "test_harness.h"
#include "../uploader/auth.h"
#include "../core/constants.h"

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/* Build a token string of exactly len printable characters. */
static void make_token(char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (char)('a' + (i % 26));
    buf[len] = '\0';
}

/* --------------------------------------------------------------------------
 * NULL guard tests
 * -------------------------------------------------------------------------- */

static void test_init_null_ctx(void)
{
    cn_err_t rc = cn_auth_init(NULL, "token");
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_init_null_token(void)
{
    cn_auth_ctx_t *ctx = NULL;
    cn_err_t rc = cn_auth_init(&ctx, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

static void test_get_header_null_ctx(void)
{
    char buf[CN_AUTH_TOKEN_MAX + 8];
    cn_err_t rc = cn_auth_get_header(NULL, buf, sizeof(buf));
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_get_header_null_buf(void)
{
    cn_auth_ctx_t *ctx = NULL;
    cn_err_t rc = cn_auth_init(&ctx, "tok");
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        rc = cn_auth_get_header(ctx, NULL, 64);
        EXPECT_EQ(rc, CN_ERR_INVAL);
        cn_auth_destroy(&ctx);
    }
}

static void test_destroy_null(void)
{
    /* Must not crash when *ctx is NULL. */
    cn_auth_ctx_t *ctx = NULL;
    cn_auth_destroy(&ctx);
    EXPECT(ctx == NULL);
}

/* --------------------------------------------------------------------------
 * Functional tests
 * -------------------------------------------------------------------------- */

static void test_init_and_header(void)
{
    const char *token = "secret-token-abc123";
    cn_auth_ctx_t *ctx = NULL;

    cn_err_t rc = cn_auth_init(&ctx, token);
    EXPECT_EQ(rc, CN_OK);
    EXPECT(ctx != NULL);
    if (ctx == NULL) return;

    char buf[CN_AUTH_TOKEN_MAX + 8];
    rc = cn_auth_get_header(ctx, buf, sizeof(buf));
    EXPECT_EQ(rc, CN_OK);

    /* Must start with "Bearer " and include the full token. */
    EXPECT(strncmp(buf, "Bearer ", 7) == 0);
    EXPECT(strcmp(buf + 7, token) == 0);

    cn_auth_destroy(&ctx);
    EXPECT(ctx == NULL);
}

static void test_empty_token_rejected(void)
{
    cn_auth_ctx_t *ctx = NULL;
    cn_err_t rc = cn_auth_init(&ctx, "");
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

static void test_max_length_token(void)
{
    /* CN_AUTH_TOKEN_MAX includes the NUL, so the maximum valid token is
     * CN_AUTH_TOKEN_MAX - 1 characters long. */
    char token[CN_AUTH_TOKEN_MAX];
    make_token(token, CN_AUTH_TOKEN_MAX - 1);

    cn_auth_ctx_t *ctx = NULL;
    cn_err_t rc = cn_auth_init(&ctx, token);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        char buf[CN_AUTH_TOKEN_MAX + 8];
        rc = cn_auth_get_header(ctx, buf, sizeof(buf));
        EXPECT_EQ(rc, CN_OK);
        EXPECT(strcmp(buf + 7, token) == 0);
        cn_auth_destroy(&ctx);
    }
}

static void test_token_too_long_rejected(void)
{
    /* CN_AUTH_TOKEN_MAX characters (no NUL) is one byte over the limit. */
    char token[CN_AUTH_TOKEN_MAX + 1];
    make_token(token, CN_AUTH_TOKEN_MAX);

    cn_auth_ctx_t *ctx = NULL;
    cn_err_t rc = cn_auth_init(&ctx, token);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(ctx == NULL);
}

static void test_get_header_overflow(void)
{
    const char *token = "short-token";
    cn_auth_ctx_t *ctx = NULL;

    cn_err_t rc = cn_auth_init(&ctx, token);
    EXPECT_EQ(rc, CN_OK);
    if (ctx == NULL) return;

    /* Buffer too small to hold "Bearer " + token + NUL. */
    char tiny[4];
    rc = cn_auth_get_header(ctx, tiny, sizeof(tiny));
    EXPECT_EQ(rc, CN_ERR_OVERFLOW);

    cn_auth_destroy(&ctx);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("test_auth\n");

    RUN_TEST(test_init_null_ctx);
    RUN_TEST(test_init_null_token);
    RUN_TEST(test_get_header_null_ctx);
    RUN_TEST(test_get_header_null_buf);
    RUN_TEST(test_destroy_null);
    RUN_TEST(test_init_and_header);
    RUN_TEST(test_empty_token_rejected);
    RUN_TEST(test_max_length_token);
    RUN_TEST(test_token_too_long_rejected);
    RUN_TEST(test_get_header_overflow);

    return TEST_RESULT();
}
