/*
 * test_ipc.c — unit tests for core/ipc.c
 *
 * Tests: NULL guards, PING/PONG roundtrip, STATUS_REQ/STATUS_RESP roundtrip.
 *
 * A pthread-based server thread is used so that client and server operate in
 * the same process without needing fork(). The socket is created in /tmp.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "test_harness.h"
#include "../core/ipc.h"
#include "../core/constants.h"

#define TEST_SOCKET_PATH "/tmp/netcap_test_ipc.sock"

/* --------------------------------------------------------------------------
 * NULL / invalid parameter tests (no server needed)
 * -------------------------------------------------------------------------- */

static void test_server_create_null(void)
{
    cn_err_t rc = cn_ipc_server_create(NULL, TEST_SOCKET_PATH);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_server_create_null_path(void)
{
    cn_ipc_server_t *srv = NULL;
    cn_err_t rc = cn_ipc_server_create(&srv, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(srv == NULL);
}

static void test_client_connect_null(void)
{
    cn_err_t rc = cn_ipc_client_connect(NULL, TEST_SOCKET_PATH);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_client_connect_null_path(void)
{
    cn_ipc_client_t *c = NULL;
    cn_err_t rc = cn_ipc_client_connect(&c, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
    EXPECT(c == NULL);
}

static void test_server_destroy_null(void)
{
    cn_ipc_server_t *srv = NULL;
    cn_ipc_server_destroy(&srv);  /* Must not crash. */
    EXPECT(srv == NULL);
}

static void test_client_destroy_null(void)
{
    cn_ipc_client_t *c = NULL;
    cn_ipc_client_destroy(&c);  /* Must not crash. */
    EXPECT(c == NULL);
}

/* --------------------------------------------------------------------------
 * Server thread context
 * -------------------------------------------------------------------------- */

typedef struct {
    const char *socket_path;
    cn_err_t    create_rc;   /* CN_OK if server created successfully. */
    /* Results for PING/PONG test. */
    cn_err_t ping_recv_rc;
    cn_err_t pong_send_rc;
    /* Results for STATUS roundtrip test. */
    cn_err_t status_req_rc;
    cn_err_t status_resp_rc;
} server_ctx_t;

/* Server thread for PING/PONG: accept one PING, reply PONG, exit. */
static void *server_ping_thread(void *arg)
{
    server_ctx_t *ctx = arg;

    cn_ipc_server_t *srv = NULL;
    ctx->create_rc = cn_ipc_server_create(&srv, ctx->socket_path);
    if (ctx->create_rc != CN_OK) return NULL;

    uint8_t buf[CN_IPC_MSG_MAX];
    cn_ipc_msg_type_t type;
    uint32_t len = 0;

    /* Loop until we receive a real message or a non-timeout error.
     * The first call may return CN_ERR_TIMEOUT after accepting the new
     * connection before client data arrives in the same select() window. */
    do {
        ctx->ping_recv_rc = cn_ipc_server_recv(srv, &type, buf,
                                               CN_IPC_MSG_MAX, &len);
    } while (ctx->ping_recv_rc == CN_ERR_TIMEOUT);
    if (ctx->ping_recv_rc == CN_OK && type == CN_IPC_MSG_PING) {
        ctx->pong_send_rc = cn_ipc_server_send(srv, CN_IPC_MSG_PONG,
                                               NULL, 0);
    }
    cn_ipc_server_destroy(&srv);
    return NULL;
}

/* Server thread for STATUS roundtrip: accept STATUS_REQ, reply STATUS_RESP. */
static void *server_status_thread(void *arg)
{
    server_ctx_t *ctx = arg;

    cn_ipc_server_t *srv = NULL;
    ctx->create_rc = cn_ipc_server_create(&srv, ctx->socket_path);
    if (ctx->create_rc != CN_OK) return NULL;

    uint8_t buf[CN_IPC_MSG_MAX];
    cn_ipc_msg_type_t type;
    uint32_t recv_len = 0;

    do {
        ctx->status_req_rc = cn_ipc_server_recv(srv, &type, buf,
                                                CN_IPC_MSG_MAX, &recv_len);
    } while (ctx->status_req_rc == CN_ERR_TIMEOUT);
    if (ctx->status_req_rc == CN_OK && type == CN_IPC_MSG_STATUS_REQ) {
        /* Build a minimal status response with one interface. */
        cn_ipc_status_t status;
        memset(&status, 0, sizeof(status));
        status.iface_count = 1;
        strncpy(status.ifaces[0].iface_name, "eth0", CN_IFACE_NAME_MAX - 1);
        status.ifaces[0].capturing   = 1;
        status.ifaces[0].pkts_written = 42;

        ctx->status_resp_rc = cn_ipc_server_send(srv, CN_IPC_MSG_STATUS_RESP,
                                                 &status, sizeof(status));
    }
    cn_ipc_server_destroy(&srv);
    return NULL;
}

/* --------------------------------------------------------------------------
 * Helper: small sleep to let the server thread reach accept().
 * -------------------------------------------------------------------------- */

#include <time.h>

static void sleep_ms(int ms)
{
    struct timespec ts = { 0, (long)ms * 1000000L };
    nanosleep(&ts, NULL);
}

/* --------------------------------------------------------------------------
 * PING / PONG roundtrip test
 * -------------------------------------------------------------------------- */

static void test_ping_pong(void)
{
    /* Remove stale socket from a previous run. */
    unlink(TEST_SOCKET_PATH);

    server_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.socket_path = TEST_SOCKET_PATH;

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_ping_thread, &ctx) != 0) {
        EXPECT(0); return;
    }

    /* Give the server thread time to bind and listen. */
    sleep_ms(50);

    cn_ipc_client_t *client = NULL;
    cn_err_t rc = cn_ipc_client_connect(&client, TEST_SOCKET_PATH);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) {
        pthread_join(tid, NULL);
        return;
    }

    /* Send PING. */
    rc = cn_ipc_client_send(client, CN_IPC_MSG_PING, NULL, 0);
    EXPECT_EQ(rc, CN_OK);

    /* Receive PONG. */
    uint8_t buf[CN_IPC_MSG_MAX];
    cn_ipc_msg_type_t type;
    uint32_t len = 0;
    rc = cn_ipc_client_recv(client, &type, buf, CN_IPC_MSG_MAX, &len);
    EXPECT_EQ(rc, CN_OK);
    EXPECT_EQ((long long)type, (long long)CN_IPC_MSG_PONG);
    EXPECT_EQ((long long)len, 0LL);

    cn_ipc_client_destroy(&client);
    pthread_join(tid, NULL);

    /* Check server-side results. */
    EXPECT_EQ(ctx.create_rc,    CN_OK);
    EXPECT_EQ(ctx.ping_recv_rc, CN_OK);
    EXPECT_EQ(ctx.pong_send_rc, CN_OK);

    unlink(TEST_SOCKET_PATH);
}

/* --------------------------------------------------------------------------
 * STATUS roundtrip test
 * -------------------------------------------------------------------------- */

static void test_status_roundtrip(void)
{
    unlink(TEST_SOCKET_PATH);

    server_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.socket_path = TEST_SOCKET_PATH;

    pthread_t tid;
    if (pthread_create(&tid, NULL, server_status_thread, &ctx) != 0) {
        EXPECT(0); return;
    }

    sleep_ms(50);

    cn_ipc_client_t *client = NULL;
    cn_err_t rc = cn_ipc_client_connect(&client, TEST_SOCKET_PATH);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) {
        pthread_join(tid, NULL);
        return;
    }

    /* Send STATUS_REQ. */
    rc = cn_ipc_client_send(client, CN_IPC_MSG_STATUS_REQ, NULL, 0);
    EXPECT_EQ(rc, CN_OK);

    /* Receive STATUS_RESP. */
    uint8_t buf[CN_IPC_MSG_MAX];
    cn_ipc_msg_type_t type;
    uint32_t len = 0;
    rc = cn_ipc_client_recv(client, &type, buf, CN_IPC_MSG_MAX, &len);
    EXPECT_EQ(rc, CN_OK);
    EXPECT_EQ((long long)type, (long long)CN_IPC_MSG_STATUS_RESP);
    EXPECT_EQ((long long)len, (long long)sizeof(cn_ipc_status_t));

    if (rc == CN_OK && len == sizeof(cn_ipc_status_t)) {
        cn_ipc_status_t status;
        memcpy(&status, buf, sizeof(status));
        EXPECT_EQ((long long)status.iface_count, 1LL);
        EXPECT(strcmp(status.ifaces[0].iface_name, "eth0") == 0);
        EXPECT(status.ifaces[0].capturing == 1);
        EXPECT_EQ((long long)status.ifaces[0].pkts_written, 42LL);
    }

    cn_ipc_client_destroy(&client);
    pthread_join(tid, NULL);

    EXPECT_EQ(ctx.create_rc,      CN_OK);
    EXPECT_EQ(ctx.status_req_rc,  CN_OK);
    EXPECT_EQ(ctx.status_resp_rc, CN_OK);

    unlink(TEST_SOCKET_PATH);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("test_ipc\n");

    RUN_TEST(test_server_create_null);
    RUN_TEST(test_server_create_null_path);
    RUN_TEST(test_client_connect_null);
    RUN_TEST(test_client_connect_null_path);
    RUN_TEST(test_server_destroy_null);
    RUN_TEST(test_client_destroy_null);
    RUN_TEST(test_ping_pong);
    RUN_TEST(test_status_roundtrip);

    return TEST_RESULT();
}
