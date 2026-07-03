/*
 * test_config.c — unit tests for config/parser.c and config/validator.c
 *
 * Tests: cn_parser_load defaults, roundtrip save/load, missing required
 * fields, validator range checks, cn_upload_is_enabled helper.
 *
 * Uses mkstemp() to write temporary TOML files.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_harness.h"
#include "../config/parser.h"
#include "../config/validator.h"
#include "../config/config.h"
#include "../core/constants.h"

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/* Write a string to a new temp file; caller must unlink. */
static int write_toml(char *path_tmpl, const char *content)
{
    int fd = mkstemp(path_tmpl);
    if (fd < 0) return -1;
    size_t len = strlen(content);
    if (write(fd, content, len) != (ssize_t)len) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* --------------------------------------------------------------------------
 * NULL guard tests
 * -------------------------------------------------------------------------- */

static void test_parser_load_null_config(void)
{
    cn_err_t rc = cn_parser_load(NULL, "/tmp/x");
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_parser_load_null_path(void)
{
    cn_config_t cfg;
    cn_err_t rc = cn_parser_load(&cfg, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_parser_save_null_config(void)
{
    cn_err_t rc = cn_parser_save(NULL, "/tmp/x");
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_parser_save_null_path(void)
{
    cn_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cn_err_t rc = cn_parser_save(&cfg, NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

static void test_validator_null(void)
{
    cn_err_t rc = cn_validator_check(NULL);
    EXPECT_EQ(rc, CN_ERR_INVAL);
}

/* --------------------------------------------------------------------------
 * Default value tests
 * -------------------------------------------------------------------------- */

static void test_defaults_no_interfaces(void)
{
    /* Minimal valid TOML with no [interfaces] and no [upload]. */
    const char *toml =
        "log_level = 1\n"
        "savefile_dir = \"/tmp\"\n"
        "ring_dir = \"/tmp\"\n";

    char path[] = "/tmp/netcap_test_cfg_XXXXXX";
    if (write_toml(path, toml) != 0) { EXPECT(0); return; }

    cn_config_t cfg;
    cn_err_t rc = cn_parser_load(&cfg, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        EXPECT_EQ((long long)cfg.iface_count, 0LL);
        EXPECT_EQ((long long)cfg.log_level, 1LL);
        /* Upload disabled when endpoint_url is empty. */
        EXPECT(cn_upload_is_enabled(&cfg.upload) == false);
    }
    unlink(path);
}

static void test_defaults_applied(void)
{
    /* Single interface — verify default ring_size, snaplen, etc. */
    const char *toml =
        "savefile_dir = \"/tmp\"\n"
        "ring_dir = \"/tmp\"\n"
        "[[interfaces]]\n"
        "name = \"lo\"\n";

    char path[] = "/tmp/netcap_test_cfg_XXXXXX";
    if (write_toml(path, toml) != 0) { EXPECT(0); return; }

    cn_config_t cfg;
    cn_err_t rc = cn_parser_load(&cfg, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        EXPECT_EQ((long long)cfg.iface_count, 1LL);
        EXPECT(strcmp(cfg.interfaces[0].name, "lo") == 0);
        EXPECT_EQ((long long)cfg.interfaces[0].ring_size,
                  (long long)CN_DEFAULT_RING_SIZE);
        EXPECT_EQ((long long)cfg.interfaces[0].snaplen,
                  (long long)CN_DEFAULT_SNAPLEN);
        EXPECT(cfg.interfaces[0].enabled == CN_DEFAULT_IFACE_ENABLED);
        EXPECT(cfg.interfaces[0].bpf_filter[0] == '\0');
        EXPECT_EQ((long long)cfg.savefile_rotation_secs,
                  (long long)CN_DEFAULT_SAVEFILE_ROTATION_SECS);
        EXPECT_EQ((long long)cfg.savefile_max_count,
                  (long long)CN_DEFAULT_SAVEFILE_MAX_COUNT);
    }
    unlink(path);
}

/* --------------------------------------------------------------------------
 * Save / load roundtrip
 * -------------------------------------------------------------------------- */

static void test_roundtrip(void)
{
    /* Build a non-default config, save it, reload it, compare fields. */
    cn_config_t orig;
    memset(&orig, 0, sizeof(orig));

    orig.iface_count = 1;
    strncpy(orig.interfaces[0].name, "eth0", CN_IFACE_NAME_MAX - 1);
    orig.interfaces[0].ring_size = 8192;
    orig.interfaces[0].snaplen   = 256;
    orig.interfaces[0].enabled   = false;
    strncpy(orig.interfaces[0].bpf_filter, "tcp port 80",
            CN_BPF_FILTER_MAX - 1);

    strncpy(orig.ring_dir,     "/tmp", CN_PATH_MAX - 1);
    strncpy(orig.savefile_dir, "/tmp", CN_PATH_MAX - 1);
    orig.savefile_rotation_secs = 300;
    orig.savefile_max_count     = 5;
    orig.log_level              = 2;

    char path[] = "/tmp/netcap_test_cfg_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { EXPECT(0); return; }
    close(fd);

    cn_err_t rc = cn_parser_save(&orig, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    cn_config_t loaded;
    rc = cn_parser_load(&loaded, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    EXPECT_EQ((long long)loaded.iface_count, (long long)orig.iface_count);
    EXPECT(strcmp(loaded.interfaces[0].name, orig.interfaces[0].name) == 0);
    EXPECT_EQ((long long)loaded.interfaces[0].ring_size,
              (long long)orig.interfaces[0].ring_size);
    EXPECT_EQ((long long)loaded.interfaces[0].snaplen,
              (long long)orig.interfaces[0].snaplen);
    EXPECT(loaded.interfaces[0].enabled == orig.interfaces[0].enabled);
    EXPECT(strcmp(loaded.interfaces[0].bpf_filter,
                  orig.interfaces[0].bpf_filter) == 0);
    EXPECT_EQ((long long)loaded.savefile_rotation_secs,
              (long long)orig.savefile_rotation_secs);
    EXPECT_EQ((long long)loaded.savefile_max_count,
              (long long)orig.savefile_max_count);
    EXPECT_EQ((long long)loaded.log_level, (long long)orig.log_level);

    unlink(path);
}

static void test_roundtrip_with_upload(void)
{
    cn_config_t orig;
    memset(&orig, 0, sizeof(orig));

    strncpy(orig.ring_dir,              "/tmp", CN_PATH_MAX - 1);
    strncpy(orig.savefile_dir,          "/tmp", CN_PATH_MAX - 1);
    orig.savefile_rotation_secs = CN_DEFAULT_SAVEFILE_ROTATION_SECS;
    orig.savefile_max_count     = CN_DEFAULT_SAVEFILE_MAX_COUNT;
    orig.log_level              = CN_DEFAULT_LOG_LEVEL;

    strncpy(orig.upload.endpoint_url, "https://example.com/upload",
            CN_URL_MAX - 1);
    strncpy(orig.upload.auth_token, "tok123", CN_AUTH_TOKEN_MAX - 1);
    orig.upload.chunk_size    = 2 * 1024 * 1024;
    orig.upload.retry_max     = 5;
    orig.upload.retry_delay_ms = 500;
    orig.upload.worker_count  = 3;
    orig.upload.compress      = true;
    orig.upload.capture_upload_traffic = false;

    EXPECT(cn_upload_is_enabled(&orig.upload) == true);

    char path[] = "/tmp/netcap_test_cfg_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { EXPECT(0); return; }
    close(fd);

    cn_err_t rc = cn_parser_save(&orig, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    cn_config_t loaded;
    rc = cn_parser_load(&loaded, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    EXPECT(cn_upload_is_enabled(&loaded.upload) == true);
    EXPECT(strcmp(loaded.upload.endpoint_url, orig.upload.endpoint_url) == 0);
    EXPECT(strcmp(loaded.upload.auth_token,   orig.upload.auth_token)   == 0);
    EXPECT_EQ((long long)loaded.upload.chunk_size,
              (long long)orig.upload.chunk_size);
    EXPECT_EQ((long long)loaded.upload.retry_max,
              (long long)orig.upload.retry_max);
    EXPECT_EQ((long long)loaded.upload.worker_count,
              (long long)orig.upload.worker_count);
    EXPECT(loaded.upload.compress == orig.upload.compress);

    unlink(path);
}

/* --------------------------------------------------------------------------
 * Validator tests
 * -------------------------------------------------------------------------- */

/* Build a minimal valid config programmatically. */
static void make_valid_config(cn_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->ring_dir,     "/tmp", CN_PATH_MAX - 1);
    strncpy(cfg->savefile_dir, "/tmp", CN_PATH_MAX - 1);
    strncpy(cfg->device,       "testhost", CN_HOST_NAME_MAX - 1);
    cfg->savefile_rotation_secs = CN_DEFAULT_SAVEFILE_ROTATION_SECS;
    cfg->savefile_max_count     = CN_DEFAULT_SAVEFILE_MAX_COUNT;
    cfg->log_level              = CN_DEFAULT_LOG_LEVEL;
    /* iface_count = 0 is valid. */
}

static void test_validator_valid_no_ifaces(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    EXPECT_EQ(cn_validator_check(&cfg), CN_OK);
}

static void test_validator_valid_with_iface(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.iface_count = 1;
    strncpy(cfg.interfaces[0].name, "eth0", CN_IFACE_NAME_MAX - 1);
    cfg.interfaces[0].ring_size = CN_RING_SIZE_MIN;
    cfg.interfaces[0].snaplen   = 128;
    cfg.interfaces[0].enabled   = true;
    EXPECT_EQ(cn_validator_check(&cfg), CN_OK);
}

static void test_validator_empty_savefile_dir(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.savefile_dir[0] = '\0';
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_empty_ring_dir(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.ring_dir[0] = '\0';
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_rotation_too_low(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.savefile_rotation_secs = CN_SAVEFILE_ROTATION_SECS_MIN - 1;
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_rotation_too_high(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.savefile_rotation_secs = CN_SAVEFILE_ROTATION_SECS_MAX + 1;
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_iface_empty_name(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.iface_count = 1;
    cfg.interfaces[0].name[0] = '\0';
    cfg.interfaces[0].ring_size = CN_RING_SIZE_MIN;
    cfg.interfaces[0].snaplen   = 128;
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_iface_snaplen_zero(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.iface_count = 1;
    strncpy(cfg.interfaces[0].name, "eth0", CN_IFACE_NAME_MAX - 1);
    cfg.interfaces[0].ring_size = CN_RING_SIZE_MIN;
    cfg.interfaces[0].snaplen   = 0;
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_iface_ring_size_too_small(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.iface_count = 1;
    strncpy(cfg.interfaces[0].name, "eth0", CN_IFACE_NAME_MAX - 1);
    cfg.interfaces[0].ring_size = CN_RING_SIZE_MIN - 1;
    cfg.interfaces[0].snaplen   = 128;
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_upload_no_https(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    /* endpoint_url does not start with "https://". */
    strncpy(cfg.upload.endpoint_url, "http://example.com/upload",
            CN_URL_MAX - 1);
    strncpy(cfg.upload.auth_token, "tok", CN_AUTH_TOKEN_MAX - 1);
    cfg.upload.chunk_size    = CN_DEFAULT_CHUNK_SIZE;
    cfg.upload.worker_count  = 1;
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

static void test_validator_upload_mtls_cert_only(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    strncpy(cfg.upload.endpoint_url, "https://example.com/upload",
            CN_URL_MAX - 1);
    strncpy(cfg.upload.auth_token, "tok", CN_AUTH_TOKEN_MAX - 1);
    cfg.upload.chunk_size   = CN_DEFAULT_CHUNK_SIZE;
    cfg.upload.worker_count = 1;
    /* Set cert but not key — should fail. */
    strncpy(cfg.upload.tls.client_cert_path, "/etc/netcap/client.crt",
            CN_PATH_MAX - 1);
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

/* --------------------------------------------------------------------------
 * cn_upload_is_enabled helper
 * -------------------------------------------------------------------------- */

static void test_upload_enabled_both_set(void)
{
    cn_upload_config_t up;
    memset(&up, 0, sizeof(up));
    strncpy(up.endpoint_url, "https://example.com/upload", CN_URL_MAX - 1);
    strncpy(up.auth_token,   "mytoken",                    CN_AUTH_TOKEN_MAX - 1);
    EXPECT(cn_upload_is_enabled(&up) == true);
}

static void test_upload_enabled_no_url(void)
{
    cn_upload_config_t up;
    memset(&up, 0, sizeof(up));
    strncpy(up.auth_token, "mytoken", CN_AUTH_TOKEN_MAX - 1);
    EXPECT(cn_upload_is_enabled(&up) == false);
}

static void test_upload_enabled_no_token(void)
{
    cn_upload_config_t up;
    memset(&up, 0, sizeof(up));
    strncpy(up.endpoint_url, "https://example.com/upload", CN_URL_MAX - 1);
    EXPECT(cn_upload_is_enabled(&up) == false);
}

static void test_upload_enabled_null(void)
{
    EXPECT(cn_upload_is_enabled(NULL) == false);
}

/* --------------------------------------------------------------------------
 * device field tests
 * -------------------------------------------------------------------------- */

static void test_device_from_toml(void)
{
    /* device key present in TOML — must be used as-is. */
    const char *toml =
        "savefile_dir = \"/tmp\"\n"
        "ring_dir     = \"/tmp\"\n"
        "device       = \"myhost\"\n";

    char path[] = "/tmp/netcap_test_cfg_XXXXXX";
    if (write_toml(path, toml) != 0) { EXPECT(0); return; }

    cn_config_t cfg;
    cn_err_t rc = cn_parser_load(&cfg, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        EXPECT(strcmp(cfg.device, "myhost") == 0);
    }
    unlink(path);
}

static void test_device_fallback_gethostname(void)
{
    /* device key absent — parser must fall back to gethostname(). */
    const char *toml =
        "savefile_dir = \"/tmp\"\n"
        "ring_dir     = \"/tmp\"\n";

    char path[] = "/tmp/netcap_test_cfg_XXXXXX";
    if (write_toml(path, toml) != 0) { EXPECT(0); return; }

    cn_config_t cfg;
    cn_err_t rc = cn_parser_load(&cfg, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        /* After load, device must never be empty. */
        EXPECT(cfg.device[0] != '\0');
    }
    unlink(path);
}

static void test_device_roundtrip(void)
{
    /* Save a config with a device name, reload it, verify the value is kept. */
    cn_config_t orig;
    make_valid_config(&orig);
    strncpy(orig.device, "capture-box", CN_HOST_NAME_MAX - 1);

    char path[] = "/tmp/netcap_test_cfg_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { EXPECT(0); return; }
    close(fd);

    cn_err_t rc = cn_parser_save(&orig, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc != CN_OK) { unlink(path); return; }

    cn_config_t loaded;
    rc = cn_parser_load(&loaded, path);
    EXPECT_EQ(rc, CN_OK);
    if (rc == CN_OK) {
        EXPECT(strcmp(loaded.device, "capture-box") == 0);
    }
    unlink(path);
}

static void test_validator_empty_device(void)
{
    cn_config_t cfg;
    make_valid_config(&cfg);
    cfg.device[0] = '\0';
    EXPECT_EQ(cn_validator_check(&cfg), CN_ERR_INVAL);
}

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("test_config\n");

    RUN_TEST(test_parser_load_null_config);
    RUN_TEST(test_parser_load_null_path);
    RUN_TEST(test_parser_save_null_config);
    RUN_TEST(test_parser_save_null_path);
    RUN_TEST(test_validator_null);

    RUN_TEST(test_defaults_no_interfaces);
    RUN_TEST(test_defaults_applied);

    RUN_TEST(test_roundtrip);
    RUN_TEST(test_roundtrip_with_upload);

    RUN_TEST(test_validator_valid_no_ifaces);
    RUN_TEST(test_validator_valid_with_iface);
    RUN_TEST(test_validator_empty_savefile_dir);
    RUN_TEST(test_validator_empty_ring_dir);
    RUN_TEST(test_validator_rotation_too_low);
    RUN_TEST(test_validator_rotation_too_high);
    RUN_TEST(test_validator_iface_empty_name);
    RUN_TEST(test_validator_iface_snaplen_zero);
    RUN_TEST(test_validator_iface_ring_size_too_small);
    RUN_TEST(test_validator_upload_no_https);
    RUN_TEST(test_validator_upload_mtls_cert_only);

    RUN_TEST(test_upload_enabled_both_set);
    RUN_TEST(test_upload_enabled_no_url);
    RUN_TEST(test_upload_enabled_no_token);
    RUN_TEST(test_upload_enabled_null);

    RUN_TEST(test_device_from_toml);
    RUN_TEST(test_device_fallback_gethostname);
    RUN_TEST(test_device_roundtrip);
    RUN_TEST(test_validator_empty_device);

    return TEST_RESULT();
}
