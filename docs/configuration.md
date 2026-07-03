# Configuration reference

All netcap settings are stored in a single TOML file.

## Default paths

| Platform    | Path |
|-------------|------|
| Linux       | `/etc/netcap/netcap.toml` |
| macOS       | `/etc/netcap/netcap.toml` |
| Windows     | `C:\ProgramData\netcap\netcap.toml` |
| Development | `./netcap.toml` (repository root) |

The daemon accepts `--config <path>` to load a file from a non-default location.

Validate the file at any time without restarting the service:

```bash
netcap-ctl config check
```

---

## Top-level keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `log_level` | integer | `1` | `0` = ERROR, `1` = WARN, `2` = INFO, `3` = DEBUG |
| `device` | string | *(hostname)* | Short hostname sent as `X-Netcap-Device` in upload requests. When absent, `gethostname()` is used. Never the FQDN. |
| `ring_dir` | string | OS default | Directory for ring buffer files (`ring_<iface>.bin`). |
| `savefile_dir` | string | OS default | Directory where `.pcap` savefiles are written. |
| `savefile_rotation_secs` | integer | `180` | Rotation interval in seconds. Range: 60–86400. |
| `savefile_max_count` | integer | `10` | Maximum savefiles retained per interface. When the limit is reached, the oldest file is deleted before a new one is opened. Range: 1–1000. |

### Production default paths

| Platform | `ring_dir` | `savefile_dir` |
|----------|-----------|----------------|
| Linux | `/var/lib/netcap/rings` | `/usr/share/netcap/captures` |
| macOS | `/Library/Application Support/netcap/rings` | `/Library/Application Support/netcap/captures` |
| Windows | `C:\ProgramData\netcap\rings` | `C:\Program Files\netcap\data\captures` |

---

## `[[interfaces]]`

One block per network interface. Multiple blocks are allowed.
Omitting this section entirely is valid — the service starts but does not
capture until interfaces are added via `netcap-ctl start`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | **required** | OS interface name (e.g. `eth0`, `en0`, `Ethernet`). |
| `enabled` | boolean | `true` | `false` = configured but not started at service launch. |
| `ring_size` | integer | `67108864` | Ring buffer size in bytes. Must be a power-of-two multiple of the system page size. Default: 64 MiB. |
| `snaplen` | integer | `65535` | Maximum bytes captured per packet (full packet by default). |
| `bpf_filter` | string | `""` | libpcap BPF filter expression. Empty = capture everything. |

### Example

```toml
[[interfaces]]
name       = "eth0"
enabled    = true
bpf_filter = "ip"

[[interfaces]]
name       = "eth1"
enabled    = false
snaplen    = 1500
bpf_filter = "tcp port 443"
```

---

## `[upload]`

Upload is **disabled** when either `endpoint_url` or `auth_token` is absent.
Both must be set to enable any upload functionality.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `endpoint_url` | string | — | HTTPS endpoint. Must start with `https://`. |
| `auth_token` | string | — | Bearer token sent in the `Authorization` header. |
| `auto` | boolean | `false` | When `true`, each fully-rotated savefile is pushed to the upload queue automatically. Files closed at service stop are never auto-uploaded. |
| `compress` | boolean | `false` | When `true`, savefiles are gzip-compressed in memory before upload. `Content-Encoding: gzip` is set on the request. Files on disk are never modified. |
| `capture_upload_traffic` | boolean | `false` | When `false` (default), the upload endpoint hostname is resolved at startup and a `not host <ip>` BPF exclusion is prepended to every interface filter so that upload traffic is not captured. |
| `retry_max` | integer | `3` | Maximum retry attempts on transient failure (`CN_ERR_NET`, `CN_ERR_TIMEOUT`). IO and memory errors are not retried. |
| `retry_delay_ms` | integer | `1000` | Initial backoff before the first retry in milliseconds. Doubles on each attempt, capped at 30 s. |
| `chunk_size` | integer | `1048576` | Reserved for future chunked-upload support. Not used in the current single-shot POST implementation. |
| `worker_count` | integer | `2` | Reserved for future parallel upload support. Currently a single worker thread is used regardless of this value. |

### HTTP headers sent on every upload

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <auth_token>` |
| `Content-Type` | `application/octet-stream` |
| `Content-Encoding` | `gzip` (only when `compress = true`) |
| `X-Netcap-Iface` | Capture interface name |
| `X-Netcap-Device` | Hostname (`device` key or `gethostname()`) |
| `X-Netcap-Filename` | Basename of the `.pcap` file |

---

## `[upload.tls]`

Optional TLS overrides. When absent, libcurl uses the system trust store and
no client certificate is presented.

TLS 1.3 is the minimum version. `CURLOPT_SSL_VERIFYPEER` and
`CURLOPT_SSL_VERIFYHOST` are always enabled and cannot be disabled.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ca_cert_path` | string | `""` | Path to a custom CA certificate bundle (PEM). Empty = use the system trust store. |
| `client_cert_path` | string | `""` | Client certificate for mutual TLS (mTLS). Must be set together with `client_key_path`. |
| `client_key_path` | string | `""` | Client private key for mTLS. Must be set together with `client_cert_path`. |

### Common pitfall — commented-out section headers

tomlc99 silently ignores keys that appear outside their section. If `[upload]`
or `[upload.tls]` is accidentally commented out, the keys beneath it land at
the wrong level and are silently dropped. `netcap-ctl config check` detects
and reports this pattern.

---

## Savefile filename format

```
netcap_<interface>_<YYYY>_<MM>_<DD>_<HH>_<mm>_<SS>.pcap
```

The timestamp is the local time at which the file was opened.

Example: `netcap_eth0_2026_06_29_14_30_00.pcap`
