# Upload guide

netcap can push completed `.pcap` savefiles to an HTTPS endpoint.
Upload is entirely optional and is disabled until both `endpoint_url` and
`auth_token` are set in the `[upload]` section of the configuration file.

---

## Minimum configuration

```toml
[upload]
endpoint_url = "https://ingest.example.com/api/upload"
auth_token   = "your-secret-token"
```

Validate the configuration before restarting the service:

```bash
netcap-ctl config check
```

---

## Manual upload

Upload a single savefile on demand:

```bash
netcap-ctl upload /usr/share/netcap/captures/netcap_eth0_2026_06_29_14_30_00.pcap
```

The tool reads the endpoint URL and credentials from the configuration file.
It extracts the interface name from the filename and sends the file as a single
HTTP POST with the following headers:

```
Authorization:      Bearer <auth_token>
Content-Type:       application/octet-stream
X-Netcap-Iface:     eth0
X-Netcap-Device:    <hostname>
X-Netcap-Filename:  netcap_eth0_2026_06_29_14_30_00.pcap
```

---

## Automatic upload on rotation

When `auto = true`, every savefile that completes a full rotation cycle is
pushed to an in-process upload queue automatically. The service runs a single
background upload worker that drains the queue sequentially.

```toml
[upload]
endpoint_url = "https://ingest.example.com/api/upload"
auth_token   = "your-secret-token"
auto         = true
```

**Files that are NOT auto-uploaded:**

- The file open at the time of a service stop or crash. It is written and
  closed cleanly but never queued, because it was not fully rotated.
  Upload it manually if needed.
- Files that existed before the service started (no startup scan).

**Queue overflow:** the queue holds up to 64 pending files. If the queue is
full when a rotation completes, the new entry is dropped and a warning is
logged. The file remains on disk.

---

## Compression

```toml
[upload]
compress = true
```

When enabled, each file is gzip-compressed in memory before the POST.
`Content-Encoding: gzip` is added to the request. Files on disk are never
modified.

---

## Custom CA certificate

If your endpoint uses a certificate signed by a private CA:

```toml
[upload.tls]
ca_cert_path = "/etc/netcap/ca-bundle.pem"
```

The system trust store is used when `ca_cert_path` is empty or absent.

---

## Mutual TLS (mTLS)

To authenticate the client with a certificate:

```toml
[upload.tls]
ca_cert_path     = "/etc/netcap/ca-bundle.pem"
client_cert_path = "/etc/netcap/client.crt"
client_key_path  = "/etc/netcap/client.key"
```

Both `client_cert_path` and `client_key_path` must be set together or both
must be absent.

Protect the configuration file:

```bash
chmod 600 /etc/netcap/netcap.toml
```

---

## TLS security invariants

These settings are enforced in code and cannot be changed via configuration:

- TLS 1.3 minimum — no fallback to older versions.
- `CURLOPT_SSL_VERIFYPEER = 1` — certificate chain is always verified.
- `CURLOPT_SSL_VERIFYHOST = 2` — hostname is always verified against the certificate.

---

## Retry policy

Transient failures (`CN_ERR_NET`, `CN_ERR_TIMEOUT`) are retried up to
`retry_max` times (default: 3) with exponential backoff starting at
`retry_delay_ms` milliseconds (default: 1000 ms), doubling each attempt and
capped at 30 s.

Permanent failures (`CN_ERR_IO` — file not readable, `CN_ERR_NOMEM`) are
not retried.

A non-2xx HTTP response is treated as a permanent failure and is not retried.

```toml
[upload]
retry_max      = 5
retry_delay_ms = 2000
```

---

## Excluding upload traffic from capture

By default (`capture_upload_traffic = false`), the upload endpoint hostname
is resolved via DNS at service startup and a BPF exclusion is automatically
prepended to every interface's filter:

```
not host <resolved-ip> [and (<user-filter>)]
```

This prevents capture traffic from contaminating your savefiles. If DNS
resolution fails at startup, a warning is logged and capture continues without
the exclusion for that session.

To capture upload traffic intentionally:

```toml
[upload]
capture_upload_traffic = true
```
