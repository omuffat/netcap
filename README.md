# netcap

A cross-platform network capture agent for Linux, macOS, and Windows.

netcap runs as an OS daemon (systemd / launchd / Windows Service) and continuously writes
rotating `.pcap` files to disk for every configured network interface.
Savefiles can be uploaded to an HTTPS endpoint manually or automatically on rotation.

---

## Features

- Continuous packet capture via **libpcap** (Linux/macOS) or **Npcap** (Windows)
- Per-interface **ring-buffer** memory-mapping for zero-copy writes
- Time-based **savefile rotation** with configurable count limits
- **BPF filter** per interface
- **Upload** to an HTTPS endpoint — manual (`netcap-ctl upload`) or automatic on rotation
- Optional **gzip compression** before upload
- **mTLS** support (client certificate + key)
- Automatic **BPF exclusion** of upload traffic
- Control via **IPC** (`netcap-ctl`)
- **TOML** configuration file; all keys optional except interface names
- Privilege drop after pcap handles are open (Linux: `cap_set_proc`)

---

## Platform support

| Platform | Daemon integration | Capture library |
|----------|--------------------|-----------------|
| Linux    | systemd            | libpcap         |
| macOS    | launchd            | libpcap         |
| Windows  | Windows Service    | Npcap           |

---

## Build requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| CMake      | ≥ 3.18  | |
| C compiler | C17     | GCC or Clang on POSIX; MSVC or Clang-cl on Windows |
| libpcap    | any     | `libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL |
| Npcap SDK  | any     | Windows only — set `CMAKE_PREFIX_PATH` to the SDK root |
| libcurl    | ≥ 7.85  | Must be built with TLS support (OpenSSL, GnuTLS, or Schannel) |
| zlib       | any     | For optional gzip compression of uploads |
| libcap     | any     | Linux only — for `CAP_NET_RAW` drop |

---

## Building

```bash
# Clone
git clone https://github.com/your-org/netcap.git
cd netcap

# Configure — Debug uses repository-relative paths (safe for development)
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Configure — Release uses OS production paths
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build

# Run tests
cd build && ctest --output-on-failure
```

On Windows, point CMake to the Npcap SDK before configuring:

```cmd
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:\npcap-sdk
```

---

## Quick start (development)

```bash
# Copy and edit the example configuration
cp netcap.toml.example netcap.toml
# Edit netcap.toml: set the interface name under [[interfaces]]

# Create the directories used in dev mode
mkdir -p rings captures

# Run the daemon (requires CAP_NET_RAW on Linux)
sudo ./build/service/netcapd

# In another terminal — check the service is alive
./build/cli/netcap-ctl ping

# Show capture statistics
./build/cli/netcap-ctl status
```

Savefiles appear in `./captures/` named `netcap_<iface>_<timestamp>.pcap`.

---

## netcap-ctl command reference

```
netcap-ctl [--config <path>] <command> [arguments]

IPC commands (require the service to be running):
  ping              Verify the service is alive.
  status            Print per-interface capture statistics.
  start <iface>     Start capture on a network interface.
  stop  <iface>     Stop capture on a network interface.
  reload            Restart the service with the current config.

Local commands:
  config check      Load and validate the configuration file.
  upload <file>     Upload a savefile to the configured endpoint.

Options:
  --config <path>   Path to the TOML configuration file.
```

---

## Configuration

All service settings live in a single TOML file.

| Platform | Default path |
|----------|-------------|
| Linux / macOS | `/etc/netcap/netcap.toml` |
| Windows | `C:\ProgramData\netcap\netcap.toml` |
| Development | `./netcap.toml` |

See [`netcap.toml.example`](netcap.toml.example) for an annotated reference and
[`docs/configuration.md`](docs/configuration.md) for the full key reference.

```bash
# Validate the configuration file at any time
netcap-ctl config check
```

---

## Upload

Upload is optional. When `endpoint_url` and `auth_token` are both set in
`[upload]`, files can be pushed to an HTTPS endpoint:

```bash
# Manual upload
netcap-ctl upload captures/netcap_eth0_2026_06_29_12_00_00.pcap

# Automatic upload on rotation — set  auto = true  in [upload]
```

See [`docs/upload.md`](docs/upload.md) for TLS, mTLS, compression, and retry configuration.

---

## Architecture

```
+-------------------+     IPC (Unix socket / Named Pipe)     +-------------+
|      netcapd      | <------------------------------------- |  netcap-ctl |
|      (daemon)     |                                        +-------------+
+--------+----------+
         |
         +-- pcap thread (iface 0) --> ring_eth0.bin --> savefile worker (0)
         +-- pcap thread (iface 1) --> ring_eth1.bin --> savefile worker (1)
         |
         +-- upload worker (single thread, optional)
```

| Directory   | Contents |
|-------------|----------|
| `core/`     | Ring buffer, pcap capture, BPF filter, pcap writer, IPC, logging |
| `service/`  | OS daemon, savefile rotation, upload queue |
| `uploader/` | HTTP POST client, gzip compression, retry logic |
| `config/`   | TOML parser (tomlc99), validation, configuration structs |
| `gui/`      | Systray stubs (Windows/macOS — not yet implemented) |
| `cli/`      | `netcap-ctl` control tool |
| `tests/`    | Unit tests |
| `third_party/tomlc99/` | Vendored TOML parser (MIT, CK Tan) |

---

## Security

- TLS 1.3 minimum for all uploads; peer and host verification always enabled.
- `CAP_NET_RAW` is dropped immediately after all pcap handles are open.
- The configuration file is written with mode `0600` to protect `auth_token`.
- Upload traffic can be excluded from capture automatically (BPF exclusion).

---

## Maintained by

netcap is developed and maintained by
[Comoe Networks](https://comoe-networks.com),
with development assistance from [Claude Code](https://claude.ai/code)
(Anthropic).

---

## License

BSD 2-Clause License. See [LICENSE](https://github.com/omuffat/netcap/blob/main/LICENSE) for details.
