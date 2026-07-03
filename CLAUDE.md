# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

netcap is a cross-platform network capture agent (Windows/macOS/Linux) based on libpcap/Npcap.

---

## Language — mandatory, no exception

**All content in this project must be written in English.**

This rule applies to every artifact without exception: source file comments, header and
implementation files, `CMakeLists.txt` comments, configuration file keys and inline comments,
IPC protocol field names, log messages, error strings, commit messages, and all documentation.

**This rule also applies to Claude Code outputs**: every generated file, comment, and string
literal must be in English.

---

## Build and test

```bash
# Configure (Release — production paths)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Configure (Debug — repository-relative paths, CN_DEV_BUILD defined)
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# Run all tests
ctest --test-dir build --output-on-failure

# Run a single test binary
./build/tests/test_ring
```

On Windows, set `CMAKE_PREFIX_PATH` to the Npcap SDK root before configuring.

Required compiler flags (enforced in `CMakeLists.txt`):
```
-std=c17 -Wall -Wextra -Werror -Wformat-security -fstack-protector-strong
```

### Development vs. production paths (`CN_DEV_BUILD`)

`CMAKE_BUILD_TYPE=Debug` defines the compile-time flag `CN_DEV_BUILD=1`.
When set, all `CN_DEFAULT_*` path macros in `config/config.h` point to
directories **relative to the repository root** (`./rings`, `./captures`,
`/tmp/netcap.sock`), so development and testing never touch system paths.

`CMAKE_BUILD_TYPE=Release` (or any other type) uses OS-conventional
production paths:

| Platform | `config file` | `ring_dir` | `savefile_dir` | `ipc_socket_path` |
|----------|--------------|-----------|---------------|-----------------|
| Linux | `/etc/netcap/netcap.toml` | `/var/lib/netcap/rings` | `/usr/share/netcap/captures` | `/run/netcap/netcap.sock` |
| macOS | `/etc/netcap/netcap.toml` | `/Library/Application Support/netcap/rings` | `/Library/Application Support/netcap/captures` | `/var/run/netcap/netcap.sock` |
| Windows | `C:\ProgramData\netcap\netcap.toml` | `C:\ProgramData\netcap\rings` | `C:\Program Files\netcap\data\captures` | `\\.\pipe\netcap` |
| Dev (all) | `./netcap.toml` | `./rings` | `./captures` | `/tmp/netcap.sock` (Win: `\\.\pipe\netcap`) |

All paths can be overridden by setting the corresponding key in the TOML
config file. The Windows and macOS installers offer a directory picker that
writes the chosen `savefile_dir` back to the config file. On Linux, all
paths are changed directly in `/etc/netcap/netcap.toml`.

The service daemon accepts an optional `--config <path>` argument to load
a config file from a non-default location. When the argument is absent,
`CN_DEFAULT_CONFIG_PATH` (`config/config.h`) is used.

macOS note: `/etc` on macOS resolves to `/private/etc`. Using the same
`/etc/netcap/` path on both Linux and macOS keeps scripts and documentation
consistent across platforms.

---

## Architecture

```
+-------------------+     IPC (Unix socket / Named Pipe)     +-------------+
|      Service      | <------------------------------------- |     GUI     |
|      (daemon)     |                                        |  (systray)  |
+--------+----------+                                        +-------------+
         |
         +-- pcap thread (iface 0) --> ring_eth0.bin --> msync_worker(0)
         +-- pcap thread (iface 1) --> ring_eth1.bin --> msync_worker(1)
         |   ...
         +-- shared upload worker pool (uploads are strictly per-interface)
```

| Directory   | Role                                                              |
|-------------|-------------------------------------------------------------------|
| `core/`     | Ring buffer mmap, pcap capture, BPF filter, pcap writer           |
| `service/`  | OS daemon: systemd (Linux), launchd (macOS), Windows Service      |
| `uploader/` | HTTP client, chunker, authentication                              |
| `config/`   | TOML parser (tomlc99), validation, configuration structs          |
| `gui/`      | Systray: Windows (Win32/Qt) and macOS (Cocoa/Qt)                  |
| `cli/`      | `netcap-ctl` — service control via IPC                            |
| `tests/`    | Unit tests per module                                             |

### Third-party libraries

tomlc99 is **vendored** in `third_party/tomlc99/` (MIT licence, CK Tan).
Do not install it system-wide; the CMake build uses the in-tree copy exclusively.
When updating tomlc99, replace `third_party/tomlc99/toml.h` and
`third_party/tomlc99/toml.c` and commit both files.

### Savefile output (always active)

For every active interface a `.pcap` file is written to `savefile_dir`.
Files rotate by time (`savefile_rotation_secs`, default 180 s). When
`savefile_max_count` is reached the oldest file for that interface is
deleted before a new one is opened (circular rotation). Incomplete files
created before a clean service stop are kept.

Filename format: `netcap_<interface>_<YYYY>_<MM>_<DD>_<HH>_<mm>_<SS>.pcap`
where the timestamp is the moment the file was opened.

### Upload (optional, user-triggered)

Upload is enabled only when **both** `upload.endpoint_url` (must start
with `https://`) and `upload.auth_token` are non-empty in the config.
Use `cn_upload_is_enabled()` (`config/config.h`) to test at runtime.
Upload is always user-triggered (GUI / CLI); automatic upload is reserved
for a future version.

### Automatic BPF exclusion of upload traffic

When upload is enabled and `upload.capture_upload_traffic = false`
(the default), the capture layer resolves the hostname from `endpoint_url`
to its IP address(es) at service start and prepends `not host <ip>` to
each interface's effective BPF filter.

- The exclusion is IP-only (port 443 filtering is a planned future enhancement).
- Resolution is one-time at startup (no periodic refresh).
- If DNS resolution fails: the service starts, savefiles continue normally,
  and the user is warned (systray notification on Windows/macOS; log entry
  on Linux). The unresolved exclusion is skipped for that session.
- The injected exclusion is invisible to the TOML file; it is computed and
  applied in the capture layer only.

### Service startup ordering

The service must not begin packet capture until the OS network stack is
fully available:
- **Linux (systemd)**: `After=network-online.target`
- **macOS (launchd)**: appropriately deferred via `WaitForDebugger` / network
  checks in the daemon itself
- **Windows Service**: `SERVICE_DELAYED_AUTO_START` with dependency on the
  network provider

### Ring buffer

One `ring_<iface>.bin` file per captured network interface, memory-mapped via `mmap`
(POSIX) or `MapViewOfFile` (Windows). One pcap thread writes into the ring; one
`msync_worker` flushes to disk. The upload worker pool is shared, but each interface has
its own uploads — data from two different interfaces must never be mixed in a single upload.

### IPC — Service to GUI

- **Linux/macOS**: Unix domain socket.
- **Windows**: Named Pipe.
- Protocol: length-prefixed binary messages defined in `core/ipc.h`.

### OS integration

- **Linux**: systemd service, no GUI — configuration via TOML file only.
- **macOS**: launchd service, systray GUI (Cocoa or Qt).
- **Windows**: Windows Service, systray GUI (Win32 or Qt).

### Language boundary

Code in `core/` and `service/` is pure C (`-std=c17`). Code in `gui/` may be C++
(Qt, Cocoa bindings) and is compiled separately.

---

## Naming conventions — mandatory, no exception

| Category                               | Prefix  | Example                                |
|----------------------------------------|---------|----------------------------------------|
| Internal types (struct, typedef, enum) | `cn_`   | `cn_ring_t`, `cn_err_t`                |
| Internal functions                     | `cn_`   | `cn_ring_init()`                       |
| Internal macros and constants          | `CN_`   | `CN_RING_SIZE_MAX`                     |
| External library symbols               | none    | `pcap_open_live()`, `curl_easy_init()` |

External library symbols (`pcap_*`, `curl_*`, `pthread_*`, `CURLOPT_*`, etc.) **never**
receive the `cn_`/`CN_` prefix.

---

## Comments — mandatory

### Public functions (declared in a `.h`)

```c
/**
 * @brief Initialize a ring buffer for the given interface.
 *
 * Maps ring_<iface>.bin into memory, creating it if needed.
 * Size must be a multiple of the system page size.
 *
 * @security Caller must have dropped CAP_NET_RAW if pcap handles are already
 *           open. Path must be validated against CN_PATH_MAX by the caller.
 *
 * @param[out] ring  Structure to initialize. Must not be NULL.
 * @param[in]  path  Absolute path of the ring file. Must not be NULL.
 * @param[in]  size  Ring size in bytes. Must be <= CN_RING_SIZE_MAX.
 *
 * @return CN_OK on success.
 * @return CN_ERR_INVAL if any parameter is invalid.
 * @return CN_ERR_IO    if file creation or mapping fails.
 */
cn_err_t cn_ring_init(cn_ring_t *ring, const char *path, size_t size)
    __attribute__((warn_unused_result));
```

### Static internal functions

At minimum one line — role and preconditions:

```c
/* Flush dirty ring pages to disk. Precondition: ring != NULL and ring->mapped == true. */
static cn_err_t flush_dirty_pages(cn_ring_t *ring) { ... }
```

### Struct fields

Comment non-obvious fields inline:

```c
typedef struct {
    uint8_t  *base;        /* Base address of the mmap mapping. */
    size_t    size;        /* Total ring size in bytes. */
    uint64_t  write_head;  /* Write index (modulo size), written only by the pcap thread. */
    uint64_t  read_head;   /* Read index (modulo size), written only by msync_worker. */
    int       fd;          /* File descriptor for ring_<iface>.bin. */
    bool      mapped;      /* true if mmap is active; false if uninitialized or failed. */
} cn_ring_t;
```

---

## Security — non-negotiable rules

### 1. Return type and warn_unused_result

Every `cn_*` function returns `cn_err_t __attribute__((warn_unused_result))`.
Never silently ignore a `cn_err_t` — `-Werror` will catch it at compile time.

### 2. Forbidden string functions

| Forbidden              | Mandatory replacement                        |
|------------------------|----------------------------------------------|
| `strcpy`, `strcat`     | `cn_strlcpy()` — implemented in `core/str.c` |
| `sprintf`              | `snprintf()` with return value check         |
| `gets`                 | `fgets()` with explicit size                 |
| `scanf("%s", ...)`     | `scanf("%<N>s", ...)` or `fgets()`           |

### 3. No VLA

Variable Length Arrays are forbidden. All sizes are `CN_*` constants from `core/constants.h`.

### 4. Pointer validation

Every pointer parameter is checked `!= NULL` before any other operation.

### 5. Size validation

Every size parameter is validated against its associated `CN_*_MAX` constant.

### 6. CAP_NET_RAW drop

Dropped via `cap_set_proc()` in `service/caps.c` as soon as all pcap handles are open.
Apply the equivalent least-privilege model on Windows.

### 7. Packet data is untrusted

Data from `pcap_next_ex()` is network-originated and untrusted. It must never be
copied without first checking against `CN_PKT_SIZE_MAX`:

```c
if (header->caplen > CN_PKT_SIZE_MAX) return CN_ERR_INVAL;
memcpy(dst, pkt_data, header->caplen);
```

### 8. TLS for uploads

TLS 1.3 minimum, no fallback. `CURLOPT_SSL_VERIFYPEER = 1L` and
`CURLOPT_SSL_VERIFYHOST = 2L` must never be disabled, including in debug builds.

---

## Error handling

`cn_err_t` is defined in `core/constants.h`. Always use the named constants; never
use raw integers (`-1`, `0`) in place of `CN_ERR_*` values.

```c
typedef enum {
    CN_OK           =  0,
    CN_ERR_INVAL    = -1,  /* Invalid or NULL parameter. */
    CN_ERR_IO       = -2,  /* Input/output error. */
    CN_ERR_NOMEM    = -3,  /* Memory allocation failed. */
    CN_ERR_OVERFLOW = -4,  /* Size overflow. */
    CN_ERR_PERM     = -5,  /* Permission denied. */
    CN_ERR_NET      = -6,  /* Network or TLS error. */
    CN_ERR_TIMEOUT  = -7,  /* Operation timed out. */
} cn_err_t;
```

---

## Pre-commit checklist

- [ ] All new internal symbols follow the `cn_`/`CN_` prefix convention.
- [ ] All new `cn_*` functions return `cn_err_t __attribute__((warn_unused_result))`.
- [ ] No `strcpy`, `sprintf`, `gets`, `strcat`, or `scanf("%s")` introduced.
- [ ] No VLA introduced.
- [ ] Every pointer parameter checked `!= NULL` at function entry.
- [ ] Every size parameter validated against its `CN_*_MAX` constant.
- [ ] Packet data checked against `CN_PKT_SIZE_MAX` before any `memcpy`.
- [ ] TLS: `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` unchanged.
- [ ] Public functions documented with a full `/** */` block (description, Security, @param, returns).
- [ ] Static functions have at least a one-line comment (role + preconditions).
- [ ] All comments, log messages, error strings, and commit messages are in English.
- [ ] Every new optional TOML field has a matching `CN_DEFAULT_*` macro in `config/config.h` and is applied in `cn_config_init()`.
- [ ] `cn_upload_is_enabled()` is used (not raw string comparisons) wherever upload availability is tested.
- [ ] New file-system paths follow the `CN_DEV_BUILD` / production split.
- [ ] Third-party code (tomlc99) is never modified; update by replacing files in `third_party/tomlc99/`.
- [ ] Build passes with no warnings under `-Wall -Wextra -Werror`.
- [ ] `ctest` passes with no failures.
