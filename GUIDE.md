# Hermit User Guide

Hermit is a lightweight sandbox that runs build commands with filesystem and
network isolation. It uses Linux user namespaces (no root required), Landlock
MAC policies, and optionally pasta for user-mode networking.

## Installation

```sh
cd platform/hermit
cargo build --release
# optional: copy to a directory on $PATH
cp target/release/hermit ~/.local/bin/
```

### Optional dependencies

| Tool | Required for | Install |
|------|-------------|---------|
| pasta (passt) | `--net pasta` | `apt install passt` or https://passt.top |
| sni-proxy | `--allowed-hosts` | `cargo install --path ../sni-proxy` |

## Quick start

```sh
# Run a command in the sandbox (host networking, filesystem isolation)
hermit -- echo hello

# Specify which directory gets read-write access
hermit --project-dir /path/to/project -- make

# Pass through extra directories
hermit --passthrough /opt/toolchain -- cargo build
```

## CLI reference

```
hermit [OPTIONS] -- <COMMAND>...
```

| Flag | Default | Description |
|------|---------|-------------|
| `--project-dir <DIR>` | `.` | Directory with read-write access inside the sandbox |
| `--passthrough <DIR>` | _(none)_ | Extra read-write directory (repeatable) |
| `--net <MODE>` | `host` | Network mode: `host`, `isolate`, or `pasta` |
| `--allowed-hosts <HOSTS>` | _(none)_ | Comma-separated hostnames for SNI proxy (requires `--net pasta`) |
| `-v` / `--verbose` | off | Verbosity: `-v` info, `-vv` debug, `-vvv` trace |

## Filesystem isolation

By default hermit creates a fresh mount namespace:

- **`$HOME`** is an empty tmpfs. Writes do not persist.
- **`/tmp`** is an ephemeral tmpfs. Writes do not persist.
- **`--project-dir`** is bind-mounted read-write. Writes persist.
- **`--passthrough`** directories are bind-mounted read-write. Writes persist.
- Everything else on the filesystem is read-only (enforced by Landlock).

### Home-files config

You can selectively populate `$HOME` inside the sandbox by creating a config
file at `<project-dir>/.hermit/home-files` or `~/.hermit/home-files`:

```
# Copy a snapshot (read-only inside sandbox)
copy .gitconfig

# Bind-mount read-only (live, but immutable)
read .ssh

# Bind-mount read-write (live, writes persist)
pass .cargo/registry
```

Set `HERMIT_HOME_FILES` to override with a single config file.

## Network modes

### `--net host` (default)

Shares the host network. No isolation.

### `--net isolate`

Empty network namespace. Only the loopback interface exists. All outbound
connections fail. Good for hermetic builds.

### `--net pasta`

User-mode networking via [pasta/passt](https://passt.top). Creates a TAP
device with DHCP in the sandbox, translating L2 traffic to host L4 sockets.
The sandbox gets full internet access through the host.

### `--net pasta --allowed-hosts`

Same as `--net pasta`, but also launches an **sni-proxy** alongside pasta.
The proxy listens on `127.0.0.1:1443` and only allows HTTPS connections to
the listed hostnames.

```sh
hermit --net pasta --allowed-hosts crates.io,github.com -- cargo build
```

> **Note:** In this release, the proxy is started but traffic is not yet
> transparently routed through it. Routing is a follow-up.

## Smoke tests

These commands verify that hermit is working correctly. Run them in order.

### 1. Basic execution

```sh
hermit -- echo "hello from sandbox"
# Expected: prints "hello from sandbox"
```

### 2. Exit code forwarding

```sh
hermit -- sh -c "exit 42"
echo $?
# Expected: 42
```

### 3. Filesystem isolation

```sh
# Project-dir writes persist
DIR=$(mktemp -d)
hermit --project-dir "$DIR" -- sh -c "echo persisted > $DIR/smoke_test"
cat "$DIR/smoke_test"
# Expected: prints "persisted"

# /tmp writes do NOT persist (ephemeral tmpfs)
hermit --project-dir "$DIR" -- sh -c 'echo gone > /tmp/hermit_smoke_test'
cat /tmp/hermit_smoke_test
# Expected: file does not exist
rm -r "$DIR"
```

### 4. Landlock blocks writes outside allowed dirs

```sh
hermit --project-dir /tmp -- touch /etc/hermit_test
# Expected: "Permission denied" or "Read-only file system"
```

### 5. Network isolation

```sh
hermit --net isolate --project-dir /tmp -- sh -c 'ls /sys/class/net/'
# Expected: only "lo"
```

### 6. Pasta networking

Requires `pasta` installed.

```sh
hermit --net pasta --project-dir /tmp -- sh -c 'ls /sys/class/net/'
# Expected: "lo" plus a tap interface (e.g. "tap0")
```

### 7. SNI proxy startup

Requires both `pasta` and `sni-proxy` installed.

```sh
hermit -v --net pasta --allowed-hosts example.com --project-dir /tmp -- echo proxy_ok
# Expected: prints "proxy_ok", verbose output shows sni-proxy starting and stopping
```

## Running the test suite

```sh
# Unit tests (always work, no special dependencies)
cargo test --lib

# Integration tests (some tests skip if pasta/sni-proxy not installed)
cargo test --test integration_test

# All tests
cargo test
```
