# Hermit User Guide

Hermit is a lightweight sandbox that runs build commands with filesystem and
network isolation. It uses Linux user namespaces (no root required) and Landlock
MAC policies.

## Installation

```sh
cd platform/hermit
cargo build --release
# optional: copy to a directory on $PATH
cp target/release/hermit ~/.local/bin/
```

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
hermit run    [OPTIONS] -- <COMMAND>...
hermit sign   --cert <PEM> --key <PEM> <CONFIG> [--output <PATH>]
hermit verify [--trust-dir <DIR>] <CONFIG_URL>
hermit keygen --cert <PEM> --key <PEM> [--subject <CN>] [--force]
```

`hermit run` flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--config <URL>` | _(required)_ | `file://` or `https://` URL of the signed hermit config TOML |
| `--allow-unsigned` | off | Accept a config without a `[signature]` section (local development) |
| `--project-dir <DIR>` | `.` | Directory with read-write access inside the sandbox |
| `--block-log <PATH>` | `$XDG_STATE_HOME/hermit/blocks.jsonl` | JSON-lines log of blocked DNS / TLS / HTTP events |
| `--no-block-log` | off | Disable block-event logging entirely |
| `--log-file <PATH>` | stderr | Where hermit's own info/debug output goes (sandboxed command's output is unaffected) |
| `-v` / `--verbose` | off | Verbosity: `-v` info, `-vv` debug, `-vvv` trace |

Everything after `--` is the command (and arguments) to run inside the sandbox.

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

Network mode is set in `[sandbox]` of the config, not via CLI flag.

### `net = "host"` (default)

Shares the host network. No isolation.

### `net = "isolate"` with no access rules

Empty network namespace. Only the loopback interface exists. All outbound
connections fail. Good for hermetic builds.

### `net = "isolate"` with `[[access_rule]]` entries

Empty network namespace plus hermit-managed proxies for:

- **DNS** on 127.0.0.1:53 inside the sandbox. Allowed queries are
  forwarded to a real resolver (configurable via `[dns]`, default
  `1.1.1.1:53`) and the answers are cached so downstream relays can
  map a destination IP back to the hostname it was resolved from.
- **HTTPS / TLS** on port 443, handled by an SNI-reading MITM proxy
  on `127.0.0.1:1443` (DNAT redirected). Every rule with
  `mechanism = "mitm"` terminates TLS with an ephemeral CA and
  enforces `path_prefix` / `methods`. `mechanism = "sni"` rules
  splice bytes after the ClientHello with no interception.
- **HTTP** on port 80, handled on `127.0.0.1:1080`. The proxy
  understands origin-form requests, absolute-form requests (what
  `HTTP_PROXY`-aware clients send), and `CONNECT` tunnels (what
  `HTTPS_PROXY`-aware clients send).
- **Bypass** TCP / UDP relays for non-HTTP protocols — see the
  `mechanism = "bypass"` section below.

The child process receives these environment variables automatically
so proxy-aware clients route through hermit explicitly:

```
HTTP_PROXY=http://127.0.0.1:1080
HTTPS_PROXY=http://127.0.0.1:1080
NO_PROXY=localhost,127.0.0.1,::1
```

(and the lowercase `http_proxy` / `https_proxy` / `no_proxy` forms,
because ecosystems disagree on casing.)

Blocked DNS / TLS / HTTP / bypass events are recorded to
`$XDG_STATE_HOME/hermit/blocks.jsonl` by default; see `--block-log`.

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

## Config format

Hermit loads a TOML file referenced by `--config <URL>` (schemes:
`file://` or `https://`). Every config must either carry a `[signature]`
section produced by `hermit sign` and verified against a cert in
`~/.hermit/keys/` (overridable via `HERMIT_TRUST_DIR`), or be loaded
under `hermit run --allow-unsigned` for local development.

Top-level sections:

| Section | Purpose |
|---|---|
| `include = ["<url>", ...]` | Other configs to merge into this one (see below) |
| `[sandbox]` | Network mode + `passthrough` dirs |
| `[dns]` | Upstream DNS resolver for allowed queries |
| `[[home_file]]` | `copy` / `pass` / `read` actions applied to a `$HOME` path |
| `[[access_rule]]` | Allow a host (or literal IP) through the proxy; choose `mitm`, `sni`, or `bypass` |
| `[[port_forward]]` | Extra TCP ports to intercept (`https` → MITM, `http` → HTTP proxy) |
| `[[rule]]` + `[credential.<name>]` | Credential-injection matcher + credential source |
| `[signature]` | Detached ed25519 signature over the preceding content |

### `[dns]` — upstream resolver

```toml
[dns]
upstream = "1.1.1.1:53"   # default; override with any ip:port resolver
```

Allowed DNS queries (those whose hostname matches an `[[access_rule]]`)
are forwarded to this resolver. The real answer is relayed to the
child and A/AAAA records are tapped into an in-memory cache that the
bypass relays consult to map a destination IP back to a hostname.
Denied queries return REFUSED; upstream failures return SERVFAIL.

### `[[access_rule]]` — the allowlist

Each rule either keys off a **hostname** (`host = "…"`) or a literal
**IP** (`ip = "…"`) — set exactly one. Hostname rules cover the
common DNS-driven case; IP rules cover services reached without a
DNS query hermit sees.

The `mechanism` field picks the enforcement strategy:

| Mechanism | Listener | What it does | Compatible fields |
|---|---|---|---|
| `"mitm"` (default) | HTTPS/HTTP proxy | Terminates TLS with an ephemeral CA, parses HTTP, can inject credentials, enforces `path_prefix` / `methods` | `host`, `path_prefix`, `methods` |
| `"sni"` | HTTPS proxy | Reads the TLS ClientHello and splices bytes — no termination, no payload visibility. Use for cert-pinning clients | `host` only |
| `"bypass"` | Dedicated TCP or UDP relay on `(protocol, port)` | SO_ORIGINAL_DST / IP_RECVORIGDSTADDR yields the real destination, the DNS cache (or IP rule) authorizes, then bytes splice | `host` or `ip`; `protocol` and `port` required |

Validation happens at config-load time:

- `path_prefix` / `methods` on `"sni"` or `"bypass"` → rejected
  (those fields require plaintext visibility).
- `"bypass"` requires `protocol = "tcp"|"udp"` and `port = <number>`.
- Bypass `port` 80 or 443 → rejected (those are claimed by the
  MITM/HTTP proxies; for certificate-pinned HTTPS use `"sni"`).
- `ip = "…"` with `"mitm"` or `"sni"` → rejected (both strategies
  fundamentally key on hostnames).

Examples:

```toml
# Plain MITM — the default when `mechanism` is omitted.
[[access_rule]]
host = "api.github.com"
path_prefix = "/repos/"
methods = ["GET", "POST"]

# SNI cut-through for a certificate-pinning client.
[[access_rule]]
host = "pinned.example"
mechanism = "sni"

# Bypass UDP 88 for Kerberos. A single entry covers both IPv4 and
# IPv6 — hermit installs parallel nft rules and relay listeners in
# each family.
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
port = 88

# Literal-IP bypass (the KDC is reached by address, not via DNS).
[[access_rule]]
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88
```

### `include` — composing configs

`include` lets a config share rules with others by pulling their content
in at load time. A typical layout:

```toml
# /etc/hermit/shared-rules.toml  (signed, owned by an admin)
[[access_rule]]
host = "api.github.com"

[[access_rule]]
host = "registry.npmjs.org"
```

```toml
# project.toml  (signed, owned by the developer)
include = ["file:///etc/hermit/shared-rules.toml"]

[sandbox]
net = "isolate"

[[access_rule]]                # extends the shared set
host = "my-private-registry.example"
```

Rules:

- **URLs**: each entry is `file://` or `https://` (same schemes hermit
  accepts for `--config`). Relative URLs resolve against the including
  file's URL.
- **Signatures**: every fetched file is verified independently against
  the trust dir. `--allow-unsigned` skips verification for the whole
  chain. `verify <url>` walks the chain and fails if any link is
  unsigned or tampered.
- **Cycles**: `A → B → A` is rejected at load time. Include depth is
  capped at 16 to catch pathological chains.
- **Merge order**: depth-first in declaration order. Each include is
  fully merged *before* the including file's own entries.
- **Arrays** (`home_file`, `access_rule`, `port_forward`, `rule`):
  concatenated in merge order — `include_1 ++ include_2 ++ ... ++ own`.
  For consumers where order matters (e.g. first-match injection rules),
  includes take precedence over the including file's own entries.
- **Scalars and tables** (`sandbox`, `credential.<name>`): last writer
  wins. The including file is merged last, so it overrides any value an
  include provided.
- **Signatures don't merge**: `[signature]` applies only to its own
  file during verification, and is dropped during merge.

## Running the test suite

```sh
# Unit tests (always work, no special dependencies)
cargo test --lib

# Integration tests
cargo test --test integration_test

# All tests
cargo test
```
