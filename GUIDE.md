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
hermit [OPTIONS] -- <COMMAND>...
```

| Flag | Default | Description |
|------|---------|-------------|
| `--project-dir <DIR>` | `.` | Directory with read-write access inside the sandbox |
| `--passthrough <DIR>` | _(none)_ | Extra read-write directory (repeatable) |
| `--net <MODE>` | `host` | Network mode: `host` or `isolate` |
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
| `[[home_file]]` | `copy` / `pass` / `read` actions applied to a `$HOME` path |
| `[[access_rule]]` | Allow a host / path prefix / HTTP methods through the proxy |
| `[[port_forward]]` | Extra TCP ports to intercept (`https` → MITM, `http` → HTTP proxy) |
| `[[rule]]` + `[credential.<name>]` | Credential-injection matcher + credential source |
| `[signature]` | Detached ed25519 signature over the preceding content |

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
