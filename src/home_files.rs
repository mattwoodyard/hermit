//! Per-file directives that the runtime applies on top of the sandbox's
//! base mounts.
//!
//! These come from the `[[home_file]]` section of the signed TOML config
//! (parsed in `config.rs`). The line-based DSL parser that used to live
//! here was removed once the TOML schema became the single source of
//! truth — only the enum remains.

use std::path::PathBuf;

/// A directive from a `home_file` config section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeFileDirective {
    /// Copy a file or directory from real $HOME into the sandbox (read-only snapshot).
    Copy(PathBuf),
    /// Bind-mount (passthrough) a file or directory writably into the sandbox.
    Pass(PathBuf),
    /// Bind-mount a file or directory read-only into the sandbox (live, not a snapshot).
    Read(PathBuf),
    /// Mask the path inside the sandbox: the sandbox sees a
    /// zero-byte file (if the source is a file) or an empty
    /// directory (if the source is a directory) at this path,
    /// regardless of what's there on the host. Useful when a
    /// `Pass` or `Read` directive bind-mounts a parent
    /// directory but a *specific* child should not be visible
    /// — e.g. passing `~/.claude` while hiding
    /// `~/.claude/.credentials.json` so the sandbox can't
    /// recover the host's OAuth tokens.
    Hide(PathBuf),
    /// Bind-mount a host file/dir to a different path inside
    /// the sandbox. `path` is the namespace location the
    /// sandboxed process sees; `source` is where the bytes
    /// actually live on the host. Read-write — `Pass` shape,
    /// just with separate source vs destination paths. Use
    /// when the sandbox should see a credential or config at
    /// a known location but the host stores it elsewhere
    /// (e.g. sandbox's `~/.aws/credentials` ↔ host's
    /// `/etc/hermit/build-aws-creds`).
    Redirect { path: PathBuf, source: PathBuf },
}
