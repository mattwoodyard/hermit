//! Credential acquisition with TTL caching.
//!
//! Three sources are supported:
//!   - Env   — read an environment variable once (no expiry, it can't change)
//!   - File  — read a file's contents, trimmed of trailing newline
//!   - Script — exec a command and read stdout; cached for `ttl_secs`
//!
//! A `CredentialResolver` holds a map of name → `Source` plus an async-safe
//! cache of resolved values. `get(name)` returns the current value,
//! re-running the script if the cached entry has expired.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::process::Command;

/// How a credential is acquired.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Source {
    Env {
        name: String,
    },
    File {
        path: PathBuf,
    },
    Script {
        command: Vec<String>,
        #[serde(default = "default_ttl")]
        ttl_secs: u64,
    },
}

fn default_ttl() -> u64 {
    300
}

/// A credential declaration: how to acquire it and how to inject it.
#[derive(Debug, Clone, Deserialize)]
pub struct Credential {
    pub source: Source,
    #[serde(default)]
    pub inject: Vec<InjectAction>,
}

/// A single header-set action. `{cred}` in `value` is substituted with
/// the acquired credential value.
#[derive(Debug, Clone, Deserialize)]
pub struct InjectAction {
    pub header: String,
    pub value: String,
}

struct CachedValue {
    value: String,
    expires_at: Option<Instant>,
}

pub struct CredentialResolver {
    credentials: HashMap<String, Credential>,
    cache: Mutex<HashMap<String, CachedValue>>,
}

impl CredentialResolver {
    pub fn new(credentials: HashMap<String, Credential>) -> Self {
        Self {
            credentials,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_credential(&self, name: &str) -> Option<&Credential> {
        self.credentials.get(name)
    }

    /// Acquire the value for the named credential. For script sources,
    /// serves from cache if still fresh, otherwise re-runs the script.
    pub async fn resolve(&self, name: &str, match_host: Option<&str>) -> Result<String> {
        let cred = self
            .credentials
            .get(name)
            .with_context(|| format!("unknown credential: {name}"))?;

        // Serve from cache if fresh
        if let Some(cached) = self.cache_lookup(name) {
            return Ok(cached);
        }

        // Acquire + decide cache policy. A returned expiry of `None` means
        // "cache forever" (Env/File can't change at runtime); `Some(exp)`
        // means cache until that instant; we skip storing entirely when
        // the source is explicitly non-cacheable (Script ttl_secs=0).
        let (value, expires_at, should_cache) = match &cred.source {
            Source::Env { name: var } => {
                let v = std::env::var(var)
                    .with_context(|| format!("env var {var} not set"))?;
                (v, None, true)
            }
            Source::File { path } => {
                let v = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("reading credential file {path:?}"))?;
                (v.trim_end_matches(['\n', '\r']).to_string(), None, true)
            }
            Source::Script { command, ttl_secs } => {
                let v = run_script(command, match_host).await?;
                if *ttl_secs == 0 {
                    (v, None, false)
                } else {
                    (v, Some(Instant::now() + Duration::from_secs(*ttl_secs)), true)
                }
            }
        };

        if should_cache {
            self.cache_store(name, &value, expires_at);
        }
        Ok(value)
    }

    fn cache_lookup(&self, name: &str) -> Option<String> {
        // Recover from a poisoned lock: cache ops are atomic (plain
        // HashMap insert/get) so no invariant carries across panics.
        // Panicking here would take down every concurrent credential
        // resolver call.
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let entry = cache.get(name)?;
        match entry.expires_at {
            None => Some(entry.value.clone()),
            Some(exp) if Instant::now() < exp => Some(entry.value.clone()),
            _ => None,
        }
    }

    fn cache_store(&self, name: &str, value: &str, expires_at: Option<Instant>) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(
            name.to_string(),
            CachedValue {
                value: value.to_string(),
                expires_at,
            },
        );
    }

    /// Drop the cached value for `name`, if any. The next
    /// [`resolve`](Self::resolve) call re-runs the source.
    /// Used for OAuth-style flows where the proxy sees a 401
    /// from upstream and wants the next request to fetch a
    /// fresh access token instead of replaying the stale one.
    /// No-op when the cache had no entry (or only contained an
    /// already-expired one).
    pub fn invalidate(&self, name: &str) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.remove(name);
    }
}

/// Environment variables passed through to credential scripts.
///
/// We `env_clear()` before invoking so the script does NOT inherit
/// the parent's env wholesale — hermit may have been launched with
/// other secrets in the env (`GITHUB_TOKEN`, `AWS_*`, etc.) and a
/// credential helper for service A should not be able to read
/// service B's token. Only the variables on this allowlist survive.
///
/// The list covers what generic Unix tooling typically needs:
///   - `PATH` so `Command::new("aws")` can resolve via $PATH
///     (the alternative — forcing absolute paths in every config —
///     is hostile)
///   - `HOME` so tools find their dotfiles (`~/.aws/config`,
///     `~/.config/gcloud`, `~/.password-store`, ...)
///   - `USER`, `LOGNAME` for tools that key cache state on user
///   - `LANG`, `LC_ALL`, `LANGUAGE` so script output isn't
///     mangled by an unset locale
///   - `TZ` so timestamp-emitting helpers stay consistent
///   - `TERM` so a misbehaving helper that touches a terminal
///     doesn't crash on an unset value
///
/// Tool-specific configuration vars (`AWS_PROFILE`, `OP_SESSION_*`,
/// `CLOUDSDK_*`) are intentionally NOT passed through — wrap the
/// command in `["sh", "-c", "AWS_PROFILE=foo exec aws ..."]` if
/// you need them.
const SCRIPT_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LANGUAGE",
    "TZ",
    "TERM",
];

async fn run_script(command: &[String], match_host: Option<&str>) -> Result<String> {
    if command.is_empty() {
        bail!("credential script has empty command");
    }
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    // Pin the script's environment: clear the parent's, then
    // re-add only the allowlisted keys (and HERMIT_MATCH_HOST).
    // This prevents inadvertent leakage of one credential into
    // another credential's helper script.
    cmd.env_clear();
    for key in SCRIPT_ENV_ALLOWLIST {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    if let Some(host) = match_host {
        cmd.env("HERMIT_MATCH_HOST", host);
    }
    let out = cmd
        .output()
        .await
        .with_context(|| format!("spawning credential script {:?}", command))?;
    if !out.status.success() {
        bail!(
            "credential script {:?} failed: {}",
            command,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let s = String::from_utf8(out.stdout).context("credential script stdout not utf-8")?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

