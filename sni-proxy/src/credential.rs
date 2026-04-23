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
}

async fn run_script(command: &[String], match_host: Option<&str>) -> Result<String> {
    if command.is_empty() {
        bail!("credential script has empty command");
    }
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn resolver_with(name: &str, source: Source) -> CredentialResolver {
        let mut m = HashMap::new();
        m.insert(
            name.to_string(),
            Credential {
                source,
                inject: vec![],
            },
        );
        CredentialResolver::new(m)
    }

    #[tokio::test]
    async fn resolves_env() {
        // SAFETY: tests run single-threaded inside this tokio runtime.
        unsafe { std::env::set_var("CRED_TEST_ENV", "secret-abc") };
        let r = resolver_with("k", Source::Env { name: "CRED_TEST_ENV".into() });
        let v = r.resolve("k", None).await.unwrap();
        assert_eq!(v, "secret-abc");
    }

    #[tokio::test]
    async fn resolves_file_trims_newline() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "tok-xyz").unwrap();
        let r = resolver_with("k", Source::File { path: f.path().to_path_buf() });
        let v = r.resolve("k", None).await.unwrap();
        assert_eq!(v, "tok-xyz");
    }

    #[tokio::test]
    async fn resolves_script_stdout() {
        let r = resolver_with(
            "k",
            Source::Script {
                command: vec!["/bin/echo".into(), "-n".into(), "from-script".into()],
                ttl_secs: 60,
            },
        );
        let v = r.resolve("k", None).await.unwrap();
        assert_eq!(v, "from-script");
    }

    #[tokio::test]
    async fn script_cache_hit_returns_cached_value() {
        // Script returns the current timestamp in nanos. If we call twice
        // within the TTL, we should get the same value (cache hit).
        let r = resolver_with(
            "k",
            Source::Script {
                command: vec!["/bin/sh".into(), "-c".into(), "date +%s%N".into()],
                ttl_secs: 60,
            },
        );
        let v1 = r.resolve("k", None).await.unwrap();
        let v2 = r.resolve("k", None).await.unwrap();
        assert_eq!(v1, v2, "cached value should be reused");
    }

    #[tokio::test]
    async fn script_ttl_zero_disables_cache() {
        let r = resolver_with(
            "k",
            Source::Script {
                command: vec!["/bin/sh".into(), "-c".into(), "date +%s%N".into()],
                ttl_secs: 0,
            },
        );
        let v1 = r.resolve("k", None).await.unwrap();
        // Sleep briefly so the timestamp advances
        tokio::time::sleep(Duration::from_millis(20)).await;
        let v2 = r.resolve("k", None).await.unwrap();
        assert_ne!(v1, v2, "ttl=0 should re-run the script each call");
    }

    #[tokio::test]
    async fn script_passes_match_host_env() {
        let r = resolver_with(
            "k",
            Source::Script {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo -n $HERMIT_MATCH_HOST".into(),
                ],
                ttl_secs: 0,
            },
        );
        let v = r.resolve("k", Some("api.example.com")).await.unwrap();
        assert_eq!(v, "api.example.com");
    }

    #[tokio::test]
    async fn script_failure_is_error() {
        let r = resolver_with(
            "k",
            Source::Script {
                command: vec!["/bin/sh".into(), "-c".into(), "exit 7".into()],
                ttl_secs: 60,
            },
        );
        let err = r.resolve("k", None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn unknown_credential_is_error() {
        let r = CredentialResolver::new(HashMap::new());
        let err = r.resolve("missing", None).await;
        assert!(err.is_err());
    }
}
