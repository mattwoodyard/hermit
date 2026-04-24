//! Fetch config bytes from a URL. Supports `file://` and `https://`.
//!
//! Plain `http://` is intentionally *not* supported — network-fetched
//! configs always travel over TLS. Signature verification makes this
//! redundant in theory, but keeping the transport honest is cheap
//! defense-in-depth.
//!
//! This module also drives the `include = [...]` assembly path: see
//! [`assemble`], which recursively fetches, verifies, and merges included
//! configs into a single [`Config`].

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use url::Url;

use crate::config::Config;
use crate::signature;

/// Fetch the raw bytes referenced by `url`. Blocking — the caller is
/// expected to run this at startup, not inside a hot path.
pub fn fetch(url: &str) -> Result<Vec<u8>> {
    let parsed = Url::parse(url).with_context(|| format!("invalid config URL {url:?}"))?;
    match parsed.scheme() {
        "file" => fetch_file(&parsed),
        "https" => fetch_https(url),
        other => bail!("unsupported URL scheme {other:?} (only file:// and https:// are allowed)"),
    }
}

fn fetch_file(url: &Url) -> Result<Vec<u8>> {
    let path: PathBuf = url
        .to_file_path()
        .map_err(|_| anyhow::anyhow!("file URL must be absolute: {url}"))?;
    std::fs::read(&path).with_context(|| format!("reading config file {}", path.display()))
}

fn fetch_https(url: &str) -> Result<Vec<u8>> {
    let resp = reqwest::blocking::get(url)
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()
        .with_context(|| format!("non-2xx response from {url}"))?;
    let bytes = resp
        .bytes()
        .with_context(|| format!("reading body from {url}"))?;
    Ok(bytes.to_vec())
}

/// Governs how each fetched config's signature is handled when
/// assembling a config graph. `RequireSigned` verifies every file
/// independently against `trust_dir`; `AllowUnsigned` skips verification
/// entirely (and is *also* applied to transitively-included files).
pub enum TrustPolicy<'a> {
    RequireSigned { trust_dir: &'a Path },
    AllowUnsigned,
}

/// Maximum depth of the include graph. A sane ceiling that catches
/// runaway-chain configs without tripping any real use case.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Load the config at `root_url`, recursively resolving any `include =
/// [...]` references, and return a single merged [`Config`].
///
/// Every file is fetched via [`fetch`], has its signature checked per
/// `trust`, and is parsed with [`Config::parse`]. Relative URLs in an
/// include list are resolved against the including file's URL — for
/// `file://` that's path-relative, for `https://` that's URL-relative.
///
/// Cycles are detected (via the set of already-visited absolute URLs) and
/// rejected with a clear error.
pub fn assemble(root_url: &str, trust: &TrustPolicy<'_>) -> Result<Config> {
    let root = parse_absolute_url(root_url)?;
    let mut accumulator = Config::default();
    let mut visited: HashSet<String> = HashSet::new();
    assemble_into(&root, trust, &mut accumulator, &mut visited, 0)?;
    // Re-run config-level validation on the merged result — individual
    // files may each be valid but still produce e.g. duplicate port
    // forwards once concatenated.
    accumulator.validate_port_forwards()?;
    Ok(accumulator)
}

/// Recursive worker for [`assemble`]. Visits includes depth-first in
/// declaration order so the caller's `accumulator.merge_from` calls
/// happen in the order: include_1, include_1's includes, ...,
/// include_N, then finally the containing file itself.
fn assemble_into(
    url: &Url,
    trust: &TrustPolicy<'_>,
    accumulator: &mut Config,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_INCLUDE_DEPTH {
        bail!(
            "include depth limit {MAX_INCLUDE_DEPTH} exceeded at {}",
            url
        );
    }
    let key = url.as_str().to_string();
    if !visited.insert(key.clone()) {
        bail!("include cycle detected at {url}");
    }

    let bytes = fetch(url.as_str()).with_context(|| format!("fetching {url}"))?;
    if let TrustPolicy::RequireSigned { trust_dir } = trust {
        signature::verify(&bytes, trust_dir)
            .with_context(|| format!("verifying signature of {url}"))?;
    }
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{url}: config is not valid UTF-8"))?;
    let parsed = Config::parse(text).with_context(|| format!("parsing {url}"))?;

    // Depth-first: drain each include before folding `parsed` itself.
    // This yields the declared merge order (includes first, own last).
    for inc in &parsed.include {
        let child = url
            .join(inc)
            .with_context(|| format!("resolving include {inc:?} relative to {url}"))?;
        assemble_into(&child, trust, accumulator, visited, depth + 1)?;
    }
    accumulator.merge_from(parsed);
    Ok(())
}

/// Parse `s` as an absolute URL. `file://` and `https://` are accepted;
/// [`fetch`] will enforce the same restriction again, but we want to
/// surface "not a URL" and "unsupported scheme" early.
fn parse_absolute_url(s: &str) -> Result<Url> {
    let u = Url::parse(s).with_context(|| format!("invalid config URL {s:?}"))?;
    match u.scheme() {
        "file" | "https" => Ok(u),
        other => bail!("unsupported URL scheme {other:?} (only file:// and https:// are allowed)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rejects_http_scheme() {
        let err = fetch("http://example.com/config.toml").unwrap_err();
        assert!(format!("{err:#}").contains("unsupported URL scheme"));
    }

    #[test]
    fn rejects_unknown_scheme() {
        let err = fetch("ftp://example.com/c.toml").unwrap_err();
        assert!(format!("{err:#}").contains("unsupported URL scheme"));
    }

    #[test]
    fn rejects_malformed_url() {
        let err = fetch("not a url").unwrap_err();
        assert!(format!("{err:#}").contains("invalid config URL"));
    }

    #[test]
    fn reads_file_scheme() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "hello = 1\n").unwrap();
        let url = format!("file://{}", f.path().display());
        let bytes = fetch(&url).unwrap();
        assert_eq!(bytes, b"hello = 1\n");
    }

    #[test]
    fn file_scheme_reports_missing_path() {
        let err = fetch("file:///nonexistent/path/definitely/not/there.toml").unwrap_err();
        assert!(format!("{err:#}").contains("reading config file"));
    }

    // HTTPS end-to-end is covered at the integration-test layer where we
    // spin up a rustls server; doing it here would pull axum/hyper into
    // the unit-test graph.

    // ------------------------------------------------------------------
    // assemble() — include resolution
    // ------------------------------------------------------------------

    fn file_url(path: &std::path::Path) -> String {
        format!("file://{}", path.display())
    }

    #[test]
    fn assemble_merges_single_include() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared.toml");
        std::fs::write(&shared, r#"
[[access_rule]]
host = "shared.example"
"#).unwrap();

        let root = dir.path().join("root.toml");
        std::fs::write(&root, format!(r#"
include = ["{}"]

[[access_rule]]
host = "root.example"
"#, file_url(&shared))).unwrap();

        let cfg = assemble(&file_url(&root), &TrustPolicy::AllowUnsigned).unwrap();
        let rules = cfg.access_rules().unwrap();
        // Include merged first (shared), then root's own entries.
        assert_eq!(rules[0].hostname, "shared.example");
        assert_eq!(rules[1].hostname, "root.example");
    }

    #[test]
    fn assemble_resolves_relative_includes() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared.toml");
        std::fs::write(&shared, r#"[[access_rule]]
host = "rel.example"
"#).unwrap();
        let root = dir.path().join("root.toml");
        std::fs::write(&root, r#"include = ["shared.toml"]
"#).unwrap();

        let cfg = assemble(&file_url(&root), &TrustPolicy::AllowUnsigned).unwrap();
        assert_eq!(cfg.access_rules[0].host.as_deref(), Some("rel.example"));
    }

    #[test]
    fn assemble_detects_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        let b = dir.path().join("b.toml");
        std::fs::write(&a, format!(r#"include = ["{}"]"#, file_url(&b))).unwrap();
        std::fs::write(&b, format!(r#"include = ["{}"]"#, file_url(&a))).unwrap();

        let err = assemble(&file_url(&a), &TrustPolicy::AllowUnsigned).unwrap_err();
        assert!(
            format!("{err:#}").contains("cycle"),
            "expected cycle error, got: {err:#}"
        );
    }

    #[test]
    fn assemble_detects_deep_chain_limit() {
        // Build a chain a0 -> a1 -> a2 -> ... longer than MAX_INCLUDE_DEPTH.
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(MAX_INCLUDE_DEPTH + 2) {
            let this = dir.path().join(format!("a{}.toml", i));
            let next = dir.path().join(format!("a{}.toml", i + 1));
            std::fs::write(&this, format!(r#"include = ["{}"]"#, file_url(&next))).unwrap();
        }
        // Last file empty.
        let last = dir.path().join(format!("a{}.toml", MAX_INCLUDE_DEPTH + 2));
        std::fs::write(&last, "").unwrap();

        let root = dir.path().join("a0.toml");
        let err = assemble(&file_url(&root), &TrustPolicy::AllowUnsigned).unwrap_err();
        assert!(
            format!("{err:#}").contains("depth limit"),
            "expected depth-limit error, got: {err:#}"
        );
    }

    #[test]
    fn assemble_scalar_override_follows_merge_order() {
        // Shared says isolate; root says host. Root wins (merged last).
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared.toml");
        std::fs::write(&shared, "[sandbox]\nnet = \"isolate\"\n").unwrap();
        let root = dir.path().join("root.toml");
        std::fs::write(&root, format!(
            "include = [\"{}\"]\n[sandbox]\nnet = \"host\"\n",
            file_url(&shared)
        )).unwrap();

        let cfg = assemble(&file_url(&root), &TrustPolicy::AllowUnsigned).unwrap();
        assert_eq!(cfg.sandbox().net, crate::config::NetMode::Host);
    }

    #[test]
    fn assemble_scalar_inherited_from_include_when_root_silent() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared.toml");
        std::fs::write(&shared, "[sandbox]\nnet = \"isolate\"\n").unwrap();
        let root = dir.path().join("root.toml");
        std::fs::write(&root, format!("include = [\"{}\"]\n", file_url(&shared))).unwrap();

        let cfg = assemble(&file_url(&root), &TrustPolicy::AllowUnsigned).unwrap();
        assert_eq!(cfg.sandbox().net, crate::config::NetMode::Isolate);
    }

    #[test]
    fn assemble_rejects_cross_file_port_forward_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared.toml");
        std::fs::write(&shared, "[[port_forward]]\nport = 8443\n").unwrap();
        let root = dir.path().join("root.toml");
        std::fs::write(&root, format!(
            "include = [\"{}\"]\n[[port_forward]]\nport = 8443\n",
            file_url(&shared)
        )).unwrap();

        let err = assemble(&file_url(&root), &TrustPolicy::AllowUnsigned).unwrap_err();
        assert!(
            format!("{err:#}").contains("listed twice"),
            "expected duplicate-port error, got: {err:#}"
        );
    }

    #[test]
    fn assemble_rejects_unsupported_scheme_at_root() {
        let err = assemble("ftp://example.com/c.toml", &TrustPolicy::AllowUnsigned).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported URL scheme"));
    }
}
