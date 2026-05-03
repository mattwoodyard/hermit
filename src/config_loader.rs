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
pub(crate) const MAX_INCLUDE_DEPTH: usize = 16;

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

/// Wrappers around `config_loader`'s private items for the
/// dedicated test crate. Off by default; `hermit-tests` flips on
/// the `__test_internals` feature in its `[dependencies]` entry.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    pub const MAX_INCLUDE_DEPTH: usize = super::MAX_INCLUDE_DEPTH;
}
