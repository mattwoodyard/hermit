//! Fetch config bytes from a URL. Supports `file://` and `https://`.
//!
//! Plain `http://` is intentionally *not* supported — network-fetched
//! configs always travel over TLS. Signature verification makes this
//! redundant in theory, but keeping the transport honest is cheap
//! defense-in-depth.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use url::Url;

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
}
