//! Tests for `hermit::config_loader`.
//!
//! Reaches into private items via `hermit::config_loader::__test_internals`
//! (only available because hermit-tests turns on the
//! `__test_internals` feature).

use hermit::config_loader::__test_internals::MAX_INCLUDE_DEPTH;
use hermit::config_loader::{assemble, fetch, TrustPolicy};
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
    assert_eq!(cfg.sandbox().net, hermit::config::NetMode::Host);
}

#[test]
fn assemble_scalar_inherited_from_include_when_root_silent() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared.toml");
    std::fs::write(&shared, "[sandbox]\nnet = \"isolate\"\n").unwrap();
    let root = dir.path().join("root.toml");
    std::fs::write(&root, format!("include = [\"{}\"]\n", file_url(&shared))).unwrap();

    let cfg = assemble(&file_url(&root), &TrustPolicy::AllowUnsigned).unwrap();
    assert_eq!(cfg.sandbox().net, hermit::config::NetMode::Isolate);
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
