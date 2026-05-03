//! Tests for `hermit::edit_config`.
//!
//! `render` is `pub(crate)` in the source crate, so we go through
//! the `__test_internals` wrapper. Everything else (`add_rule`,
//! `remove_rule`, `AddRuleArgs`, `RemoveRuleArgs`, `Config`) is
//! public API.

use std::path::{Path, PathBuf};

use hermit::cli::{AddRuleArgs, RemoveRuleArgs};
use hermit::config::Config;
use hermit::edit_config::__test_internals::render;
use hermit::edit_config::{add_rule, remove_rule};

fn tmp_config(contents: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hermit.toml");
    std::fs::write(&path, contents).unwrap();
    (dir, path)
}

fn add_args(path: PathBuf) -> AddRuleArgs {
    AddRuleArgs {
        config: path,
        host: None,
        ip: None,
        mechanism: "mitm".to_string(),
        path_prefix: None,
        methods: None,
        protocol: None,
        port: None,
    }
}

fn remove_args(path: PathBuf) -> RemoveRuleArgs {
    RemoveRuleArgs {
        config: path,
        host: None,
        ip: None,
        all_matching: false,
    }
}

#[test]
fn add_rule_appends_hostname_mitm_default() {
    let (_dir, path) = tmp_config("");
    let mut args = add_args(path.clone());
    args.host = Some("api.example".to_string());
    add_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("[[access_rule]]"));
    assert!(text.contains(r#"host = "api.example""#));
    // MITM is the default — don't clutter the file with it.
    assert!(
        !text.contains("mechanism"),
        "default mitm mechanism should not be written: {text}"
    );
}

#[test]
fn add_rule_writes_bypass_fields() {
    let (_dir, path) = tmp_config("");
    let mut args = add_args(path.clone());
    args.host = Some("kdc.example".to_string());
    args.mechanism = "bypass".to_string();
    args.protocol = Some("udp".to_string());
    args.port = Some(88);
    add_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(r#"host = "kdc.example""#));
    assert!(text.contains(r#"mechanism = "bypass""#));
    assert!(text.contains(r#"protocol = "udp""#));
    assert!(text.contains("port = 88"));
}

#[test]
fn add_rule_accepts_ip_target() {
    let (_dir, path) = tmp_config("");
    let mut args = add_args(path.clone());
    args.ip = Some("10.0.0.5".parse().unwrap());
    args.mechanism = "bypass".to_string();
    args.protocol = Some("tcp".to_string());
    args.port = Some(389);
    add_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(r#"ip = "10.0.0.5""#));
    assert!(text.contains("port = 389"));
}

#[test]
fn add_rule_preserves_existing_comments_and_rules() {
    // toml_edit's entire reason for existing — comments and
    // formatting must survive round-trips.
    let initial = r#"# top banner
[sandbox]
net = "isolate"

[[access_rule]]
host = "first.example"   # trailing note

[[access_rule]]
host = "second.example"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = add_args(path.clone());
    args.host = Some("third.example".to_string());
    add_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("# top banner"), "banner lost: {text}");
    assert!(text.contains("# trailing note"), "trailing note lost: {text}");
    assert!(text.contains("first.example"));
    assert!(text.contains("second.example"));
    assert!(text.contains("third.example"));
}

#[test]
fn add_rule_rejects_invalid_combination_before_writing() {
    // bypass + path_prefix is rejected by compile_rules. We must
    // surface the error BEFORE touching the file, so a bad
    // invocation doesn't leave the config in a broken state.
    let initial = "# untouched\n";
    let (_dir, path) = tmp_config(initial);
    let mut args = add_args(path.clone());
    args.host = Some("x.example".to_string());
    args.mechanism = "bypass".to_string();
    args.protocol = Some("tcp".to_string());
    args.port = Some(9000);
    args.path_prefix = Some("/api/".to_string()); // illegal
    // `{:#}` renders the full anyhow context chain so the
    // inner validator message is visible — the top-level
    // context is generic and wouldn't match either keyword.
    let err = format!("{:#}", add_rule(&args).unwrap_err());
    assert!(
        err.contains("path_prefix") || err.contains("bypass"),
        "error should mention the offending field: {err}"
    );

    let after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(after, initial, "file must be unchanged on validation failure");
}

#[test]
fn add_rule_drops_existing_signature() {
    // Editing the rules invalidates any signature; the
    // subcommand must clear `[signature]` so the user doesn't
    // accidentally use an untrustworthy config.
    let initial = r#"[[access_rule]]
host = "x.example"

[signature]
cert = "BASE64"
signature = "BASE64"
algorithm = "ed25519"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = add_args(path.clone());
    args.host = Some("y.example".to_string());
    add_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("[signature]"),
        "signature should be dropped after edit: {text}");
}

#[test]
fn remove_rule_removes_single_match_by_host() {
    let initial = r#"[[access_rule]]
host = "keep.example"

[[access_rule]]
host = "drop.example"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = remove_args(path.clone());
    args.host = Some("drop.example".to_string());
    remove_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("keep.example"));
    assert!(!text.contains("drop.example"));
}

#[test]
fn remove_rule_by_ip() {
    let initial = r#"[[access_rule]]
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88

[[access_rule]]
host = "api.example"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = remove_args(path.clone());
    args.ip = Some("10.0.0.5".parse().unwrap());
    remove_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("api.example"));
    assert!(!text.contains("10.0.0.5"));
}

#[test]
fn remove_rule_rejects_ambiguous_match_without_all_flag() {
    let initial = r#"[[access_rule]]
host = "same.example"
path_prefix = "/a/"

[[access_rule]]
host = "same.example"
path_prefix = "/b/"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = remove_args(path.clone());
    args.host = Some("same.example".to_string());
    let err = remove_rule(&args).unwrap_err().to_string();
    assert!(err.contains("matched 2") || err.contains("--all-matching"));
    // File unchanged.
    let after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(after, initial);
}

#[test]
fn remove_rule_all_matching_wipes_every_match() {
    let initial = r#"[[access_rule]]
host = "same.example"
path_prefix = "/a/"

[[access_rule]]
host = "keep.example"

[[access_rule]]
host = "same.example"
path_prefix = "/b/"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = remove_args(path.clone());
    args.host = Some("same.example".to_string());
    args.all_matching = true;
    remove_rule(&args).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("keep.example"));
    assert!(!text.contains("same.example"));
}

#[test]
fn remove_rule_no_match_is_error() {
    let initial = r#"[[access_rule]]
host = "exists.example"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = remove_args(path.clone());
    args.host = Some("nope.example".to_string());
    let err = remove_rule(&args).unwrap_err().to_string();
    assert!(err.contains("no [[access_rule]] matched"));
}

fn render_str(contents: &str) -> String {
    let cfg = Config::parse(contents).unwrap();
    render(&cfg, Path::new("hermit.toml"))
}

#[test]
fn show_renders_host_and_ip_rules_with_mechanism() {
    let out = render_str(
        r#"
[[access_rule]]
host = "api.example"

[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
port = 88

[[access_rule]]
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "tcp"
port = 389
"#,
    );
    assert!(out.contains("[[access_rule]] (3)"), "count missing: {out}");
    assert!(out.contains(r#"host="api.example"  mechanism=mitm"#));
    assert!(out.contains(r#"host="kdc.example"  mechanism=bypass(udp/88)"#));
    assert!(out.contains(r#"ip=10.0.0.5  mechanism=bypass(tcp/389)"#));
}

#[test]
fn show_marks_dns_default_vs_override() {
    // No [dns] block → default marker.
    let out = render_str("");
    assert!(
        out.contains(r#"upstream = "1.1.1.1:53"   (default)"#),
        "default not labelled: {out}"
    );

    // Explicit [dns] → override marker.
    let out = render_str(
        r#"
[dns]
upstream = "9.9.9.9:53"
"#,
    );
    assert!(
        out.contains(r#"upstream = "9.9.9.9:53"   (override)"#),
        "override not labelled: {out}"
    );
}

#[test]
fn show_lists_includes_when_present() {
    let out = render_str(
        r#"
include = ["file:///etc/hermit/shared.toml", "https://example.com/other.toml"]
"#,
    );
    assert!(out.contains("includes:"));
    assert!(out.contains("- file:///etc/hermit/shared.toml"));
    assert!(out.contains("- https://example.com/other.toml"));
}

#[test]
fn show_renders_path_prefix_and_methods() {
    let out = render_str(
        r#"
[[access_rule]]
host = "api.example"
path_prefix = "/v1/"
methods = ["GET", "POST"]
"#,
    );
    // Deterministic ordering — methods are sorted before
    // rendering so the output doesn't depend on HashSet
    // iteration order.
    assert!(out.contains(r#"path_prefix="/v1/""#), "path_prefix missing: {out}");
    assert!(out.contains(r#"methods=["GET","POST"]"#), "methods not sorted: {out}");
}

#[test]
fn show_reports_signature_presence() {
    let out_absent = render_str("");
    assert!(out_absent.contains("[signature] absent"));

    let out_present = render_str(
        r#"
[signature]
cert = "A"
signature = "B"
algorithm = "ed25519"
"#,
    );
    assert!(out_present.contains("[signature] present"));
}

#[test]
fn show_recovers_on_invalid_rule_and_dumps_raw() {
    // A rule with bypass + path_prefix fails validation. `show`
    // should still produce output so the user can diagnose the
    // file, rather than bail halfway through.
    let out = render_str(
        r#"
[[access_rule]]
host = "x.example"
mechanism = "bypass"
protocol = "tcp"
port = 9000
path_prefix = "/api/"
"#,
    );
    assert!(
        out.contains("validation failed"),
        "expected raw-fallback path: {out}"
    );
    assert!(out.contains(r#"host=Some("x.example")"#),
        "raw dump missing host: {out}");
}

#[test]
fn show_includes_port_forwards_and_injection_counts() {
    // `match` is the raw match-DSL string; `credential` is
    // referenced by name from [credential.<name>].
    let out = render_str(
        r#"
[[port_forward]]
port = 8443
protocol = "https"

[[rule]]
match = "host == \"api.example\""
credential = "tok"

[credential.tok]
source = { type = "env", name = "MY_TOKEN" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#,
    );
    assert!(out.contains("[[port_forward]] (1)"));
    assert!(out.contains("port=8443"));
    assert!(out.contains("1 injection rule(s), 1 credential(s)"));
}

#[test]
fn remove_rule_host_match_is_case_insensitive() {
    let initial = r#"[[access_rule]]
host = "MiXeD.Example"
"#;
    let (_dir, path) = tmp_config(initial);
    let mut args = remove_args(path.clone());
    args.host = Some("mixed.example".to_string());
    remove_rule(&args).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("MiXeD.Example"));
}
