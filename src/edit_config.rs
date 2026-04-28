//! Implementation of `hermit edit-config add-rule` / `remove-rule`.
//!
//! Edits preserve formatting via `toml_edit`: comments, section
//! ordering, and blank lines survive. Any existing `[signature]`
//! section is dropped on every write because an edit invalidates
//! the signature — re-sign afterwards with `hermit sign`.

use std::path::Path;

use anyhow::{bail, Context, Result};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};

use crate::cli::{AddRuleArgs, RemoveRuleArgs, ShowArgs};
use crate::config::Config;

/// Entry point for `edit-config add-rule`.
pub fn add_rule(args: &AddRuleArgs) -> Result<()> {
    if args.host.is_none() && args.ip.is_none() {
        bail!("add-rule: must supply --host or --ip");
    }
    let doc = read_doc(&args.config)?;
    let mut doc = doc;
    append_rule(&mut doc, args)?;
    validate_roundtrip(&doc)?;
    strip_signature(&mut doc);
    write_doc(&args.config, &doc)
}

/// Entry point for `edit-config show`. Parses `<config>` without
/// following `include = […]` and prints a human-readable summary.
/// Intentionally does *not* validate via `compile_rules` so a
/// partially-invalid file can still be inspected and fixed — each
/// malformed bit is rendered verbatim with a `(invalid)` marker
/// where we can detect it.
pub fn show(args: &ShowArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading config {}", args.config.display()))?;
    let cfg = Config::parse(&text)
        .with_context(|| format!("parsing {} as TOML", args.config.display()))?;
    let rendered = render(&cfg, &args.config);
    print!("{rendered}");
    Ok(())
}

/// Pure renderer: `Config` → human-readable summary. Split out
/// from [`show`] so tests can assert on the output string without
/// going through stdout.
pub(crate) fn render(cfg: &Config, path: &Path) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "=== {} ===", path.display());

    if !cfg.include.is_empty() {
        let _ = writeln!(out, "\nincludes:");
        for inc in &cfg.include {
            let _ = writeln!(out, "  - {inc}");
        }
    }

    // [sandbox]
    let sb = cfg.sandbox();
    let _ = writeln!(out, "\n[sandbox]");
    let _ = writeln!(out, "  net = {}", sb.net.to_cli());
    if !sb.passthrough.is_empty() {
        let _ = writeln!(out, "  passthrough:");
        for p in &sb.passthrough {
            let _ = writeln!(out, "    - {}", p.display());
        }
    }

    // [dns]
    let dns = cfg.dns();
    let origin = if cfg.dns_override.is_some() { "override" } else { "default" };
    let _ = writeln!(out, "\n[dns]");
    let _ = writeln!(out, "  upstream = {:?}   ({origin})", dns.upstream);

    // [[access_rule]] — two buckets after compile_rules; fall back
    // to the raw specs if validation fails so show still works on a
    // broken file.
    match cfg.compile_rules() {
        Ok((host_rules, ip_rules)) => {
            let total = host_rules.len() + ip_rules.len();
            let _ = writeln!(out, "\n[[access_rule]] ({total})");
            for r in &host_rules {
                let mut line = format!(
                    "  host={:?}  mechanism={}",
                    r.hostname, r.mechanism
                );
                if let Some(pp) = &r.path_prefix {
                    let _ = write!(line, "  path_prefix={pp:?}");
                }
                if let Some(ms) = &r.methods {
                    // Render in the canonical HTTP wire form (Display),
                    // not Debug, so the output round-trips back to the
                    // user's source TOML. Sort for determinism —
                    // `methods` lives in a HashSet at runtime.
                    let mut methods: Vec<String> =
                        ms.iter().map(|m| format!("\"{m}\"")).collect();
                    methods.sort();
                    let _ = write!(line, "  methods=[{}]", methods.join(","));
                }
                let _ = writeln!(out, "{line}");
            }
            for r in &ip_rules {
                let _ = writeln!(out, "  ip={}  mechanism={}", r.ip, r.mechanism);
            }
        }
        Err(e) => {
            let _ = writeln!(
                out,
                "\n[[access_rule]] (validation failed: {e:#}; showing raw entries)"
            );
            for (i, ar) in cfg.access_rules.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "  [{i}] host={:?} ip={:?} mechanism={:?} path_prefix={:?} methods={:?} \
                     protocol={:?} port={:?}",
                    ar.host, ar.ip, ar.mechanism, ar.path_prefix,
                    ar.methods, ar.protocol, ar.port,
                );
            }
        }
    }

    // [[port_forward]]
    if !cfg.port_forwards.is_empty() {
        let _ = writeln!(out, "\n[[port_forward]] ({})", cfg.port_forwards.len());
        for pf in &cfg.port_forwards {
            let _ = writeln!(out, "  port={}  protocol={:?}", pf.port, pf.protocol);
        }
    }

    // [[rule]] / [credential] — don't print the credential values;
    // just the shape. Counts are the load-bearing signal and the
    // values frequently include tokens, so we stay terse here.
    if !cfg.injection_rules.is_empty() || !cfg.credential.is_empty() {
        let _ = writeln!(
            out,
            "\n[[rule]] + [credential.*]: {} injection rule(s), {} credential(s)",
            cfg.injection_rules.len(),
            cfg.credential.len()
        );
    }

    if cfg.signature.is_some() {
        let _ = writeln!(out, "\n[signature] present");
    } else {
        let _ = writeln!(out, "\n[signature] absent");
    }

    out
}

/// Entry point for `edit-config remove-rule`.
pub fn remove_rule(args: &RemoveRuleArgs) -> Result<()> {
    if args.host.is_none() && args.ip.is_none() {
        bail!("remove-rule: must supply --host or --ip");
    }
    let mut doc = read_doc(&args.config)?;
    let removed = remove_matching(&mut doc, args)?;
    if removed == 0 {
        bail!(
            "remove-rule: no [[access_rule]] matched the selector \
             (host={:?}, ip={:?})",
            args.host,
            args.ip
        );
    }
    validate_roundtrip(&doc)?;
    strip_signature(&mut doc);
    write_doc(&args.config, &doc)
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

fn read_doc(path: &Path) -> Result<DocumentMut> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    text.parse::<DocumentMut>()
        .with_context(|| format!("parsing {} as TOML", path.display()))
}

fn write_doc(path: &Path, doc: &DocumentMut) -> Result<()> {
    std::fs::write(path, doc.to_string())
        .with_context(|| format!("writing config {}", path.display()))
}

// ---------------------------------------------------------------------------
// Mutators
// ---------------------------------------------------------------------------

/// Append a new `[[access_rule]]` table populated from `args`. The
/// access_rule array-of-tables is created if it didn't exist.
fn append_rule(doc: &mut DocumentMut, args: &AddRuleArgs) -> Result<()> {
    let mut rule = Table::new();
    if let Some(host) = &args.host {
        rule.insert("host", Item::Value(Value::from(host.as_str())));
    }
    if let Some(ip) = &args.ip {
        rule.insert("ip", Item::Value(Value::from(ip.to_string())));
    }
    // `mechanism = "mitm"` is the loader default — omit it from the
    // written rule to keep files tidy unless the user chose
    // something else.
    if args.mechanism != "mitm" {
        rule.insert(
            "mechanism",
            Item::Value(Value::from(args.mechanism.as_str())),
        );
    }
    if let Some(p) = &args.path_prefix {
        rule.insert("path_prefix", Item::Value(Value::from(p.as_str())));
    }
    if let Some(ms) = &args.methods {
        let mut arr = Array::new();
        for m in ms {
            arr.push(Value::from(m.as_str()));
        }
        rule.insert("methods", Item::Value(Value::Array(arr)));
    }
    if let Some(proto) = &args.protocol {
        rule.insert("protocol", Item::Value(Value::from(proto.as_str())));
    }
    if let Some(port) = args.port {
        rule.insert("port", Item::Value(Value::from(port as i64)));
    }

    let aot = ensure_access_rule_aot(doc);
    aot.push(rule);
    Ok(())
}

/// Remove matching `[[access_rule]]` entries. Returns how many were
/// removed so the caller can surface "no match" as an error.
fn remove_matching(doc: &mut DocumentMut, args: &RemoveRuleArgs) -> Result<usize> {
    let Some(aot) = doc
        .get_mut("access_rule")
        .and_then(|item| item.as_array_of_tables_mut())
    else {
        return Ok(0);
    };

    // Two-pass to avoid repeatedly shifting indices: collect
    // indices to drop, then remove in reverse order.
    let mut matches: Vec<usize> = Vec::new();
    for (idx, tbl) in aot.iter().enumerate() {
        if matches_selector(tbl, args) {
            matches.push(idx);
        }
    }
    if matches.len() > 1 && !args.all_matching {
        bail!(
            "remove-rule: selector matched {} entries — re-run with \
             --all-matching or tighten the selector",
            matches.len()
        );
    }
    for idx in matches.iter().rev() {
        aot.remove(*idx);
    }
    Ok(matches.len())
}

fn matches_selector(tbl: &Table, args: &RemoveRuleArgs) -> bool {
    if let Some(host) = &args.host {
        let h = tbl.get("host").and_then(|v| v.as_str()).unwrap_or("");
        return h.eq_ignore_ascii_case(host);
    }
    if let Some(ip) = &args.ip {
        let s = tbl.get("ip").and_then(|v| v.as_str()).unwrap_or("");
        return s.parse::<std::net::IpAddr>().map(|a| a == *ip).unwrap_or(false);
    }
    false
}

/// Borrow (or create) the `access_rule` array-of-tables on the
/// document. Creating keeps the rest of the formatting intact.
fn ensure_access_rule_aot(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    if !doc.contains_key("access_rule") {
        doc.insert("access_rule", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["access_rule"]
        .as_array_of_tables_mut()
        .expect("access_rule is an array of tables by construction")
}

fn strip_signature(doc: &mut DocumentMut) {
    doc.remove("signature");
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Render the edited document back to TOML and feed it through the
/// standard parser + validator. This catches any malformed rule
/// before we write to disk. "Parse don't validate": there is no
/// alternate validation path — we use the same one the runtime
/// loader does.
fn validate_roundtrip(doc: &DocumentMut) -> Result<()> {
    let text = doc.to_string();
    let cfg = Config::parse(&text).context("edited config no longer parses")?;
    cfg.compile_rules().context("edited config failed rule validation")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
}
