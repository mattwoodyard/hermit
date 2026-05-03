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

/// Wrappers around `edit_config`'s `pub(crate)` items for the
/// dedicated test crate. Off by default; `hermit-tests` flips on
/// the `__test_internals` feature in its `[dependencies]` entry.
///
/// Wrappers (rather than `pub use`) because Rust E0364 forbids
/// re-exporting `pub(crate)` items outside the crate.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use super::Config;
    use std::path::Path;

    pub fn render(cfg: &Config, path: &Path) -> String {
        super::render(cfg, path)
    }
}
