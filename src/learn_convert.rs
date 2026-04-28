//! Implementation of `hermit learn-convert`.
//!
//! Reads a JSONL trace produced by `hermit learn` (one
//! `BlockEvent` per line, each tagged "allow" by virtue of being in
//! the access log), aggregates by hostname, and emits a TOML
//! scaffold the user can extend. The mechanism is a best-effort
//! guess:
//!
//! - **mitm** (default) when we saw at least one HTTP/HTTPS request
//!   for the host. Indicates the MITM handshake worked, so plaintext
//!   inspection is fine and the user gets full L7 filtering options.
//! - **sni** when we saw `tls_hostname` allow events but no `https`
//!   requests. That pattern means hermit's MITM CA wasn't accepted —
//!   typical for cert-pinning clients. Suggesting `sni` lets the
//!   user keep the policy strict without breaking the client.
//! - **mitm** when we only saw a DNS query (the host was resolved
//!   but never connected). Conservative default — the user can
//!   delete or narrow later.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cli::LearnConvertArgs;
use crate::sandbox::default_access_log_path;

/// Events from the access trace. Mirrors the wire shape of
/// `sni_proxy::block_log::BlockEvent` but only the fields we
/// actually consume — gives the converter a stable schema even
/// if `BlockEvent` grows new fields.
#[derive(Debug, Deserialize)]
pub(crate) struct TraceEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    method: Option<String>,
    /// Destination port. Only set for `tcp_observe` events today
    /// (the learn-mode catch-all observer logs the pre-DNAT port
    /// here so we can emit a `mechanism = "bypass"` rule that
    /// names it).
    #[serde(default)]
    port: Option<u16>,
    // path, client, time_unix_ms, reason are present in the JSONL
    // but unused for v1 conversion.
}

/// Per-hostname accumulator built up during conversion. Sorted
/// containers (`BTreeMap` / `BTreeSet`) so the emitted TOML is
/// deterministic regardless of input order.
#[derive(Default, Debug)]
struct HostAggregate {
    saw_dns: bool,
    saw_tls: bool,
    saw_http: bool,
    saw_https: bool,
    methods: BTreeSet<String>,
    /// TCP destination ports observed via the learn-mode
    /// catch-all (`tcp_observe` events). Each port becomes a
    /// separate `mechanism = "bypass"` rule when the scaffold is
    /// rendered.
    bypass_tcp_ports: BTreeSet<u16>,
}

impl HostAggregate {
    /// True iff the host generated any HTTP/TLS/DNS traffic the
    /// existing mitm/sni mechanism guess can speak to. A host with
    /// only `tcp_observe` events skips the mitm/sni rule —
    /// emitting one would be meaningless because the build wasn't
    /// using HTTP.
    fn has_web_traffic(&self) -> bool {
        self.saw_dns || self.saw_tls || self.saw_http || self.saw_https
    }
}

/// Top-level entry. Reads `args.input` (defaulting to the XDG
/// access-log path), aggregates events, and writes the rendered
/// TOML to `args.output` (or stdout if unset).
pub fn convert(args: &LearnConvertArgs) -> Result<()> {
    let input = args
        .input
        .clone()
        .unwrap_or_else(default_access_log_path);
    let text = std::fs::read_to_string(&input)
        .with_context(|| format!("reading access log {}", input.display()))?;
    let events = parse_events(&text)?;
    let toml = render(&events, &input, args.with_methods);

    match &args.output {
        Some(path) => std::fs::write(path, &toml)
            .with_context(|| format!("writing {}", path.display())),
        None => {
            print!("{toml}");
            Ok(())
        }
    }
}

/// Parse newline-delimited JSON. Blank lines are skipped; lines
/// that don't deserialize cleanly are surfaced with their line
/// number so the user can fix a mid-file corruption rather than
/// have the whole conversion fail silently.
fn parse_events(text: &str) -> Result<Vec<TraceEvent>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ev: TraceEvent = serde_json::from_str(line)
            .with_context(|| format!("line {}: malformed JSON", i + 1))?;
        out.push(ev);
    }
    Ok(out)
}

/// Aggregate events into a `host -> HostAggregate` map, then emit
/// the TOML scaffold. Pure (no I/O) so tests can pin the output.
pub(crate) fn render(events: &[TraceEvent], input_path: &Path, with_methods: bool) -> String {
    use std::fmt::Write as _;

    // Aggregate.
    let mut hosts: BTreeMap<String, HostAggregate> = BTreeMap::new();
    let mut malformed = 0usize;
    for ev in events {
        let Some(host) = ev.hostname.as_deref() else {
            // tls_no_sni / http_no_host → no hostname to bucket.
            // Counted but not folded; the comment header will
            // mention them so the user notices anomalous traffic.
            malformed += 1;
            continue;
        };
        let entry = hosts.entry(host.to_ascii_lowercase()).or_default();
        match ev.kind.as_str() {
            "dns" => entry.saw_dns = true,
            "tls_hostname" => entry.saw_tls = true,
            "http" => {
                entry.saw_http = true;
                if let Some(m) = &ev.method {
                    entry.methods.insert(m.to_ascii_uppercase());
                }
            }
            "https" => {
                entry.saw_https = true;
                if let Some(m) = &ev.method {
                    entry.methods.insert(m.to_ascii_uppercase());
                }
            }
            "tcp_observe" => {
                // The learn-mode catch-all observer fires for any
                // TCP connection on a port outside the proxied
                // set. Without a port the event isn't actionable
                // (we can't write a bypass rule for "some port"),
                // so events missing it are silently skipped.
                if let Some(p) = ev.port {
                    entry.bypass_tcp_ports.insert(p);
                }
            }
            _ => {} // tls_no_sni etc. — ignored at host level
        }
    }

    // Emit.
    let mut out = String::new();
    let _ = writeln!(out, "# Generated by `hermit learn-convert` from:");
    let _ = writeln!(out, "#   {}", input_path.display());
    let _ = writeln!(out, "# Events read: {}", events.len());
    if malformed > 0 {
        let _ = writeln!(
            out,
            "# Events without a hostname: {malformed} \
             (tls_no_sni / http_no_host — review the source trace)"
        );
    }
    let _ = writeln!(out, "# Unique hosts: {}", hosts.len());
    let _ = writeln!(
        out,
        "# Mechanism guess: `sni` when a host's TLS handshake never \
         produced an HTTPS request"
    );
    let _ = writeln!(out, "# (typical of cert-pinning clients); `mitm` otherwise.");
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# Review and edit before signing. `hermit run` enforces; \
         `hermit edit-config` mutates."
    );
    let _ = writeln!(out);

    for (host, agg) in &hosts {
        let provenance = describe_provenance(agg);
        let target_key = HostKey::parse(host);

        // Web-shaped traffic gets a single mitm/sni rule. A host
        // with only tcp_observe events (no DNS/TLS/HTTP) skips
        // this branch entirely.
        if agg.has_web_traffic() {
            let mechanism = guess_mechanism(agg);
            let _ = writeln!(out, "# observed: {provenance}");
            let _ = writeln!(out, "[[access_rule]]");
            target_key.write_target(&mut out);
            // Emit `mechanism` even when it matches the default
            // (`mitm`). The scaffold is meant to be edited, and a
            // reader skimming the file shouldn't have to
            // remember which fields fall back to which defaults
            // — every rule should be self-describing.
            let _ = writeln!(out, "mechanism = {mechanism:?}");
            if with_methods && mechanism == "mitm" && !agg.methods.is_empty() {
                let methods: Vec<String> = agg
                    .methods
                    .iter()
                    .map(|m| format!("{m:?}"))
                    .collect();
                let _ = writeln!(out, "methods = [{}]", methods.join(", "));
            }
            let _ = writeln!(out);
        }

        // One bypass rule per observed (host, port). Multiple
        // ports for the same host become multiple rules so the
        // operator can prune them individually.
        for port in &agg.bypass_tcp_ports {
            let _ = writeln!(out, "# observed: tcp port={port}");
            let _ = writeln!(out, "[[access_rule]]");
            target_key.write_target(&mut out);
            let _ = writeln!(out, "mechanism = \"bypass\"");
            let _ = writeln!(out, "protocol = \"tcp\"");
            let _ = writeln!(out, "port = {port}");
            let _ = writeln!(out);
        }
    }
    out
}

/// What the observer recorded as `hostname` for an event:
/// either a real DNS name (the common case, when the DNS cache
/// reverse-mapped the dst IP) or a synthetic `ip:1.2.3.4` /
/// `ip:unknown` placeholder. The latter rendering would not be
/// a legal hostname; emit the rule using `ip = "…"` instead.
enum HostKey<'a> {
    Hostname(&'a str),
    Ip(&'a str),
    Unknown,
}

impl<'a> HostKey<'a> {
    fn parse(raw: &'a str) -> Self {
        if let Some(rest) = raw.strip_prefix("ip:") {
            if rest == "unknown" {
                HostKey::Unknown
            } else {
                HostKey::Ip(rest)
            }
        } else {
            HostKey::Hostname(raw)
        }
    }

    /// Write either a `host = "…"` or `ip = "…"` line. Synthetic
    /// "unknown" sources are still emitted as a placeholder so
    /// the operator notices and can fix the rule manually.
    fn write_target(&self, out: &mut String) {
        use std::fmt::Write as _;
        match self {
            HostKey::Hostname(h) => {
                let _ = writeln!(out, "host = {h:?}");
            }
            HostKey::Ip(ip) => {
                let _ = writeln!(out, "ip = {ip:?}");
            }
            HostKey::Unknown => {
                let _ = writeln!(out, "# FIXME: no hostname or IP captured for this connection");
                let _ = writeln!(out, "host = \"REPLACE_ME\"");
            }
        }
    }
}

fn guess_mechanism(a: &HostAggregate) -> &'static str {
    // Saw a TLS handshake but never an HTTPS request → MITM
    // failed (likely cert pinning), so cut-through is what works.
    if a.saw_tls && !a.saw_https {
        return "sni";
    }
    "mitm"
}

fn describe_provenance(a: &HostAggregate) -> String {
    let mut parts = Vec::with_capacity(4);
    if a.saw_dns {
        parts.push("dns".to_string());
    }
    if a.saw_tls {
        parts.push("tls".to_string());
    }
    if a.saw_https {
        let methods = if a.methods.is_empty() {
            String::new()
        } else {
            let m: Vec<&str> = a.methods.iter().map(|s| s.as_str()).collect();
            format!(" {{{}}}", m.join(","))
        };
        parts.push(format!("https{methods}"));
    } else if a.saw_http {
        let methods = if a.methods.is_empty() {
            String::new()
        } else {
            let m: Vec<&str> = a.methods.iter().map(|s| s.as_str()).collect();
            format!(" {{{}}}", m.join(","))
        };
        parts.push(format!("http{methods}"));
    }
    parts.join(", ")
}

/// Test-only constructor for [`TraceEvent`] so the renderer can
/// be exercised without going through serde.
#[cfg(test)]
fn ev(kind: &str, host: Option<&str>, method: Option<&str>) -> TraceEvent {
    TraceEvent {
        kind: kind.to_string(),
        hostname: host.map(|s| s.to_string()),
        method: method.map(|s| s.to_string()),
        port: None,
    }
}

/// Test-only constructor for a `tcp_observe` event with a port.
#[cfg(test)]
fn ev_tcp(host: Option<&str>, port: u16) -> TraceEvent {
    TraceEvent {
        kind: "tcp_observe".to_string(),
        hostname: host.map(|s| s.to_string()),
        method: None,
        port: Some(port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_path() -> PathBuf {
        PathBuf::from("/tmp/access.jsonl")
    }

    #[test]
    fn render_empty_trace_emits_header_only() {
        let out = render(&[], &dummy_path(), false);
        assert!(out.contains("# Events read: 0"));
        assert!(out.contains("# Unique hosts: 0"));
        // No rule blocks at all.
        assert!(!out.contains("[[access_rule]]"));
    }

    #[test]
    fn render_dedupes_hosts_and_lowercases() {
        let events = vec![
            ev("dns", Some("API.Example"), None),
            ev("tls_hostname", Some("api.example"), None),
            ev("https", Some("API.example"), Some("GET")),
        ];
        let out = render(&events, &dummy_path(), false);
        assert_eq!(
            out.matches("[[access_rule]]").count(),
            1,
            "case-variant hostnames must collapse to one rule: {out}"
        );
        assert!(out.contains(r#"host = "api.example""#));
    }

    #[test]
    fn render_emits_mitm_when_https_request_observed() {
        let events = vec![
            ev("tls_hostname", Some("api.example"), None),
            ev("https", Some("api.example"), Some("GET")),
        ];
        let out = render(&events, &dummy_path(), false);
        // Every rule is emitted self-describingly — including the
        // `mechanism` field even when it equals the default. A
        // reader of the scaffold shouldn't have to know which
        // fields fall back to which defaults.
        assert!(out.contains(r#"host = "api.example""#));
        assert!(out.contains(r#"mechanism = "mitm""#),
            "mitm should be written explicitly, not left implicit: {out}");
    }

    #[test]
    fn render_guesses_sni_when_tls_handshake_did_not_produce_request() {
        // Cert-pinning client: hermit MITM never decrypted, so we
        // saw `tls_hostname` allow events without any subsequent
        // `https`. Suggest sni so the user gets a working policy.
        let events = vec![
            ev("dns", Some("pinned.example"), None),
            ev("tls_hostname", Some("pinned.example"), None),
        ];
        let out = render(&events, &dummy_path(), false);
        assert!(out.contains(r#"mechanism = "sni""#),
            "expected sni guess for TLS-only host: {out}");
    }

    #[test]
    fn render_with_methods_includes_method_list_for_mitm_rules() {
        let events = vec![
            ev("https", Some("api.example"), Some("GET")),
            ev("https", Some("api.example"), Some("POST")),
            ev("https", Some("api.example"), Some("get")), // case-folded
        ];
        let out = render(&events, &dummy_path(), true);
        assert!(out.contains(r#"methods = ["GET", "POST"]"#),
            "method aggregation broken: {out}");
    }

    #[test]
    fn render_with_methods_off_omits_methods() {
        let events = vec![ev("https", Some("api.example"), Some("GET"))];
        let out = render(&events, &dummy_path(), false);
        assert!(!out.contains("methods"),
            "methods must not appear without --with-methods: {out}");
    }

    #[test]
    fn render_with_methods_does_not_decorate_sni_rules() {
        // sni rules don't accept `methods`; emitting one here
        // would produce a config the runtime rejects.
        let events = vec![ev("tls_hostname", Some("pinned.example"), None)];
        let out = render(&events, &dummy_path(), true);
        assert!(out.contains(r#"mechanism = "sni""#));
        assert!(!out.contains("methods"),
            "methods must not be emitted for sni rules: {out}");
    }

    #[test]
    fn render_orders_hosts_alphabetically_for_stable_diffs() {
        // Deterministic order keeps re-runs from producing
        // unrelated diff churn when learn is re-invoked.
        let events = vec![
            ev("dns", Some("zeta.example"), None),
            ev("dns", Some("alpha.example"), None),
            ev("dns", Some("mike.example"), None),
        ];
        let out = render(&events, &dummy_path(), false);
        let alpha_at = out.find("alpha.example").unwrap();
        let mike_at = out.find("mike.example").unwrap();
        let zeta_at = out.find("zeta.example").unwrap();
        assert!(alpha_at < mike_at && mike_at < zeta_at);
    }

    #[test]
    fn render_counts_hostless_events_in_header() {
        // tls_no_sni / http_no_host events have no host bucket;
        // the count helps the user realize the trace contains
        // anomalous traffic worth investigating.
        let events = vec![
            ev("tls_no_sni", None, None),
            ev("http_no_host", None, None),
            ev("dns", Some("ok.example"), None),
        ];
        let out = render(&events, &dummy_path(), false);
        assert!(out.contains("# Events without a hostname: 2"),
            "header missing hostless count: {out}");
    }

    #[test]
    fn parse_events_skips_blank_lines() {
        let raw = r#"

{"type":"dns","hostname":"a.example"}

{"type":"https","hostname":"a.example","method":"GET","path":"/"}

"#;
        let evs = parse_events(raw).unwrap();
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn parse_events_surfaces_line_number_on_bad_json() {
        let raw = r#"{"type":"dns","hostname":"ok.example"}
this is not json
"#;
        let err = parse_events(raw).unwrap_err().to_string();
        assert!(err.contains("line 2"), "error must name line: {err}");
    }

    #[test]
    fn convert_writes_to_output_file_when_set() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("access.jsonl");
        let output = tmp.path().join("rules.toml");
        std::fs::write(
            &input,
            "{\"type\":\"dns\",\"hostname\":\"ok.example\"}\n",
        )
        .unwrap();
        let args = LearnConvertArgs {
            input: Some(input),
            output: Some(output.clone()),
            with_methods: false,
        };
        convert(&args).unwrap();
        let written = std::fs::read_to_string(&output).unwrap();
        assert!(written.contains(r#"host = "ok.example""#));
    }

    #[test]
    fn render_tcp_observe_only_host_emits_bypass_rule() {
        // A host seen exclusively via the learn-mode catch-all
        // observer (e.g. ssh on 22) should produce a bypass rule
        // and *no* mitm rule — emitting mitm here would be a lie
        // about the protocol.
        let events = vec![ev_tcp(Some("git.example"), 22)];
        let out = render(&events, &dummy_path(), false);

        assert!(
            !out.contains(r#"mechanism = "mitm""#),
            "tcp-only host must not get a mitm rule: {out}"
        );
        assert!(out.contains(r#"host = "git.example""#));
        assert!(out.contains(r#"mechanism = "bypass""#));
        assert!(out.contains(r#"protocol = "tcp""#));
        assert!(out.contains("port = 22"));
        assert!(out.contains("# observed: tcp port=22"));
    }

    #[test]
    fn render_tcp_observe_alongside_https_emits_both_rules() {
        // A host that's both an HTTPS endpoint *and* a bypass
        // target gets two rules — one mitm, one bypass — so the
        // user can keep the L7 enforcement for 443 and add bypass
        // for the non-HTTP port.
        let events = vec![
            ev("https", Some("dual.example"), Some("GET")),
            ev_tcp(Some("dual.example"), 8000),
        ];
        let out = render(&events, &dummy_path(), false);

        assert_eq!(
            out.matches("[[access_rule]]").count(),
            2,
            "expected two rules (mitm + bypass), got: {out}"
        );
        assert!(out.contains(r#"mechanism = "mitm""#));
        assert!(out.contains(r#"mechanism = "bypass""#));
        assert!(out.contains("port = 8000"));
    }

    #[test]
    fn render_tcp_observe_multiple_ports_per_host_emits_one_rule_each() {
        // Two distinct ports for the same host → two bypass
        // rules. The operator gets to prune them individually.
        let events = vec![
            ev_tcp(Some("svc.example"), 22),
            ev_tcp(Some("svc.example"), 5432),
            ev_tcp(Some("svc.example"), 22), // duplicate, dedup
        ];
        let out = render(&events, &dummy_path(), false);

        assert_eq!(
            out.matches("[[access_rule]]").count(),
            2,
            "expected two bypass rules (one per unique port): {out}"
        );
        assert!(out.contains("port = 22"));
        assert!(out.contains("port = 5432"));
    }

    #[test]
    fn render_tcp_observe_with_synthetic_ip_host_uses_ip_field() {
        // The observer falls back to a synthetic `ip:1.2.3.4`
        // hostname when the DNS cache has no reverse mapping.
        // The converter must turn that into an `ip = "…"` rule
        // (not `host = "ip:1.2.3.4"`) so the runtime parses it.
        let events = vec![ev_tcp(Some("ip:10.0.0.5"), 22)];
        let out = render(&events, &dummy_path(), false);

        assert!(out.contains(r#"ip = "10.0.0.5""#),
            "synthetic ip:… should become an ip = field: {out}");
        assert!(!out.contains(r#"host = "ip:"#),
            "synthetic prefix must not leak into a host = field: {out}");
    }

    #[test]
    fn render_tcp_observe_unknown_host_emits_fixme() {
        // The synthetic `ip:unknown` placeholder means the
        // observer didn't have an SO_ORIGINAL_DST. The rule we
        // emit is unusable as-is on purpose — it surfaces a
        // FIXME so the operator notices instead of signing a
        // garbage rule.
        let events = vec![ev_tcp(Some("ip:unknown"), 22)];
        let out = render(&events, &dummy_path(), false);

        assert!(out.contains("# FIXME"),
            "unknown-host rule should carry a FIXME marker: {out}");
        assert!(out.contains("REPLACE_ME"));
    }

    #[test]
    fn render_tcp_observe_event_without_port_is_ignored() {
        // `port` is the only field we care about for tcp_observe
        // — without it the event isn't actionable. Skip it
        // silently so a malformed event doesn't poison the
        // scaffold with a `port = 0` rule the runtime would
        // reject.
        let bad = TraceEvent {
            kind: "tcp_observe".to_string(),
            hostname: Some("svc.example".to_string()),
            method: None,
            port: None,
        };
        let out = render(&[bad], &dummy_path(), false);
        assert!(!out.contains("[[access_rule]]"),
            "tcp_observe without a port should produce no rule: {out}");
    }
}
