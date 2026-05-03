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
//! - **splice** when we saw `tls_hostname` allow events but no
//!   `https` requests. That pattern means hermit's MITM CA wasn't
//!   accepted — typical for cert-pinning clients. Suggesting
//!   `splice` lets the user keep the policy strict without
//!   breaking the client.
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
pub struct TraceEvent {
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
    /// existing mitm/splice mechanism guess can speak to. A host with
    /// only `tcp_observe` events skips the mitm/splice rule —
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
        "# Mechanism guess: `splice` when a host's TLS handshake never \
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

        // Web-shaped traffic gets a single mitm/splice rule. A host
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
    // failed (likely cert pinning), so splice (preserve the
    // client↔origin handshake) is what works.
    if a.saw_tls && !a.saw_https {
        return "splice";
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

/// Wrappers around `learn_convert`'s private items for the
/// dedicated test crate. Off by default; `hermit-tests` flips on
/// the `__test_internals` feature in its `[dependencies]` entry.
///
/// `TraceEvent`'s fields are private to enforce serde-only
/// construction in production. The wrappers offer constructor
/// helpers (`ev` / `ev_tcp` / `ev_full`) so tests can build
/// fixtures without going through serde.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use super::TraceEvent;
    use anyhow::Result;
    use std::path::Path;

    pub fn ev(kind: &str, host: Option<&str>, method: Option<&str>) -> TraceEvent {
        TraceEvent {
            kind: kind.to_string(),
            hostname: host.map(|s| s.to_string()),
            method: method.map(|s| s.to_string()),
            port: None,
        }
    }

    pub fn ev_tcp(host: Option<&str>, port: u16) -> TraceEvent {
        TraceEvent {
            kind: "tcp_observe".to_string(),
            hostname: host.map(|s| s.to_string()),
            method: None,
            port: Some(port),
        }
    }

    pub fn ev_full(
        kind: &str,
        host: Option<&str>,
        method: Option<&str>,
        port: Option<u16>,
    ) -> TraceEvent {
        TraceEvent {
            kind: kind.to_string(),
            hostname: host.map(|s| s.to_string()),
            method: method.map(|s| s.to_string()),
            port,
        }
    }

    pub fn render(events: &[TraceEvent], input_path: &Path, with_methods: bool) -> String {
        super::render(events, input_path, with_methods)
    }

    pub fn parse_events(text: &str) -> Result<Vec<TraceEvent>> {
        super::parse_events(text)
    }
}
