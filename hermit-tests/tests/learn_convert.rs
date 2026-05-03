//! Tests for `hermit::learn_convert`.
//!
//! Reaches into private items via `hermit::learn_convert::__test_internals`
//! (only available because hermit-tests turns on the
//! `__test_internals` feature).

use hermit::cli::LearnConvertArgs;
use hermit::learn_convert::__test_internals::{ev, ev_full, ev_tcp, parse_events, render};
use hermit::learn_convert::convert;
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
fn render_guesses_splice_when_tls_handshake_did_not_produce_request() {
    // Cert-pinning client: hermit MITM never decrypted, so we
    // saw `tls_hostname` allow events without any subsequent
    // `https`. Suggest splice so the user gets a working policy.
    let events = vec![
        ev("dns", Some("pinned.example"), None),
        ev("tls_hostname", Some("pinned.example"), None),
    ];
    let out = render(&events, &dummy_path(), false);
    assert!(out.contains(r#"mechanism = "splice""#),
        "expected splice guess for TLS-only host: {out}");
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
fn render_with_methods_does_not_decorate_splice_rules() {
    // splice rules don't accept `methods`; emitting one here
    // would produce a config the runtime rejects.
    let events = vec![ev("tls_hostname", Some("pinned.example"), None)];
    let out = render(&events, &dummy_path(), true);
    assert!(out.contains(r#"mechanism = "splice""#));
    assert!(!out.contains("methods"),
        "methods must not be emitted for splice rules: {out}");
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
    let bad = ev_full("tcp_observe", Some("svc.example"), None, None);
    let out = render(&[bad], &dummy_path(), false);
    assert!(!out.contains("[[access_rule]]"),
        "tcp_observe without a port should produce no rule: {out}");
}
