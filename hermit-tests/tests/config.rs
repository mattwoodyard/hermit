//! Tests for `hermit::config`. Every symbol the tests touch is
//! already public — `Config`, `NetMode`, `PortProtocol`,
//! `HomeFileDirective`, and the `sni_proxy::policy::*` types — so
//! this file uses no `__test_internals` wrappers.

use std::path::{Path, PathBuf};

use hermit::config::{Config, NetMode, PortProtocol};
use hermit::home_files::HomeFileDirective;

const FULL: &str = r#"
[sandbox]
net = "isolate"
passthrough = ["/opt/extra"]

[[home_file]]
action = "pass"
path = "~/.ssh"

[[home_file]]
action = "copy"
path = "~/.gitconfig"

[[access_rule]]
host = "registry.npmjs.org"

[[access_rule]]
host = "api.github.com"
path_prefix = "/repos/"
methods = ["GET", "POST"]

[[rule]]
match = 'url.host == "api.github.com"'
credential = "gh"

[credential.gh]
source = { type = "env", name = "GITHUB_TOKEN" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]

[signature]
cert = "BASE64_CERT"
signature = "BASE64_SIG"
algorithm = "ed25519"
"#;

#[test]
fn parses_full_example() {
    let c = Config::parse(FULL).unwrap();
    let sb = c.sandbox();
    assert_eq!(sb.net, NetMode::Isolate);
    assert_eq!(sb.passthrough, vec![PathBuf::from("/opt/extra")]);
    assert_eq!(c.home_files.len(), 2);
    assert_eq!(c.access_rules.len(), 2);
    assert_eq!(c.injection_rules.len(), 1);
    assert_eq!(c.credential.len(), 1);
    let sig = c.signature.as_ref().unwrap();
    assert_eq!(sig.algorithm, "ed25519");
}

#[test]
fn home_files_adapt_and_expand_tilde() {
    let c = Config::parse(FULL).unwrap();
    let dirs = c.home_file_directives(Path::new("/home/u")).unwrap();
    assert_eq!(
        dirs,
        vec![
            HomeFileDirective::Pass(PathBuf::from("/home/u/.ssh")),
            HomeFileDirective::Copy(PathBuf::from("/home/u/.gitconfig")),
        ]
    );
}

#[test]
fn home_files_reject_dotdot() {
    let toml = r#"
[[home_file]]
action = "pass"
path = "../escape"
"#;
    let c = Config::parse(toml).unwrap();
    assert!(c.home_file_directives(Path::new("/home/u")).is_err());
}

#[test]
fn home_files_hide_action_round_trips() {
    // The motivating shape: pass a parent dir but hide a
    // specific child so the sandbox can't read the host's
    // credential file even though the parent is bind-mounted.
    let toml = r#"
[[home_file]]
action = "pass"
path = "~/.claude"

[[home_file]]
action = "hide"
path = "~/.claude/.credentials.json"
"#;
    let c = Config::parse(toml).unwrap();
    let dirs = c.home_file_directives(Path::new("/home/u")).unwrap();
    assert_eq!(
        dirs,
        vec![
            HomeFileDirective::Pass(PathBuf::from("/home/u/.claude")),
            HomeFileDirective::Hide(PathBuf::from(
                "/home/u/.claude/.credentials.json"
            )),
        ]
    );
}

#[test]
fn home_files_unknown_action_rejected() {
    let toml = r#"
[[home_file]]
action = "obliterate"
path = "~/.foo"
"#;
    // serde rejects unknown enum variants at deserialize time.
    // `{:#}` flattens the anyhow chain so we see the
    // underlying serde message, not just the top-level
    // "parsing hermit config TOML" context.
    let err = format!("{:#}", Config::parse(toml).unwrap_err());
    for variant in ["hide", "redirect"] {
        assert!(err.contains(variant), "deserialize chain must list {variant}: {err}");
    }
}

#[test]
fn home_files_redirect_action_round_trips() {
    let toml = r#"
[[home_file]]
action = "redirect"
path = "~/.aws/credentials"
source = "/etc/hermit/build-aws"
"#;
    let c = Config::parse(toml).unwrap();
    let dirs = c.home_file_directives(Path::new("/home/u")).unwrap();
    assert_eq!(
        dirs,
        vec![HomeFileDirective::Redirect {
            path: PathBuf::from("/home/u/.aws/credentials"),
            source: PathBuf::from("/etc/hermit/build-aws"),
        }]
    );
}

#[test]
fn home_files_redirect_without_source_errors() {
    let toml = r#"
[[home_file]]
action = "redirect"
path = "~/.aws/credentials"
"#;
    let c = Config::parse(toml).unwrap();
    let err = c
        .home_file_directives(Path::new("/home/u"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("source"), "error should mention source: {err}");
}

#[test]
fn home_files_source_only_meaningful_with_redirect() {
    // Catching this at config-load time surfaces the typo
    // "I gave a source on a pass directive" before any mounts
    // happen — easier to diagnose than a silently-ignored field.
    let toml = r#"
[[home_file]]
action = "pass"
path = "~/.foo"
source = "/etc/something"
"#;
    let c = Config::parse(toml).unwrap();
    let err = c
        .home_file_directives(Path::new("/home/u"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("source"), "error should mention source: {err}");
    assert!(err.contains("redirect"), "error should mention redirect: {err}");
}

#[test]
fn access_rules_adapt_with_methods() {
    let c = Config::parse(FULL).unwrap();
    let rules = c.access_rules().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].hostname, "registry.npmjs.org");
    assert!(rules[0].methods.is_none());
    assert_eq!(rules[1].hostname, "api.github.com");
    assert_eq!(rules[1].path_prefix.as_deref(), Some("/repos/"));
    assert_eq!(rules[1].methods.as_ref().unwrap().len(), 2);
}

#[test]
fn access_rule_unknown_method_is_error() {
    let toml = r#"
[[access_rule]]
host = "x"
methods = ["BOGUS"]
"#;
    let c = Config::parse(toml).unwrap();
    assert!(c.access_rules().is_err());
}

#[test]
fn access_rule_default_mechanism_is_mitm() {
    let toml = r#"
[[access_rule]]
host = "x"
"#;
    let c = Config::parse(toml).unwrap();
    let rules = c.access_rules().unwrap();
    assert_eq!(rules[0].mechanism, sni_proxy::policy::Mechanism::Mitm);
}

#[test]
fn access_rule_sni_mechanism_parses() {
    let toml = r#"
[[access_rule]]
host = "pinned.example"
mechanism = "splice"
"#;
    let c = Config::parse(toml).unwrap();
    let rules = c.access_rules().unwrap();
    assert_eq!(rules[0].mechanism, sni_proxy::policy::Mechanism::Splice);
}

#[test]
fn access_rule_splice_with_path_prefix_is_error() {
    // A `splice` rule relays without inspecting HTTP —
    // silently ignoring `path_prefix` would widen the
    // allowlist, so parse must reject it. The error must
    // name the offending field.
    let toml = r#"
[[access_rule]]
host = "pinned.example"
mechanism = "splice"
path_prefix = "/api/"
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.access_rules().expect_err("sni + path_prefix must fail");
    assert!(err.to_string().contains("path_prefix"),
        "error must mention path_prefix, got: {err}");
}

#[test]
fn access_rule_sni_with_methods_is_error() {
    let toml = r#"
[[access_rule]]
host = "pinned.example"
mechanism = "splice"
methods = ["GET"]
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.access_rules().expect_err("sni + methods must fail");
    assert!(err.to_string().contains("methods"),
        "error must mention methods, got: {err}");
}

#[test]
fn access_rule_unknown_mechanism_is_error() {
    // Guards against typos like `mechanism = "snipassthrough"`
    // silently falling back to the default.
    let toml = r#"
[[access_rule]]
host = "x"
mechanism = "bogus"
"#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn access_rule_bypass_parses_tcp_and_udp() {
    let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
port = 88

[[access_rule]]
host = "ldap.example"
mechanism = "bypass"
protocol = "tcp"
port = 389
"#;
    let c = Config::parse(toml).unwrap();
    let rules = c.access_rules().unwrap();
    use sni_proxy::policy::{BypassProtocol, Mechanism};
    assert_eq!(
        rules[0].mechanism,
        Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 }
    );
    assert_eq!(
        rules[1].mechanism,
        Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 389 }
    );
}

#[test]
fn access_rule_bypass_requires_protocol() {
    let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
port = 88
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.access_rules().unwrap_err().to_string();
    assert!(err.contains("protocol"), "error should name `protocol`: {err}");
}

#[test]
fn access_rule_bypass_requires_port() {
    let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.access_rules().unwrap_err().to_string();
    assert!(err.contains("port"), "error should name `port`: {err}");
}

#[test]
fn access_rule_bypass_rejects_reserved_ports() {
    // 80 + 443 belong to the MITM/HTTP listeners — a bypass rule
    // there would silently break interception for every other
    // host on that port, so the config loader rejects it.
    for port in [80u16, 443] {
        let toml = format!(
            r#"
[[access_rule]]
host = "pinned.example"
mechanism = "bypass"
protocol = "tcp"
port = {port}
"#
        );
        let c = Config::parse(&toml).unwrap();
        let err = c.access_rules().unwrap_err().to_string();
        assert!(
            err.contains("reserved"),
            "port {port} should be rejected as reserved, got: {err}"
        );
    }
}

#[test]
fn access_rule_bypass_rejects_path_prefix_and_methods() {
    let toml_path = r#"
[[access_rule]]
host = "x"
mechanism = "bypass"
protocol = "tcp"
port = 8080
path_prefix = "/api/"
"#;
    let err = Config::parse(toml_path)
        .unwrap()
        .access_rules()
        .unwrap_err()
        .to_string();
    assert!(err.contains("path_prefix"));

    let toml_methods = r#"
[[access_rule]]
host = "x"
mechanism = "bypass"
protocol = "tcp"
port = 8080
methods = ["GET"]
"#;
    let err = Config::parse(toml_methods)
        .unwrap()
        .access_rules()
        .unwrap_err()
        .to_string();
    assert!(err.contains("methods"));
}

#[test]
fn access_rule_ip_bypass_parses() {
    let toml = r#"
[[access_rule]]
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
    let c = Config::parse(toml).unwrap();
    let (host_rules, ip_rules) = c.compile_rules().unwrap();
    assert!(host_rules.is_empty());
    assert_eq!(ip_rules.len(), 1);
    assert_eq!(ip_rules[0].ip, "10.0.0.5".parse::<std::net::IpAddr>().unwrap());
    use sni_proxy::policy::{BypassProtocol, Mechanism};
    assert_eq!(
        ip_rules[0].mechanism,
        Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 }
    );
}

#[test]
fn access_rule_requires_host_or_ip() {
    let toml = r#"
[[access_rule]]
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.compile_rules().unwrap_err().to_string();
    assert!(err.contains("must set either `host`") || err.contains("must set either"));
}

#[test]
fn access_rule_host_and_ip_are_mutually_exclusive() {
    let toml = r#"
[[access_rule]]
host = "x.example"
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.compile_rules().unwrap_err().to_string();
    assert!(err.contains("mutually exclusive"));
}

#[test]
fn access_rule_ip_rejects_mitm_mechanism() {
    let toml = r#"
[[access_rule]]
ip = "10.0.0.5"
mechanism = "mitm"
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.compile_rules().unwrap_err().to_string();
    assert!(err.contains("mitm"));
}

#[test]
fn access_rule_ip_rejects_splice_mechanism() {
    let toml = r#"
[[access_rule]]
ip = "10.0.0.5"
mechanism = "splice"
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.compile_rules().unwrap_err().to_string();
    assert!(err.contains("splice"));
}

#[test]
fn access_rule_mixed_host_and_ip_configs_both_compile() {
    let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
port = 88

[[access_rule]]
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
    let c = Config::parse(toml).unwrap();
    let (host_rules, ip_rules) = c.compile_rules().unwrap();
    assert_eq!(host_rules.len(), 1);
    assert_eq!(ip_rules.len(), 1);
}

#[test]
fn access_rule_protocol_port_require_bypass_mechanism() {
    // If someone accidentally drops `mechanism = "bypass"` but
    // leaves the protocol/port fields, they clearly meant bypass
    // — surfacing the error tells them to add it rather than
    // silently promoting the rule to a MITM rule that ignores
    // both fields.
    let toml = r#"
[[access_rule]]
host = "x"
protocol = "tcp"
port = 8080
"#;
    let c = Config::parse(toml).unwrap();
    let err = c.access_rules().unwrap_err().to_string();
    assert!(err.contains("bypass"));
}

#[test]
fn dns_default_upstream_is_cloudflare() {
    // Matches the documented default — don't silently move users
    // off it. If you change the default, also change this test
    // plus the doc string on `default_dns_upstream`.
    let c = Config::parse("").unwrap();
    assert_eq!(c.dns().upstream, "1.1.1.1:53");
    assert!(c.dns_override.is_none(), "absent [dns] must leave override at None");
    let addr = c.dns().upstream_addr().unwrap();
    assert_eq!(addr.port(), 53);
}

#[test]
fn dns_upstream_override_parses() {
    let toml = r#"
[dns]
upstream = "8.8.8.8:53"
"#;
    let c = Config::parse(toml).unwrap();
    assert_eq!(c.dns().upstream, "8.8.8.8:53");
    assert!(c.dns_override.is_some(), "present [dns] must set the override");
    assert!(c.dns().upstream_addr().is_ok());
}

#[test]
fn dns_upstream_malformed_addr_is_error_at_load_time() {
    // We don't want a bad `upstream` value to fail on the first
    // DNS query — catch it at config parse so the user sees the
    // problem before any work is done.
    let toml = r#"
[dns]
upstream = "not-an-address"
"#;
    let c = Config::parse(toml).unwrap();
    assert!(c.dns().upstream_addr().is_err());
}

#[test]
fn dns_override_survives_merge_with_include_lacking_dns() {
    // Regression: before this fix, every parsed config always
    // produced a `DnsConfig { upstream: "1.1.1.1:53" }` (via
    // serde `default`) and the merge blindly replaced `self.dns`
    // with `other.dns`, silently clobbering the top-level
    // override with whatever the last-merged include reported.
    let mut top = Config::parse(
        r#"
[dns]
upstream = "9.9.9.9:53"
"#,
    )
    .unwrap();
    // Include simulates a shared ruleset with no `[dns]` block.
    let include: Config = Config::parse(
        r#"
[[access_rule]]
host = "shared.example"
"#,
    )
    .unwrap();
    top.merge_from(include);
    assert_eq!(top.dns().upstream, "9.9.9.9:53",
        "top-level [dns] must survive merging an include that has no [dns]");
}

#[test]
fn dns_override_last_writer_wins_across_merges() {
    // When an include explicitly sets [dns], it overrides the
    // accumulator — matching the documented "last writer wins"
    // semantics for scalar/table fields.
    let mut acc = Config::parse(
        r#"
[dns]
upstream = "9.9.9.9:53"
"#,
    )
    .unwrap();
    let later: Config = Config::parse(
        r#"
[dns]
upstream = "8.8.8.8:53"
"#,
    )
    .unwrap();
    acc.merge_from(later);
    assert_eq!(acc.dns().upstream, "8.8.8.8:53");
}

#[test]
fn dns_unknown_field_is_rejected() {
    // Guard against typos in the `[dns]` section being silently
    // ignored — `deny_unknown_fields` on `DnsConfig` enforces
    // this but a test pins the behavior.
    let toml = r#"
[dns]
upstream = "1.1.1.1:53"
servers = ["8.8.8.8:53"]
"#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn access_rule_empty_methods_list_is_error() {
    let toml = r#"
[[access_rule]]
host = "x"
methods = []
"#;
    let c = Config::parse(toml).unwrap();
    assert!(c.access_rules().is_err());
}

#[test]
fn network_policy_present_when_rules_exist() {
    let c = Config::parse(FULL).unwrap();
    assert!(c.network_policy().unwrap().is_some());
}

#[test]
fn network_policy_absent_when_no_rules() {
    let c = Config::parse("[sandbox]\nnet = \"host\"").unwrap();
    assert!(c.network_policy().unwrap().is_none());
}

#[test]
fn network_policy_rule_refers_unknown_credential_errors() {
    let toml = r#"
[[rule]]
match = 'url.host == "x"'
credential = "ghost"
"#;
    let c = Config::parse(toml).unwrap();
    assert!(c.network_policy().is_err());
}

#[test]
fn minimal_config_parses() {
    let c = Config::parse("").unwrap();
    assert_eq!(c.sandbox().net, NetMode::Host);
    assert!(c.home_files.is_empty());
    assert!(c.access_rules.is_empty());
    assert!(c.signature.is_none());
}

#[test]
fn unknown_top_level_field_is_error() {
    let toml = r#"
[sandbox]
net = "host"

[what_is_this]
nope = true
"#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn unknown_sandbox_field_is_error() {
    let toml = r#"
[sandbox]
net = "host"
rogue_field = 1
"#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn net_mode_conversion() {
    assert_eq!(NetMode::Host.to_cli(), hermit::cli::NetMode::Host);
    assert_eq!(NetMode::Isolate.to_cli(), hermit::cli::NetMode::Isolate);
}

#[test]
fn port_forward_parses_defaults_to_https() {
    let toml = r#"
[[port_forward]]
port = 8443
"#;
    let c = Config::parse(toml).unwrap();
    assert_eq!(c.port_forwards.len(), 1);
    assert_eq!(c.port_forwards[0].port, 8443);
    assert_eq!(c.port_forwards[0].protocol, PortProtocol::Https);
}

#[test]
fn port_forward_parses_http() {
    let toml = r#"
[[port_forward]]
port = 8080
protocol = "http"
"#;
    let c = Config::parse(toml).unwrap();
    assert_eq!(c.port_forwards[0].protocol, PortProtocol::Http);
}

#[test]
fn port_forward_rejects_reserved() {
    for p in [1443, 1080] {
        let toml = format!("[[port_forward]]\nport = {}\n", p);
        let err = Config::parse(&toml).unwrap_err().to_string();
        assert!(err.contains("reserved"), "got: {err}");
    }
}

#[test]
fn port_forward_rejects_duplicate() {
    let toml = r#"
[[port_forward]]
port = 8443
[[port_forward]]
port = 8443
protocol = "http"
"#;
    let err = Config::parse(toml).unwrap_err().to_string();
    assert!(err.contains("listed twice"), "got: {err}");
}

#[test]
fn port_forward_rejects_zero() {
    let toml = r#"
[[port_forward]]
port = 0
"#;
    let err = Config::parse(toml).unwrap_err().to_string();
    assert!(err.contains("not valid"), "got: {err}");
}

#[test]
fn port_forward_rejects_unknown_protocol() {
    let toml = r#"
[[port_forward]]
port = 9000
protocol = "quic"
"#;
    assert!(Config::parse(toml).is_err());
}

#[test]
fn include_field_parses_as_empty_by_default() {
    let c = Config::parse("").unwrap();
    assert!(c.include.is_empty());
}

#[test]
fn include_field_parses_urls() {
    let c = Config::parse(r#"include = ["file:///a.toml", "file:///b.toml"]"#).unwrap();
    assert_eq!(c.include.len(), 2);
    assert_eq!(c.include[0], "file:///a.toml");
}

#[test]
fn merge_appends_arrays_other_last() {
    // Base config has one rule; `other` adds another. Since the
    // include protocol treats the including file as "other" (merged
    // last), the including file's entries land after the included
    // file's entries when the caller sets up `self = includes_merged`.
    let mut a = Config::parse(r#"[[access_rule]]
host = "a.com""#).unwrap();
    let b = Config::parse(r#"[[access_rule]]
host = "b.com""#).unwrap();
    a.merge_from(b);
    let rules = a.access_rules().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].hostname, "a.com");
    assert_eq!(rules[1].hostname, "b.com");
}

#[test]
fn merge_sandbox_other_overrides_when_present() {
    let mut a = Config::parse(r#"[sandbox]
net = "host""#).unwrap();
    let b = Config::parse(r#"[sandbox]
net = "isolate""#).unwrap();
    a.merge_from(b);
    assert_eq!(a.sandbox().net, NetMode::Isolate);
}

#[test]
fn merge_sandbox_absent_in_other_preserves_self() {
    let mut a = Config::parse(r#"[sandbox]
net = "isolate""#).unwrap();
    let b = Config::parse("").unwrap();
    a.merge_from(b);
    assert_eq!(a.sandbox().net, NetMode::Isolate);
}

#[test]
fn merge_credential_last_writer_wins_per_key() {
    let mut a = Config::parse(r#"
[credential.gh]
source = { type = "env", name = "FIRST" }
inject = [{ header = "X-Tok", value = "{cred}" }]
"#).unwrap();
    let b = Config::parse(r#"
[credential.gh]
source = { type = "env", name = "SECOND" }
inject = [{ header = "X-Tok", value = "{cred}" }]
"#).unwrap();
    a.merge_from(b);
    // `other` wins for same key — inspect via serde round-trip of the
    // underlying Credential (no public accessor, so use Debug).
    let dbg = format!("{:?}", a.credential.get("gh").unwrap());
    assert!(dbg.contains("SECOND"), "expected SECOND to win, got: {dbg}");
}

#[test]
fn merge_clears_signature() {
    let mut a = Config::parse(r#"
[signature]
cert = "AA"
signature = "BB"
algorithm = "ed25519"
"#).unwrap();
    assert!(a.signature.is_some());
    let b = Config::parse("").unwrap();
    a.merge_from(b);
    assert!(a.signature.is_none(), "signature must not survive merge");
}

#[test]
fn merge_concatenates_home_files_port_forwards_and_rules() {
    let mut a = Config::parse(r#"
[[home_file]]
action = "copy"
path = "~/.bashrc"
[[port_forward]]
port = 8443
"#).unwrap();
    let b = Config::parse(r#"
[[home_file]]
action = "pass"
path = "~/.ssh"
[[port_forward]]
port = 8080
protocol = "http"
[[rule]]
match = 'url.host == "x.com"'
credential = "gh"
[credential.gh]
source = { type = "env", name = "GH" }
inject = [{ header = "A", value = "{cred}" }]
"#).unwrap();
    a.merge_from(b);
    assert_eq!(a.home_files.len(), 2);
    assert_eq!(a.port_forwards.len(), 2);
    assert_eq!(a.injection_rules.len(), 1);
    assert_eq!(a.credential.len(), 1);
}
