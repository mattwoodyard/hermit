//! Tests for `sni_proxy::policy::ruleset`. All items under test are
//! part of the public `sni_proxy::policy` API, so no
//! `__test_internals` wrappers are needed here.

use std::collections::HashSet;

use sni_proxy::policy::{
    AccessRule, AllowAll, AllowList, BypassProtocol, ConnectionPolicy, IpRule, Mechanism,
    RequestPolicy, RuleSet, Verdict,
};

fn rule_with_mech(host: &str, mechanism: Mechanism) -> AccessRule {
    AccessRule {
        hostname: host.to_string(),
        path_prefix: None,
        methods: None,
        mechanism,
    }
}

fn bypass_rule(host: &str, protocol: BypassProtocol, port: u16) -> AccessRule {
    AccessRule {
        hostname: host.to_string(),
        path_prefix: None,
        methods: None,
        mechanism: Mechanism::Bypass { protocol, port },
    }
}

// --- RuleSet basics ---

#[test]
fn ruleset_hostname_only_like_allowlist() {
    let rs = RuleSet::new(vec![AccessRule::host_only("example.com")]);
    assert_eq!(rs.check("example.com"), Verdict::Allow);
    assert_eq!(rs.check("evil.com"), Verdict::Deny);
}

#[test]
fn ruleset_empty_denies_all() {
    let rs = RuleSet::new(vec![]);
    assert_eq!(rs.check("anything.com"), Verdict::Deny);
    assert_eq!(
        rs.check_request("anything.com", "/", "GET"),
        Verdict::Deny
    );
}

#[test]
fn ruleset_host_check_allows_if_any_rule_matches_host() {
    let rs = RuleSet::new(vec![
        "example.com/api/=GET".parse().unwrap(),
        "example.com/static/".parse().unwrap(),
    ]);
    assert_eq!(rs.check("example.com"), Verdict::Allow);
}

#[test]
fn ruleset_request_check_path_method() {
    let rs = RuleSet::new(vec![
        "example.com/api/=GET".parse().unwrap(),
        "example.com/upload/=POST".parse().unwrap(),
    ]);
    assert_eq!(
        rs.check_request("example.com", "/api/foo", "GET"),
        Verdict::Allow
    );
    assert_eq!(
        rs.check_request("example.com", "/upload/bar", "POST"),
        Verdict::Allow
    );
    assert_eq!(
        rs.check_request("example.com", "/api/foo", "POST"),
        Verdict::Deny
    );
    assert_eq!(
        rs.check_request("example.com", "/other", "GET"),
        Verdict::Deny
    );
}

#[test]
fn ruleset_multiple_hosts() {
    let rs = RuleSet::new(vec![
        AccessRule::host_only("a.com"),
        "b.com/x/=GET".parse().unwrap(),
    ]);
    assert_eq!(rs.check_request("a.com", "/anything", "DELETE"), Verdict::Allow);
    assert_eq!(rs.check_request("b.com", "/x/y", "GET"), Verdict::Allow);
    assert_eq!(rs.check_request("b.com", "/x/y", "POST"), Verdict::Deny);
    assert_eq!(rs.check_request("c.com", "/", "GET"), Verdict::Deny);
}

// --- Legacy types ---

#[test]
fn allowlist_permits_listed_host() {
    let policy = AllowList::new(["example.com".into()].into());
    assert_eq!(policy.check("example.com"), Verdict::Allow);
}

#[test]
fn allowlist_denies_unlisted_host() {
    let policy = AllowList::new(["example.com".into()].into());
    assert_eq!(policy.check("evil.com"), Verdict::Deny);
}

#[test]
fn allowlist_empty_denies_all() {
    let policy = AllowList::new(HashSet::new());
    assert_eq!(policy.check("anything.com"), Verdict::Deny);
}

#[test]
fn allow_all_permits_everything() {
    let policy = AllowAll;
    assert_eq!(policy.check("anything.com"), Verdict::Allow);
    assert_eq!(
        policy.check_request("any.com", "/path", "POST"),
        Verdict::Allow
    );
}

// --- Mechanism dispatch ---

#[test]
fn mechanism_for_unknown_host_is_none() {
    let rs = RuleSet::new(vec![rule_with_mech("ok.example", Mechanism::Mitm)]);
    assert!(rs.mechanism_for("other.example").is_none());
}

#[test]
fn mechanism_for_mitm_rule() {
    let rs = RuleSet::new(vec![rule_with_mech("ok.example", Mechanism::Mitm)]);
    assert_eq!(rs.mechanism_for("ok.example"), Some(Mechanism::Mitm));
}

#[test]
fn mechanism_for_sni_rule() {
    let rs = RuleSet::new(vec![rule_with_mech("pinned.example", Mechanism::Splice)]);
    assert_eq!(rs.mechanism_for("pinned.example"), Some(Mechanism::Splice));
}

#[test]
fn mechanism_mitm_wins_when_rules_conflict() {
    let rs = RuleSet::new(vec![
        rule_with_mech("dual.example", Mechanism::Splice),
        rule_with_mech("dual.example", Mechanism::Mitm),
    ]);
    assert_eq!(rs.mechanism_for("dual.example"), Some(Mechanism::Mitm));
}

#[test]
fn mechanism_lookup_is_case_insensitive() {
    let rs = RuleSet::new(vec![rule_with_mech("Mixed.Example", Mechanism::Splice)]);
    assert_eq!(rs.mechanism_for("mixed.example"), Some(Mechanism::Splice));
    assert_eq!(rs.mechanism_for("MIXED.EXAMPLE"), Some(Mechanism::Splice));
}

// --- Bypass ---

#[test]
fn is_bypass_allowed_happy_path() {
    let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
    assert!(rs.is_bypass_allowed("kdc.example", BypassProtocol::Udp, 88));
}

#[test]
fn is_bypass_allowed_rejects_wrong_protocol() {
    let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
    assert!(!rs.is_bypass_allowed("kdc.example", BypassProtocol::Tcp, 88));
}

#[test]
fn is_bypass_allowed_rejects_wrong_port() {
    let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
    assert!(!rs.is_bypass_allowed("kdc.example", BypassProtocol::Udp, 99));
}

#[test]
fn is_bypass_allowed_rejects_wrong_host() {
    let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
    assert!(!rs.is_bypass_allowed("other.example", BypassProtocol::Udp, 88));
}

#[test]
fn is_bypass_allowed_is_case_insensitive() {
    let rs = RuleSet::new(vec![bypass_rule("KDC.Example", BypassProtocol::Udp, 88)]);
    assert!(rs.is_bypass_allowed("kdc.example", BypassProtocol::Udp, 88));
}

#[test]
fn bypass_rules_do_not_influence_mechanism_for() {
    let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
    assert_eq!(rs.mechanism_for("kdc.example"), None);
}

#[test]
fn is_bypass_allowed_by_ip_happy_path() {
    let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
        ip: "10.0.0.5".parse().unwrap(),
        mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
    }]);
    assert!(rs.is_bypass_allowed_by_ip(
        "10.0.0.5".parse().unwrap(),
        BypassProtocol::Udp,
        88,
    ));
}

#[test]
fn is_bypass_allowed_by_ip_rejects_wrong_proto_port() {
    let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
        ip: "10.0.0.5".parse().unwrap(),
        mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
    }]);
    assert!(!rs.is_bypass_allowed_by_ip(
        "10.0.0.5".parse().unwrap(),
        BypassProtocol::Tcp,
        88,
    ));
    assert!(!rs.is_bypass_allowed_by_ip(
        "10.0.0.5".parse().unwrap(),
        BypassProtocol::Udp,
        99,
    ));
}

#[test]
fn is_bypass_allowed_by_ip_unknown_ip_is_denied() {
    let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
        ip: "10.0.0.5".parse().unwrap(),
        mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
    }]);
    assert!(!rs.is_bypass_allowed_by_ip(
        "10.0.0.99".parse().unwrap(),
        BypassProtocol::Udp,
        88,
    ));
}

// --- permit_all (learn mode) ---

#[test]
fn permit_all_short_circuits_check_and_check_request() {
    let rs = RuleSet::new(vec![]).with_permit_all(true);
    assert_eq!(rs.check("anything.example"), Verdict::Allow);
    assert_eq!(
        rs.check_request("anything.example", "/whatever", "POST"),
        Verdict::Allow
    );
    assert!(rs.is_permit_all());
}

#[test]
fn permit_all_does_not_change_mechanism_for_unknown_host() {
    let rs = RuleSet::new(vec![]).with_permit_all(true);
    assert!(rs.mechanism_for("anything.example").is_none());
    assert_eq!(rs.mechanism("anything.example"), Mechanism::Mitm);
}

// --- bypass endpoints ---

#[test]
fn bypass_endpoints_includes_ip_keyed_rules() {
    let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
        ip: "10.0.0.5".parse().unwrap(),
        mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 389 },
    }]);
    assert_eq!(
        rs.bypass_endpoints(),
        vec![(BypassProtocol::Tcp, 389)]
    );
}

#[test]
fn bypass_endpoints_deduplicates() {
    let rs = RuleSet::new(vec![
        bypass_rule("a.example", BypassProtocol::Udp, 88),
        bypass_rule("b.example", BypassProtocol::Udp, 88),
        bypass_rule("a.example", BypassProtocol::Tcp, 389),
    ]);
    let got = rs.bypass_endpoints();
    assert_eq!(
        got,
        vec![
            (BypassProtocol::Tcp, 389),
            (BypassProtocol::Udp, 88),
        ]
    );
}
