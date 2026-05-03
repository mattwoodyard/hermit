//! Tests for `sni_proxy::policy::rule`.
//!
//! `AccessRule::matches` and `AccessRule::matches_host` are
//! `pub(crate)` so they aren't reachable directly from this crate.
//! Reach them via `sni_proxy::policy::__test_internals` (only
//! available because sni-proxy-tests turns on the
//! `__test_internals` feature).

use sni_proxy::policy::{
    AccessRule, HttpMethod, Mechanism,
};
use sni_proxy::policy::__test_internals::rule_matches;

// --- AccessRule parsing ---

#[test]
fn parse_rule_hostname_only() {
    let rule: AccessRule = "example.com".parse().unwrap();
    assert_eq!(rule.hostname, "example.com");
    assert!(rule.path_prefix.is_none());
    assert!(rule.methods.is_none());
}

#[test]
fn parse_rule_with_path() {
    let rule: AccessRule = "example.com/api/v1/".parse().unwrap();
    assert_eq!(rule.hostname, "example.com");
    assert_eq!(rule.path_prefix.as_deref(), Some("/api/v1/"));
    assert!(rule.methods.is_none());
}

#[test]
fn parse_rule_with_path_and_methods() {
    let rule: AccessRule = "example.com/api/v1/=GET,POST".parse().unwrap();
    assert_eq!(rule.hostname, "example.com");
    assert_eq!(rule.path_prefix.as_deref(), Some("/api/v1/"));
    let methods = rule.methods.unwrap();
    assert!(methods.contains(&HttpMethod::Get));
    assert!(methods.contains(&HttpMethod::Post));
    assert_eq!(methods.len(), 2);
}

#[test]
fn parse_rule_hostname_with_methods_no_path() {
    let rule: AccessRule = "example.com=GET".parse().unwrap();
    assert_eq!(rule.hostname, "example.com");
    assert!(rule.path_prefix.is_none());
    let methods = rule.methods.unwrap();
    assert!(methods.contains(&HttpMethod::Get));
    assert_eq!(methods.len(), 1);
}

#[test]
fn parse_rule_uppercase_hostname_lowered() {
    let rule: AccessRule = "Example.COM".parse().unwrap();
    assert_eq!(rule.hostname, "example.com");
}

#[test]
fn parse_rule_empty_fails() {
    assert!("".parse::<AccessRule>().is_err());
    assert!("  ".parse::<AccessRule>().is_err());
}

#[test]
fn parse_rule_empty_methods_fails() {
    assert!("example.com=".parse::<AccessRule>().is_err());
}

#[test]
fn parse_rule_invalid_method_fails() {
    assert!("example.com=CONNECT".parse::<AccessRule>().is_err());
}

// --- AccessRule matching ---

#[test]
fn rule_matches_host_only() {
    let rule = AccessRule::host_only("example.com");
    assert!(rule_matches(&rule, "example.com", "/anything", "GET"));
    assert!(rule_matches(&rule, "example.com", "/foo/bar", "POST"));
    assert!(!rule_matches(&rule, "other.com", "/", "GET"));
}

#[test]
fn rule_matches_path_prefix() {
    let rule: AccessRule = "example.com/api/".parse().unwrap();
    assert!(rule_matches(&rule, "example.com", "/api/v1/foo", "GET"));
    assert!(rule_matches(&rule, "example.com", "/api/", "POST"));
    assert!(!rule_matches(&rule, "example.com", "/other", "GET"));
}

#[test]
fn rule_matches_methods() {
    let rule: AccessRule = "example.com=GET,HEAD".parse().unwrap();
    assert!(rule_matches(&rule, "example.com", "/any", "GET"));
    assert!(rule_matches(&rule, "example.com", "/any", "HEAD"));
    assert!(!rule_matches(&rule, "example.com", "/any", "POST"));
    assert!(!rule_matches(&rule, "example.com", "/any", "DELETE"));
}

#[test]
fn rule_matches_path_and_methods() {
    let rule: AccessRule = "example.com/api/=GET".parse().unwrap();
    assert!(rule_matches(&rule, "example.com", "/api/foo", "GET"));
    assert!(!rule_matches(&rule, "example.com", "/api/foo", "POST"));
    assert!(!rule_matches(&rule, "example.com", "/other", "GET"));
}

#[test]
fn rule_matches_case_insensitive_host() {
    let rule = AccessRule::host_only("example.com");
    assert!(rule_matches(&rule, "Example.COM", "/", "GET"));
}

// --- Mechanism default ---

#[test]
fn mechanism_default_is_mitm() {
    let r: AccessRule = "host.example".parse().unwrap();
    assert_eq!(r.mechanism, Mechanism::Mitm);
}

// --- path traversal ---

fn rule_with_prefix(host: &str, prefix: &str) -> AccessRule {
    AccessRule {
        hostname: host.to_string(),
        path_prefix: Some(prefix.to_string()),
        methods: None,
        mechanism: Mechanism::Mitm,
    }
}

#[test]
fn matches_rejects_literal_dotdot_in_prefix_path() {
    let r = rule_with_prefix("api.example", "/repos/");
    assert!(rule_matches(&r, "api.example", "/repos/foo", "GET"));
    assert!(!rule_matches(&r, "api.example", "/repos/../user/keys", "GET"));
    assert!(!rule_matches(&r, "api.example", "/repos/..", "GET"));
}

#[test]
fn matches_rejects_percent_encoded_dotdot_in_prefix_path() {
    let r = rule_with_prefix("api.example", "/repos/");
    assert!(!rule_matches(&r, "api.example", "/repos/%2e%2e/user", "GET"));
    assert!(!rule_matches(&r, "api.example", "/repos/%2E%2E/user", "GET"));
    assert!(!rule_matches(&r, "api.example", "/repos/.%2e/user", "GET"));
    assert!(!rule_matches(&r, "api.example", "/repos/%2e./user", "GET"));
}

#[test]
fn matches_allows_double_dot_inside_a_segment() {
    let r = rule_with_prefix("api.example", "/repos/");
    assert!(rule_matches(&r, "api.example", "/repos/foo..bar", "GET"));
    assert!(rule_matches(&r, "api.example", "/repos/.config", "GET"));
}

#[test]
fn matches_dotdot_check_only_applies_when_prefix_is_set() {
    let r = AccessRule::host_only("api.example");
    assert!(rule_matches(&r, "api.example", "/anything/../else", "GET"));
}

#[test]
fn matches_ignores_dotdot_in_query_string() {
    let r = rule_with_prefix("api.example", "/repos/");
    assert!(rule_matches(&r, "api.example", "/repos/x?ref=..", "GET"));
}
