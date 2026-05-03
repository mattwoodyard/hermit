//! Tests for `sni_proxy::forward`.

use sni_proxy::forward::ForwardConfig;
use sni_proxy::forward::__test_internals::parse_connect_target;
use sni_proxy::policy::{AccessRule, AllowAll, RuleSet};
use std::collections::BTreeSet;
use std::sync::Arc;

#[test]
fn config_builds_with_allow_all() {
    let config = ForwardConfig {
        policy: Arc::new(AllowAll),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        upstream_port: 80,
        allowed_connect_ports: BTreeSet::from([443]),
        mitm: None,
        block_log: sni_proxy::block_log::BlockLogger::disabled(),
        access_log: sni_proxy::block_log::BlockLogger::disabled(),
    };
    assert_eq!(config.upstream_port, 80);
}

#[test]
fn config_builds_with_ruleset() {
    let rules = vec![AccessRule::host_only("example.com")];
    let config = ForwardConfig {
        policy: Arc::new(RuleSet::new(rules)),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        upstream_port: 80,
        allowed_connect_ports: BTreeSet::from([443]),
        mitm: None,
        block_log: sni_proxy::block_log::BlockLogger::disabled(),
        access_log: sni_proxy::block_log::BlockLogger::disabled(),
    };
    assert_eq!(config.upstream_port, 80);
}

#[test]
fn connect_target_parses_host_port() {
    assert_eq!(
        parse_connect_target("example.com:443"),
        Some(("example.com".to_string(), 443))
    );
}

#[test]
fn connect_target_parses_ipv4() {
    assert_eq!(
        parse_connect_target("10.0.0.1:8443"),
        Some(("10.0.0.1".to_string(), 8443))
    );
}

#[test]
fn connect_target_parses_ipv6() {
    assert_eq!(
        parse_connect_target("[::1]:443"),
        Some(("::1".to_string(), 443))
    );
}

#[test]
fn connect_target_rejects_missing_port() {
    // CONNECT authorities must carry a port. Tolerating a bare
    // hostname here would let a proxy-unaware client tunnel to an
    // ambiguous destination.
    assert_eq!(parse_connect_target("example.com"), None);
}

#[test]
fn connect_target_rejects_empty_host() {
    assert_eq!(parse_connect_target(":443"), None);
}

#[test]
fn connect_target_rejects_non_numeric_port() {
    assert_eq!(parse_connect_target("example.com:abc"), None);
}

#[test]
fn connect_target_rejects_unterminated_ipv6() {
    assert_eq!(parse_connect_target("[::1:443"), None);
}
