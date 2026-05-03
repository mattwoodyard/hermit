//! Tests for `sni_proxy::mitm`.

use sni_proxy::ca::CertificateAuthority;
use sni_proxy::mitm::__test_internals::{
    build_server_config_for_test, host_matches_sni_for_test, prefixed_stream,
    touch_static_cert_resolver,
};
use tokio::io::AsyncReadExt;

#[test]
fn static_cert_resolver_returns_cert() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = CertificateAuthority::new().unwrap();
    let ck = ca.cert_for_host("example.com").unwrap();
    touch_static_cert_resolver(ck.clone());

    // Building the server config exercises the resolver
    // through rustls' constructor.
    let config = build_server_config_for_test(ck).unwrap();
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

#[tokio::test]
async fn prefixed_stream_replays_then_reads() {
    let prefix = b"hello ".to_vec();
    let inner: &'static [u8] = b"world";
    let mut stream = prefixed_stream(prefix, inner);

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"hello world");
}

#[tokio::test]
async fn prefixed_stream_empty_prefix() {
    let prefix = Vec::new();
    let inner: &'static [u8] = b"just inner";
    let mut stream = prefixed_stream(prefix, inner);

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"just inner");
}

#[test]
fn host_matches_sni_exact() {
    assert!(host_matches_sni_for_test(Some("api.example.com"), "api.example.com"));
}

#[test]
fn host_matches_sni_case_insensitive() {
    // DNS is case-insensitive and clients send mixed case.
    assert!(host_matches_sni_for_test(Some("API.Example.COM"), "api.example.com"));
}

#[test]
fn host_matches_sni_with_port_strips_port() {
    assert!(host_matches_sni_for_test(Some("api.example.com:8443"), "api.example.com"));
}

#[test]
fn host_matches_sni_rejects_different_host() {
    // The motivating threat: SNI says api.example.com (so the
    // access-control rule for that host applies) but the inner
    // request claims to be for evil.example.com — MUST be
    // rejected so the inject path can't pick a different rule
    // than the access path checked.
    assert!(!host_matches_sni_for_test(Some("evil.example.com"), "api.example.com"));
}

#[test]
fn host_matches_sni_rejects_subdomain_mismatch() {
    // Subdomain mismatch is still a mismatch — the access
    // control rule was for the SNI authority, not its parent.
    assert!(!host_matches_sni_for_test(Some("foo.api.example.com"), "api.example.com"));
    assert!(!host_matches_sni_for_test(Some("api.example.com"), "other.example.com"));
}

#[test]
fn host_matches_sni_missing_host_is_mismatch() {
    // HTTP/1.1 requires Host; absence is conservatively treated
    // as a mismatch so the request is rejected with 421 rather
    // than silently injecting against the SNI fallback.
    assert!(!host_matches_sni_for_test(None, "api.example.com"));
}

#[test]
fn host_matches_sni_ipv6_with_port() {
    // host_without_port keeps the brackets on bracketed IPv6
    // and strips a trailing :port. The SNI side is the bare
    // hostname in our usage — IPv6 SNI is rare but bracketed
    // and unbracketed forms must compare consistently.
    assert!(host_matches_sni_for_test(Some("[::1]:8443"), "[::1]"));
}
