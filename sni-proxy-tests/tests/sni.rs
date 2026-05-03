//! Tests for `sni_proxy::sni`. `extract_sni` and `SniResult` are
//! both public — no `__test_internals` wrappers needed.

use rustls::ClientConnection;
use sni_proxy::sni::{extract_sni, SniResult};
use std::sync::Arc;

fn make_client_hello(server_name: &str) -> Vec<u8> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name: rustls::pki_types::ServerName<'static> =
        server_name.to_string().try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).unwrap();
    buf
}

#[test]
fn extracts_sni_from_valid_client_hello() {
    let buf = make_client_hello("example.com");
    match extract_sni(&buf).unwrap() {
        SniResult::Hostname(name) => assert_eq!(name, "example.com"),
        other => panic!("expected Hostname, got {:?}", variant_name(&other)),
    }
}

#[test]
fn incomplete_buffer_returns_incomplete() {
    let buf = make_client_hello("example.com");
    // Truncate to half — should be incomplete
    let partial = &buf[..buf.len() / 2];
    match extract_sni(partial).unwrap() {
        SniResult::Incomplete => {}
        other => panic!("expected Incomplete, got {:?}", variant_name(&other)),
    }
}

#[test]
fn garbage_bytes_returns_error() {
    assert!(extract_sni(b"this is not TLS at all").is_err());
}

#[test]
fn empty_buffer_returns_incomplete() {
    match extract_sni(b"").unwrap() {
        SniResult::Incomplete => {}
        other => panic!("expected Incomplete, got {:?}", variant_name(&other)),
    }
}

fn variant_name(r: &SniResult) -> &'static str {
    match r {
        SniResult::Hostname(_) => "Hostname",
        SniResult::NoSni => "NoSni",
        SniResult::Incomplete => "Incomplete",
    }
}
