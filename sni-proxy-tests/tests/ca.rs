//! Tests for `sni_proxy::ca`. The `CertificateAuthority` API is
//! public; the only private item we need to reach is the cert
//! cache mutex (to poison it), which lives behind the
//! `__test_internals` `poison_cert_cache` wrapper.

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::ServerName;
use sni_proxy::ca::{__test_internals::poison_cert_cache, CertificateAuthority};
use std::sync::Arc;

#[test]
fn ca_generates_without_error() {
    let ca = CertificateAuthority::new().unwrap();
    assert!(!ca.ca_cert_pem().is_empty());
    assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
}

#[test]
fn leaf_cert_has_correct_chain() {
    let ca = CertificateAuthority::new().unwrap();
    let ck = ca.cert_for_host("example.com").unwrap();
    // The cert chain should have 2 certs (leaf + CA)
    assert_eq!(ck.cert.len(), 2);
}

#[test]
fn cache_returns_same_key() {
    let ca = CertificateAuthority::new().unwrap();
    let ck1 = ca.cert_for_host("example.com").unwrap();
    let ck2 = ca.cert_for_host("example.com").unwrap();
    assert!(Arc::ptr_eq(&ck1, &ck2));
}

#[test]
fn different_hosts_get_different_certs() {
    let ca = CertificateAuthority::new().unwrap();
    let ck1 = ca.cert_for_host("a.com").unwrap();
    let ck2 = ca.cert_for_host("b.com").unwrap();
    assert!(!Arc::ptr_eq(&ck1, &ck2));
}

#[test]
fn poisoned_cache_mutex_does_not_block_cert_issuance() {
    // A previous panic holder on the cert cache must not prevent new
    // cert issuance. Without the `unwrap_or_else(into_inner)` recovery
    // in `cert_for_host`, a single panicking request would take down
    // every concurrent MITM handler.
    let ca = Arc::new(CertificateAuthority::new().unwrap());

    // Panic inside a thread while holding the cache lock, so the
    // std::sync::Mutex gets marked poisoned.
    poison_cert_cache(Arc::clone(&ca));

    // Lock is now poisoned. The recovery path must still return a cert.
    let ck = ca.cert_for_host("example.com").expect(
        "poisoned mutex must not fail cert_for_host — recovery is via into_inner()",
    );
    assert_eq!(ck.cert.len(), 2);

    // Second call must hit the cache and return the same Arc.
    let ck2 = ca.cert_for_host("example.com").unwrap();
    assert!(Arc::ptr_eq(&ck, &ck2));
}

#[test]
fn leaf_validates_against_ca() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = CertificateAuthority::new().unwrap();

    // Build a rustls root store containing our CA
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca.ca_cert_der().clone()).unwrap();

    // Build a verifier from the root store
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .unwrap();

    // Verify the leaf cert chain
    let ck = ca.cert_for_host("example.com").unwrap();
    let server_name = ServerName::try_from("example.com").unwrap();
    let now = rustls::pki_types::UnixTime::now();

    let result = verifier.verify_server_cert(
        &ck.cert[0],
        &ck.cert[1..],
        &server_name,
        &[], // ocsp
        now,
    );
    assert!(result.is_ok(), "leaf cert should validate: {:?}", result.err());
}
