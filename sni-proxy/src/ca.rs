//! Ephemeral CA for MITM TLS interception.
//!
//! Generates a self-signed CA certificate at startup, then produces
//! per-host leaf certificates on the fly (cached after first use).
//! The CA cert is installed in the sandbox trust store so build tools
//! accept the intercepted connections.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Ephemeral certificate authority for MITM proxy.
pub struct CertificateAuthority {
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    /// The rcgen CA certificate, used for signing leaf certs.
    ca_cert: Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertificateAuthority {
    /// Generate a new ephemeral CA.
    pub fn new() -> Result<Self> {
        let ca_key = KeyPair::generate()
            .context("failed to generate CA key pair")?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "hermit ephemeral CA");
        params.distinguished_name.push(DnType::OrganizationName, "hermit sandbox");
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2038, 1, 1);

        let ca_cert = params
            .self_signed(&ca_key)
            .context("failed to self-sign CA certificate")?;

        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            ca_cert_der,
            ca_cert_pem,
            ca_cert,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate in PEM format (for trust store installation).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// The CA certificate in DER format.
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Get or generate a leaf certificate for the given hostname.
    ///
    /// Results are cached — the same `CertifiedKey` is returned for
    /// repeated requests with the same hostname.
    pub fn cert_for_host(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
        let key = hostname.to_ascii_lowercase();

        // Fast path: cached.
        //
        // Recover from a poisoned lock (`into_inner()` on the poison
        // error) — a panic in a previous holder has no cross-entry
        // invariants to violate for this cache, so the worst case is a
        // stale entry we'd have regenerated anyway. Panicking here would
        // take down every concurrent MITM handler.
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ck) = cache.get(&key) {
                return Ok(Arc::clone(ck));
            }
        }

        // Generate a new leaf cert
        let certified_key = self.generate_leaf(hostname)?;
        let certified_key = Arc::new(certified_key);

        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(key, Arc::clone(&certified_key));
        Ok(certified_key)
    }

    /// Generate a leaf certificate for a single hostname, signed by this CA.
    fn generate_leaf(&self, hostname: &str) -> Result<CertifiedKey> {
        let leaf_key = KeyPair::generate()
            .context("failed to generate leaf key pair")?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(hostname.try_into().context("invalid DNS name")?));
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2038, 1, 1);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .context("failed to sign leaf certificate")?;

        let leaf_cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let leaf_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&leaf_key_der)
            .context("failed to create rustls signing key")?;

        // Chain: leaf cert + CA cert
        let cert_chain = vec![leaf_cert_der, self.ca_cert_der.clone()];

        Ok(CertifiedKey::new(cert_chain, signing_key))
    }
}
/// Test-only wrappers around `CertificateAuthority`'s private state.
/// Off by default; `sni-proxy-tests` flips on `__test_internals` in
/// its dependency on `sni-proxy`.
///
/// The cache mutex is exposed via a function that deliberately
/// poisons it — that's the only thing tests need to reach for, and
/// returning the `Mutex` directly would require leaking the
/// `HashMap<String, Arc<CertifiedKey>>` type through a public API.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use super::CertificateAuthority;
    use std::sync::Arc;

    /// Spawn a thread that locks the cert cache and panics, leaving
    /// the `std::sync::Mutex` poisoned. Joins the panicking thread
    /// before returning so the lock is dropped (still in poisoned
    /// state) by the time the caller resumes.
    pub fn poison_cert_cache(ca: Arc<CertificateAuthority>) {
        let ca_for_panic = Arc::clone(&ca);
        let _ = std::thread::spawn(move || {
            let _guard = ca_for_panic.cache.lock().unwrap();
            panic!("simulated panic while holding cache lock");
        })
        .join();
    }
}
