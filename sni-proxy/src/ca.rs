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

        // Fast path: cached
        {
            let cache = self.cache.lock().unwrap();
            if let Some(ck) = cache.get(&key) {
                return Ok(Arc::clone(ck));
            }
        }

        // Generate a new leaf cert
        let certified_key = self.generate_leaf(hostname)?;
        let certified_key = Arc::new(certified_key);

        let mut cache = self.cache.lock().unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::ServerName;

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
            &[],   // ocsp
            now,
        );
        assert!(result.is_ok(), "leaf cert should validate: {:?}", result.err());
    }
}
