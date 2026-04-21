//! Detached in-file signature for hermit config TOML.
//!
//! The signing scheme is deliberately simple:
//!
//!   * Signed payload = all bytes of the TOML file before the first line
//!     at column 0 that reads exactly `[signature]`. The signature
//!     section itself (and any trailing whitespace after it) is excluded.
//!   * Algorithm = ed25519. The signing identity is an x509 certificate
//!     (ed25519 key); the cert travels in the `[signature]` section as
//!     base64-encoded DER.
//!   * Trust anchor = `~/.hermit/keys/*.pem`. One valid PEM cert per
//!     file. A signature validates if the signer cert's
//!     SubjectPublicKeyInfo byte-matches any trusted cert's SPKI.
//!
//! There is no TTL / revocation / chain-of-trust. The trust directory
//! is the whole story — remove a key file to revoke.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::{general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::SignatureSection;

/// The fixed line marker used to terminate signed content. Must match
/// at column 0 preceded by a LF so it cannot occur mid-string.
const MARKER: &str = "[signature]";

/// Result of a successful verification: which trusted key matched.
#[derive(Debug)]
pub struct TrustedBy {
    pub path: PathBuf,
}

/// Split a TOML document into `(signed_bytes, sig_section_bytes)`.
/// `signed_bytes` omits the trailing `\n` that precedes the marker.
/// Returns `None` if the marker isn't present.
pub fn split_signed(content: &[u8]) -> Option<(&[u8], &[u8])> {
    // Accept either `\n[signature]` (most cases) or a file that starts
    // with `[signature]` at offset 0 (degenerate but well-defined).
    if content.starts_with(MARKER.as_bytes()) {
        return Some((&[], content));
    }
    let needle = format!("\n{MARKER}");
    let pos = find_subslice(content, needle.as_bytes())?;
    let signed = &content[..pos];
    let sig = &content[pos + 1..]; // skip the leading \n so sig starts with [signature]
    Some((signed, sig))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Verify a signed config document. Returns which trusted key file
/// matched on success.
pub fn verify(content: &[u8], trusted_dir: &Path) -> Result<TrustedBy> {
    let (signed_bytes, sig_bytes) = split_signed(content)
        .context("no [signature] section found in config")?;

    let sig_text = std::str::from_utf8(sig_bytes)
        .context("signature section is not valid UTF-8")?;
    // The signature section may have trailing whitespace / newlines —
    // those don't affect TOML parsing.
    let outer: SignatureOuter = toml::from_str(sig_text)
        .context("parsing [signature] section")?;
    let sig = outer.signature;

    if sig.algorithm != "ed25519" {
        bail!("unsupported signature algorithm: {}", sig.algorithm);
    }

    let cert_der = B64
        .decode(sig.cert.as_bytes())
        .context("decoding [signature].cert base64")?;
    let signature_bytes = B64
        .decode(sig.signature.as_bytes())
        .context("decoding [signature].signature base64")?;

    let signer_pubkey = extract_ed25519_pubkey(&cert_der)
        .context("extracting ed25519 public key from signer cert")?;
    let signer_spki = extract_spki(&cert_der).context("extracting signer SPKI")?;

    // Match signer cert against trust anchor
    let matched = match_trusted(trusted_dir, &signer_spki)?
        .with_context(|| format!(
            "signer cert did not match any trusted key in {}",
            trusted_dir.display()
        ))?;

    let signature = Signature::from_slice(&signature_bytes)
        .context("signature bytes are not a valid ed25519 signature")?;
    signer_pubkey
        .verify(signed_bytes, &signature)
        .context("ed25519 signature verification failed")?;

    Ok(TrustedBy { path: matched })
}

/// Sign an unsigned TOML document. The signed payload is the input with
/// any trailing LF stripped (so signer and verifier agree on exactly
/// which bytes are signed regardless of whether the source file ends in
/// a newline). Returns `payload + "\n[signature]\n…"`.
pub fn sign(unsigned: &[u8], cert_pem: &str, key_pem: &str) -> Result<Vec<u8>> {
    // Reject input that already has a [signature] section.
    if split_signed(unsigned).is_some() {
        bail!("input already contains a [signature] section");
    }

    let cert_der = pem_to_der(cert_pem, "CERTIFICATE")
        .context("parsing signer cert PEM")?;
    // Sanity check the cert holds an ed25519 key we can use.
    let _ = extract_ed25519_pubkey(&cert_der)?;

    let signing_key = signing_key_from_pkcs8_pem(key_pem)
        .context("parsing signer private key PEM")?;

    let payload = strip_trailing_newline(unsigned);
    let signature = signing_key.sign(payload);

    let sig_section = format!(
        "[signature]\nalgorithm = \"ed25519\"\ncert = \"{}\"\nsignature = \"{}\"\n",
        B64.encode(&cert_der),
        B64.encode(signature.to_bytes())
    );

    let mut out = Vec::with_capacity(payload.len() + sig_section.len() + 1);
    out.extend_from_slice(payload);
    out.push(b'\n');
    out.extend_from_slice(sig_section.as_bytes());
    Ok(out)
}

fn strip_trailing_newline(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\n' || b[end - 1] == b'\r') {
        end -= 1;
    }
    &b[..end]
}

#[derive(serde::Deserialize)]
struct SignatureOuter {
    signature: SignatureSection,
}

/// Parse a DER cert and return the ed25519 public key.
/// Errors if the cert's public key algorithm isn't ed25519.
fn extract_ed25519_pubkey(cert_der: &[u8]) -> Result<VerifyingKey> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("parsing cert DER: {e}"))?;

    // ed25519 OID is 1.3.101.112
    let algo_oid = &cert.tbs_certificate.subject_pki.algorithm.algorithm;
    if algo_oid.to_id_string() != "1.3.101.112" {
        bail!(
            "signer cert key algorithm is {}, only ed25519 (1.3.101.112) is supported",
            algo_oid.to_id_string()
        );
    }

    let raw_key = cert.tbs_certificate.subject_pki.subject_public_key.data.as_ref();
    let key_bytes: [u8; 32] = raw_key.try_into()
        .map_err(|_| anyhow!("ed25519 public key must be 32 bytes, got {}", raw_key.len()))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow!("invalid ed25519 public key bytes: {e}"))
}

/// Extract the SubjectPublicKeyInfo (algorithm + key bytes) as a
/// canonical byte blob we can compare across certs.
fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("parsing cert DER: {e}"))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

fn match_trusted(trusted_dir: &Path, target_spki: &[u8]) -> Result<Option<PathBuf>> {
    if !trusted_dir.exists() {
        bail!(
            "trust directory {} does not exist (create it and add trusted cert .pem files)",
            trusted_dir.display()
        );
    }
    for entry in fs::read_dir(trusted_dir)
        .with_context(|| format!("reading trust directory {}", trusted_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let pem = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let der = match pem_to_der(&pem, "CERTIFICATE") {
            Ok(d) => d,
            Err(_) => continue, // skip files that aren't cert PEMs
        };
        if let Ok(spki) = extract_spki(&der) {
            if spki == target_spki {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn pem_to_der(pem_text: &str, expected_label: &str) -> Result<Vec<u8>> {
    let block = pem::parse(pem_text).context("parsing PEM")?;
    if block.tag() != expected_label {
        bail!(
            "expected PEM label {expected_label:?}, got {:?}",
            block.tag()
        );
    }
    Ok(block.into_contents())
}

fn signing_key_from_pkcs8_pem(pem_text: &str) -> Result<SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    SigningKey::from_pkcs8_pem(pem_text)
        .map_err(|e| anyhow!("parsing PKCS8 ed25519 private key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate an ed25519 cert + private key PEM pair for tests.
    fn gen_cert() -> (String, String) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["test-signer".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        (cert.pem(), kp.serialize_pem())
    }

    #[test]
    fn split_works_on_typical_input() {
        let doc = b"key = 1\n[signature]\ncert = \"x\"\n";
        let (signed, sig) = split_signed(doc).unwrap();
        assert_eq!(signed, b"key = 1");
        assert_eq!(sig, b"[signature]\ncert = \"x\"\n");
    }

    #[test]
    fn split_handles_leading_signature() {
        let doc = b"[signature]\ncert = \"x\"\n";
        let (signed, sig) = split_signed(doc).unwrap();
        assert_eq!(signed, b"");
        assert_eq!(sig, doc);
    }

    #[test]
    fn split_none_when_marker_absent() {
        let doc = b"key = 1\n";
        assert!(split_signed(doc).is_none());
    }

    #[test]
    fn split_only_matches_at_line_start() {
        // A `[signature]` embedded inside a value must not match.
        let doc = b"note = \"see [signature] below\"\nkey = 2\n";
        assert!(split_signed(doc).is_none());
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (cert_pem, key_pem) = gen_cert();

        // Build trust dir with this cert as the only trusted key
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("signer.pem"), &cert_pem).unwrap();

        let unsigned = b"[sandbox]\nnet = \"host\"\n";
        let signed = sign(unsigned, &cert_pem, &key_pem).unwrap();

        let result = verify(&signed, tmp.path()).unwrap();
        assert!(result.path.ends_with("signer.pem"));
    }

    #[test]
    fn tampered_content_fails_verification() {
        let (cert_pem, key_pem) = gen_cert();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("s.pem"), &cert_pem).unwrap();

        let unsigned = b"[sandbox]\nnet = \"host\"\n";
        let mut signed = sign(unsigned, &cert_pem, &key_pem).unwrap();
        // Flip a byte in the signed payload
        signed[5] ^= 0x80;

        let err = verify(&signed, tmp.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("signature verification"), "got: {msg}");
    }

    #[test]
    fn unknown_signer_is_rejected() {
        let (cert_pem, key_pem) = gen_cert();
        // Trust dir contains a *different* cert.
        let (other_cert, _) = gen_cert();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("trusted.pem"), &other_cert).unwrap();

        let signed = sign(b"key = 1\n", &cert_pem, &key_pem).unwrap();
        let err = verify(&signed, tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("did not match any trusted key"));
    }

    #[test]
    fn empty_trust_dir_is_rejected() {
        let (cert_pem, key_pem) = gen_cert();
        let tmp = tempfile::tempdir().unwrap();
        let signed = sign(b"k=1\n", &cert_pem, &key_pem).unwrap();
        let err = verify(&signed, tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("did not match any trusted key"));
    }

    #[test]
    fn missing_signature_section_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let err = verify(b"[sandbox]\nnet=\"host\"\n", tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("no [signature] section"));
    }

    #[test]
    fn signing_rejects_already_signed_input() {
        let (cert_pem, key_pem) = gen_cert();
        let already = b"k=1\n[signature]\nalgorithm=\"ed25519\"\ncert=\"\"\nsignature=\"\"\n";
        let err = sign(already, &cert_pem, &key_pem).unwrap_err();
        assert!(format!("{err:#}").contains("already contains a [signature]"));
    }

    #[test]
    fn non_ed25519_cert_in_trust_dir_is_ignored() {
        // Trust dir contains a non-ed25519 cert (e.g. ECDSA) — it's
        // skipped silently; the signer is still rejected because its
        // SPKI doesn't match any ed25519 cert either.
        let (sign_cert, sign_key) = gen_cert();
        let ecdsa_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ecdsa_cert = rcgen::CertificateParams::new(vec!["ecdsa".to_string()])
            .unwrap()
            .self_signed(&ecdsa_kp)
            .unwrap()
            .pem();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ecdsa.pem"), ecdsa_cert).unwrap();

        let signed = sign(b"k=1\n", &sign_cert, &sign_key).unwrap();
        assert!(verify(&signed, tmp.path()).is_err());
    }

    #[test]
    fn non_pem_file_in_trust_dir_is_ignored() {
        let (cert_pem, key_pem) = gen_cert();
        let tmp = tempfile::tempdir().unwrap();
        // README file should be ignored (.pem filter).
        std::fs::write(tmp.path().join("README"), "just a readme\n").unwrap();
        // Trash file ending in .pem — malformed; should be skipped without error.
        std::fs::write(tmp.path().join("trash.pem"), "not a pem\n").unwrap();
        // The real trusted cert.
        std::fs::write(tmp.path().join("ok.pem"), &cert_pem).unwrap();

        let signed = sign(b"k=1\n", &cert_pem, &key_pem).unwrap();
        assert!(verify(&signed, tmp.path()).is_ok());
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let (cert_pem, key_pem) = gen_cert();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("c.pem"), &cert_pem).unwrap();

        let mut signed = sign(b"k=1\n", &cert_pem, &key_pem).unwrap();
        // Swap the algorithm field in place.
        let s = std::str::from_utf8(&signed).unwrap().to_string();
        let tampered = s.replace("algorithm = \"ed25519\"", "algorithm = \"rsa\"");
        signed = tampered.into_bytes();

        let err = verify(&signed, tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported signature algorithm"));
    }
}
