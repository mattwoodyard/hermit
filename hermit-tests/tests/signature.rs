//! Tests for `hermit::signature`. The functions under test
//! (`split_signed`, `sign`, `verify`) are all part of the
//! public API.

use hermit::signature::{sign, split_signed, verify};

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
