//! Integration tests for the signed-config + URL-loading pipeline.
//!
//! These exercise hermit at the CLI boundary without privileged sandbox
//! features (namespaces/landlock). The tests that require those live in
//! `integration_test.rs` and need porting to use this harness.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn hermit_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hermit"))
}

struct Harness {
    _home: tempfile::TempDir,
    trust_dir: PathBuf,
    cert_pem: String,
    key_pem: String,
}

impl Harness {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let trust_dir = home.path().join(".hermit/keys");
        std::fs::create_dir_all(&trust_dir).unwrap();

        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["hermit-test-signer".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        let cert_pem = cert.pem();
        let key_pem = kp.serialize_pem();

        std::fs::write(trust_dir.join("signer.pem"), &cert_pem).unwrap();

        Self {
            _home: home,
            trust_dir,
            cert_pem,
            key_pem,
        }
    }

    fn sign_config(&self, toml_body: &str) -> PathBuf {
        let cert_path = self._home.path().join("cert.pem");
        let key_path = self._home.path().join("key.pem");
        std::fs::write(&cert_path, &self.cert_pem).unwrap();
        std::fs::write(&key_path, &self.key_pem).unwrap();

        let unsigned_path = self._home.path().join("unsigned.toml");
        let signed_path = self._home.path().join("signed.toml");
        std::fs::write(&unsigned_path, toml_body).unwrap();

        let out = hermit_bin()
            .args([
                "sign",
                "--cert",
                cert_path.to_str().unwrap(),
                "--key",
                key_path.to_str().unwrap(),
                "--output",
                signed_path.to_str().unwrap(),
                unsigned_path.to_str().unwrap(),
            ])
            .output()
            .expect("sign failed");
        assert!(
            out.status.success(),
            "sign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        signed_path
    }

    fn run_cmd(
        &self,
        signed_config: &Path,
        project_dir: Option<&Path>,
        cmd: &[&str],
    ) -> Output {
        let url = format!("file://{}", signed_config.display());
        let mut c = hermit_bin();
        c.env("HERMIT_TRUST_DIR", &self.trust_dir);
        c.args(["run", "--config", &url]);
        if let Some(pd) = project_dir {
            c.args(["--project-dir", pd.to_str().unwrap()]);
        }
        c.arg("--");
        for a in cmd {
            c.arg(a);
        }
        c.output().expect("hermit run failed to exec")
    }
}

#[test]
fn verify_subcommand_prints_trusted_key() {
    let h = Harness::new();
    let signed = h.sign_config("[sandbox]\nnet = \"host\"\n");

    let url = format!("file://{}", signed.display());
    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args(["verify", &url])
        .output()
        .expect("verify failed");
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("OK: verified by"), "stdout was {stdout}");
    assert!(stdout.contains("signer.pem"));
}

#[test]
fn verify_rejects_tampered_config() {
    let h = Harness::new();
    let signed = h.sign_config("[sandbox]\nnet = \"host\"\n");
    // Flip a byte in the signed payload (not in the signature section).
    let mut bytes = std::fs::read(&signed).unwrap();
    bytes[2] ^= 0x80;
    let tampered = signed.with_extension("tampered.toml");
    std::fs::write(&tampered, bytes).unwrap();

    let url = format!("file://{}", tampered.display());
    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args(["verify", &url])
        .output()
        .expect("verify failed");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("signature verification"), "stderr was {stderr}");
}

#[test]
fn run_refuses_unsigned_config() {
    let h = Harness::new();
    // Write a raw config without a signature section.
    let path = h._home.path().join("plain.toml");
    std::fs::write(&path, "[sandbox]\nnet = \"host\"\n").unwrap();

    let out = h.run_cmd(&path, Some(Path::new("/tmp")), &["true"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no [signature] section") || stderr.contains("verifying"),
        "stderr was {stderr}"
    );
}

#[test]
fn run_rejects_unknown_signer() {
    let h = Harness::new();
    // Sign with a *different* signer whose cert is not in the trust dir.
    let kp2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert2 = rcgen::CertificateParams::new(vec!["other-signer".to_string()])
        .unwrap()
        .self_signed(&kp2)
        .unwrap()
        .pem();
    let key2 = kp2.serialize_pem();

    let cert_path = h._home.path().join("other-cert.pem");
    let key_path = h._home.path().join("other-key.pem");
    let unsigned = h._home.path().join("u.toml");
    let signed = h._home.path().join("s.toml");
    std::fs::write(&cert_path, &cert2).unwrap();
    std::fs::write(&key_path, &key2).unwrap();
    std::fs::write(&unsigned, "[sandbox]\nnet = \"host\"\n").unwrap();

    let o = hermit_bin()
        .args([
            "sign",
            "--cert",
            cert_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--output",
            signed.to_str().unwrap(),
            unsigned.to_str().unwrap(),
        ])
        .output()
        .expect("sign failed");
    assert!(o.status.success(), "sign setup: {}", String::from_utf8_lossy(&o.stderr));

    let out = h.run_cmd(&signed, Some(Path::new("/tmp")), &["true"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("did not match any trusted key"),
        "stderr was {stderr}"
    );
}

#[test]
fn sign_round_trips_produces_verifiable_file() {
    let h = Harness::new();
    let signed = h.sign_config("[sandbox]\nnet = \"host\"\n[[home_file]]\naction = \"pass\"\npath = \"~/.ssh\"\n");

    // Read signed file: must contain [signature] and re-verify cleanly.
    let bytes = std::fs::read(&signed).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("[signature]"));
    assert!(text.contains("algorithm = \"ed25519\""));

    let url = format!("file://{}", signed.display());
    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args(["verify", &url])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn run_rejects_missing_trust_dir() {
    let h = Harness::new();
    let signed = h.sign_config("[sandbox]\nnet = \"host\"\n");
    let url = format!("file://{}", signed.display());

    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", "/does/not/exist/hermit/keys")
        .args(["run", "--config", &url, "--", "true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not exist"), "stderr was {stderr}");
}

#[test]
fn run_rejects_http_url() {
    let h = Harness::new();
    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args(["run", "--config", "http://example.com/c.toml", "--", "true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unsupported URL scheme"),
        "stderr was {stderr}"
    );
}
