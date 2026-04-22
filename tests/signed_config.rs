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
        self.sign_config_as(toml_body, "signed.toml")
    }

    /// Like `sign_config`, but writes the output to a specific filename
    /// so a single test can produce multiple signed files (e.g. a root
    /// plus an include target).
    fn sign_config_as(&self, toml_body: &str, filename: &str) -> PathBuf {
        let cert_path = self._home.path().join("cert.pem");
        let key_path = self._home.path().join("key.pem");
        std::fs::write(&cert_path, &self.cert_pem).unwrap();
        std::fs::write(&key_path, &self.key_pem).unwrap();

        let unsigned_name = format!("{}.unsigned", filename);
        let unsigned_path = self._home.path().join(&unsigned_name);
        let signed_path = self._home.path().join(filename);
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
fn allow_unsigned_accepts_config_without_signature() {
    let h = Harness::new();
    // Plain TOML, no sign step, no [signature] section.
    let path = h._home.path().join("plain.toml");
    std::fs::write(&path, "[sandbox]\nnet = \"host\"\n").unwrap();
    let url = format!("file://{}", path.display());

    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args([
            "run",
            "--config",
            &url,
            "--allow-unsigned",
            "--project-dir",
            "/tmp",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    // The actual sandbox may fail for privilege reasons, but the config
    // load/parse step must succeed, so stderr must NOT complain about
    // signatures or verification.
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Any signature-related *failure* would appear as an anyhow error
    // line prefixed with "hermit:". The warning emitted by --allow-unsigned
    // starts with "[WARN ]" and is fine.
    let failure_indicators = [
        "hermit: verifying",
        "no [signature] section found",
        "signature verification failed",
        "did not match any trusted key",
    ];
    for f in failure_indicators {
        assert!(
            !stderr.contains(f),
            "--allow-unsigned should skip signature checks, but stderr contained {f:?}:\n{stderr}"
        );
    }
}

#[test]
fn allow_unsigned_logs_warning() {
    let h = Harness::new();
    let path = h._home.path().join("p.toml");
    std::fs::write(&path, "[sandbox]\nnet = \"host\"\n").unwrap();
    let url = format!("file://{}", path.display());

    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        // -v to see warn-level logs on stderr.
        .args([
            "run",
            "--config",
            &url,
            "--allow-unsigned",
            "-v",
            "--project-dir",
            "/tmp",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--allow-unsigned") || stderr.contains("skipping signature"),
        "expected allow-unsigned warning in stderr, got:\n{stderr}"
    );
}

#[test]
fn keygen_produces_usable_signer() {
    let tmp = tempfile::tempdir().unwrap();
    let cert = tmp.path().join("c.pem");
    let key = tmp.path().join("k.pem");

    let out = hermit_bin()
        .args([
            "keygen",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--subject",
            "unit-test",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(cert.exists());
    assert!(key.exists());

    // Key file must be 0600 on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode was {mode:o}");
    }

    // Round-trip: put generated cert into a fresh trust dir, sign a
    // config with the generated key, verify it.
    let trust_dir = tmp.path().join("trust");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::copy(&cert, trust_dir.join("signer.pem")).unwrap();

    let unsigned = tmp.path().join("u.toml");
    let signed = tmp.path().join("s.toml");
    std::fs::write(&unsigned, "[sandbox]\nnet = \"host\"\n").unwrap();

    let o = hermit_bin()
        .args([
            "sign",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            signed.to_str().unwrap(),
            unsigned.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "sign: {}", String::from_utf8_lossy(&o.stderr));

    let url = format!("file://{}", signed.display());
    let v = hermit_bin()
        .env("HERMIT_TRUST_DIR", &trust_dir)
        .args(["verify", &url])
        .output()
        .unwrap();
    assert!(v.status.success(), "verify: {}", String::from_utf8_lossy(&v.stderr));
}

#[test]
fn keygen_refuses_to_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let cert = tmp.path().join("c.pem");
    let key = tmp.path().join("k.pem");
    std::fs::write(&cert, "existing\n").unwrap();

    let out = hermit_bin()
        .args([
            "keygen",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already exists"));
    // Existing file untouched.
    assert_eq!(std::fs::read_to_string(&cert).unwrap(), "existing\n");
}

#[test]
fn keygen_force_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let cert = tmp.path().join("c.pem");
    let key = tmp.path().join("k.pem");
    std::fs::write(&cert, "old\n").unwrap();
    std::fs::write(&key, "old\n").unwrap();

    let out = hermit_bin()
        .args([
            "keygen",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen --force: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cert_content = std::fs::read_to_string(&cert).unwrap();
    assert!(cert_content.contains("BEGIN CERTIFICATE"));
}

#[test]
fn verify_transitively_checks_signed_include_chain() {
    // Signed include chain: root.toml -> shared.toml, both signed by the
    // same trusted key. `verify` must accept the chain end-to-end.
    let h = Harness::new();
    let shared = h.sign_config_as(
        "[[access_rule]]\nhost = \"shared.example\"\n",
        "shared.toml",
    );
    let shared_url = format!("file://{}", shared.display());
    let root = h.sign_config_as(
        &format!(
            "include = [\"{shared_url}\"]\n[[access_rule]]\nhost = \"root.example\"\n",
        ),
        "root.toml",
    );
    let root_url = format!("file://{}", root.display());

    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args(["verify", &root_url])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify chain failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn verify_rejects_unsigned_include_even_when_root_is_signed() {
    // A trusted root that pulls in an unsigned include must fail verify
    // — otherwise a signature is just a decoy and an attacker could
    // smuggle rules via the include URL.
    let h = Harness::new();
    let include_path = h._home.path().join("unsigned-include.toml");
    std::fs::write(
        &include_path,
        "[[access_rule]]\nhost = \"evil.example\"\n",
    )
    .unwrap();
    let include_url = format!("file://{}", include_path.display());
    let root = h.sign_config_as(
        &format!("include = [\"{include_url}\"]\n"),
        "root.toml",
    );
    let root_url = format!("file://{}", root.display());

    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args(["verify", &root_url])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify should reject unsigned include; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("signature") || stderr.contains("verifying"),
        "expected signature error, got: {stderr}"
    );
}

#[test]
fn allow_unsigned_merges_includes_end_to_end() {
    // With --allow-unsigned we can bypass signing entirely and still
    // exercise the full include → merge pipeline.
    let h = Harness::new();
    let shared = h._home.path().join("shared.toml");
    std::fs::write(
        &shared,
        "[sandbox]\nnet = \"isolate\"\n\n[[access_rule]]\nhost = \"shared.example\"\n",
    )
    .unwrap();
    let shared_url = format!("file://{}", shared.display());
    let root = h._home.path().join("root.toml");
    std::fs::write(
        &root,
        format!(
            "include = [\"{shared_url}\"]\n\n[[access_rule]]\nhost = \"root.example\"\n",
        ),
    )
    .unwrap();
    let root_url = format!("file://{}", root.display());

    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args([
            "run",
            "--config",
            &root_url,
            "--allow-unsigned",
            "--project-dir",
            "/tmp",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    // Don't assert status — the sandbox may fail for privilege reasons in
    // CI. We only care that the config pipeline did not complain about
    // the include or merge.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("loading config"),
        "include merge failed; stderr={stderr}"
    );
    assert!(
        !stderr.contains("cycle"),
        "unexpected cycle error; stderr={stderr}"
    );
}

#[test]
fn verify_accepts_config_with_port_forwards() {
    // End-to-end check that a signed config with [[port_forward]] entries
    // parses through the full `verify` pipeline.
    let h = Harness::new();
    let body = r#"
[sandbox]
net = "isolate"

[[access_rule]]
host = "example.com"

[[port_forward]]
port = 8443

[[port_forward]]
port = 8080
protocol = "http"
"#;
    let signed = h.sign_config(body);
    let url = format!("file://{}", signed.display());
    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args(["verify", &url])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn verify_rejects_port_forward_on_reserved_port() {
    // Parsing happens inside `verify` for signature-checked configs too;
    // a reserved listener port must surface as an error at that stage.
    //
    // Note: `verify` only reads the signed text bytes and checks the
    // signature — it doesn't call Config::parse. So we exercise this via
    // `run --allow-unsigned` which does parse the config.
    let h = Harness::new();
    let bad = h._home.path().join("bad.toml");
    std::fs::write(
        &bad,
        "[sandbox]\nnet = \"host\"\n[[port_forward]]\nport = 1443\n",
    )
    .unwrap();
    let url = format!("file://{}", bad.display());
    let out = hermit_bin()
        .env("HERMIT_TRUST_DIR", &h.trust_dir)
        .args([
            "run",
            "--config",
            &url,
            "--allow-unsigned",
            "--project-dir",
            "/tmp",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("reserved"),
        "expected reserved-port error in stderr, got:\n{stderr}"
    );
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
