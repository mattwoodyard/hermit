//! Install an ephemeral CA certificate into the sandbox trust store.
//!
//! Must be called inside the mount namespace so bind-mounts don't leak
//! to the host. Sets environment variables that common build tools use
//! to locate custom CA certificates.

use anyhow::{Context, Result};
use log::info;
use nix::mount::{mount, MsFlags};
use std::path::Path;

/// Well-known system CA bundle paths (Debian/Ubuntu, Alpine, Fedora/RHEL).
const SYSTEM_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

/// Path where we write the hermit CA PEM for tool-specific env vars.
const HERMIT_CA_PATH: &str = "/tmp/.hermit-ca.pem";

/// Install the CA certificate PEM into the sandbox.
///
/// 1. Writes the CA PEM to a temp file.
/// 2. Finds the system CA bundle, appends our CA, and bind-mounts the
///    modified bundle over the original.
/// 3. Sets environment variables that build tools use to find CA certs.
///
/// Must be called after mount namespace setup and before landlock.
pub fn install_ca_cert(ca_pem: &str) -> Result<()> {
    // Write standalone CA file for env vars
    std::fs::write(HERMIT_CA_PATH, ca_pem)
        .context("failed to write hermit CA PEM")?;

    // Find and patch the system CA bundle
    if let Some(bundle_path) = find_system_ca_bundle() {
        install_into_system_bundle(bundle_path, ca_pem)?;
    } else {
        info!("trust: no system CA bundle found, relying on env vars only");
    }

    // Set env vars for tools that use them
    set_trust_env_vars();

    Ok(())
}

/// Find the first existing system CA bundle.
fn find_system_ca_bundle() -> Option<&'static str> {
    SYSTEM_CA_PATHS.iter().find(|p| Path::new(p).exists()).copied()
}

/// Append the CA PEM to a copy of the system bundle, then bind-mount it
/// over the original.
fn install_into_system_bundle(bundle_path: &str, ca_pem: &str) -> Result<()> {
    info!("trust: patching system CA bundle at {}", bundle_path);

    let original = std::fs::read_to_string(bundle_path)
        .with_context(|| format!("failed to read {}", bundle_path))?;

    let patched_path = format!("/tmp/.hermit-{}-ca-bundle.pem", std::process::id());
    let mut patched = original;
    if !patched.ends_with('\n') {
        patched.push('\n');
    }
    patched.push_str("# hermit ephemeral CA\n");
    patched.push_str(ca_pem);

    std::fs::write(&patched_path, &patched)
        .context("failed to write patched CA bundle")?;

    mount(
        Some(patched_path.as_str()),
        bundle_path,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("failed to bind-mount patched CA bundle over {}", bundle_path))?;

    info!("trust: bind-mounted patched bundle over {}", bundle_path);
    Ok(())
}

/// Set environment variables that build tools look for.
fn set_trust_env_vars() {
    // OpenSSL / generic
    std::env::set_var("SSL_CERT_FILE", HERMIT_CA_PATH);
    // Node.js
    std::env::set_var("NODE_EXTRA_CA_CERTS", HERMIT_CA_PATH);
    // Python requests
    std::env::set_var("REQUESTS_CA_BUNDLE", HERMIT_CA_PATH);
    // Cargo
    std::env::set_var("CARGO_HTTP_CAINFO", HERMIT_CA_PATH);
    // curl
    std::env::set_var("CURL_CA_BUNDLE", HERMIT_CA_PATH);
    // Go
    std::env::set_var("SSL_CERT_DIR", "");

    info!("trust: set CA env vars pointing to {}", HERMIT_CA_PATH);
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_PEM: &str = "-----BEGIN CERTIFICATE-----\nTESTDATA\n-----END CERTIFICATE-----\n";

    #[test]
    fn find_system_ca_bundle_returns_existing_path() {
        // At least one should exist on this system, or None is fine
        let result = find_system_ca_bundle();
        if let Some(path) = result {
            assert!(Path::new(path).exists());
        }
    }

    #[test]
    fn hermit_ca_path_is_in_tmp() {
        assert!(HERMIT_CA_PATH.starts_with("/tmp/"));
    }

    #[test]
    fn write_ca_pem_to_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, TEST_PEM).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("TESTDATA"));
    }

    #[test]
    fn patched_bundle_contains_original_and_ca() {
        let dir = tempfile::tempdir().unwrap();
        let original_path = dir.path().join("original.pem");
        std::fs::write(&original_path, "ORIGINAL_BUNDLE\n").unwrap();

        let original = std::fs::read_to_string(&original_path).unwrap();
        let mut patched = original;
        patched.push_str("# hermit ephemeral CA\n");
        patched.push_str(TEST_PEM);

        assert!(patched.contains("ORIGINAL_BUNDLE"));
        assert!(patched.contains("TESTDATA"));
        assert!(patched.contains("# hermit ephemeral CA"));
    }
}
