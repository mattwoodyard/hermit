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

/// Path where we write the combined CA bundle for tool-specific
/// env vars.
///
/// Lives on the *sandbox* `/tmp` — `setup_namespace` mounts a
/// fresh tmpfs over `/tmp` inside the new mount namespace before
/// `install_ca_cert` runs, so this path is mount-isolated from
/// the host's `/tmp`. The file goes away with the sandbox when
/// the build exits and is never visible to the host.
const HERMIT_CA_PATH: &str = "/tmp/.hermit-ca.pem";

/// Install the CA certificate PEM into the sandbox.
///
/// 1. Writes [system bundle + hermit CA] to `HERMIT_CA_PATH` on
///    the sandbox tmpfs. Tools that exclusively follow the
///    `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`
///    style of env-var trust pointer get *both* the hermit CA
///    (needed for MITM'd HTTPS) and the host's system roots
///    (needed for bypass-mode connections that splice raw bytes
///    to a real origin and let the build validate the origin's
///    cert itself). When no system bundle exists, the file holds
///    just the hermit CA.
/// 2. If a system bundle exists, also bind-mounts the
///    [system + hermit] file over the bundle path so tools that
///    follow the OS default path (e.g. OpenSSL with no env var)
///    pick up the hermit CA too.
/// 3. Sets the env vars that build tools look for.
///
/// Must be called after mount-namespace setup (so `/tmp` is the
/// sandbox tmpfs) and before landlock (so `mount` and writes
/// under `/etc` are still permitted).
pub fn install_ca_cert(ca_pem: &str) -> Result<()> {
    let system_bundle = find_system_ca_bundle();
    // Build the combined bundle once. Both the env-var file and
    // the bind-mount source share the same bytes.
    let combined = build_combined_bundle(system_bundle, ca_pem)?;

    // Write the combined bundle to the sandbox tmpfs path that
    // env-var-following tools point at.
    std::fs::write(HERMIT_CA_PATH, combined.as_bytes())
        .with_context(|| format!("failed to write {} (combined CA bundle)", HERMIT_CA_PATH))?;

    if let Some(bundle_path) = system_bundle {
        install_into_system_bundle(bundle_path, &combined)?;
    } else {
        info!(
            "trust: no system CA bundle found at {:?}; \
             {} holds the hermit CA only",
            SYSTEM_CA_PATHS, HERMIT_CA_PATH
        );
    }

    set_trust_env_vars();

    Ok(())
}

/// Concatenate the system bundle (when present) with the hermit
/// CA cert. The hermit CA is appended *after* the system roots so
/// tools that early-out on the first verifier match still try
/// the system roots first for bypass-mode TLS, while MITM'd
/// connections (where only the hermit CA can verify) still fall
/// through to the appended block.
fn build_combined_bundle(system_bundle: Option<&str>, ca_pem: &str) -> Result<String> {
    let mut combined = match system_bundle {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read system CA bundle {}", path))?,
        None => String::new(),
    };
    if !combined.is_empty() && !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str("# hermit ephemeral CA\n");
    combined.push_str(ca_pem);
    if !combined.ends_with('\n') {
        combined.push('\n');
    }
    Ok(combined)
}

/// Find the first existing system CA bundle.
fn find_system_ca_bundle() -> Option<&'static str> {
    SYSTEM_CA_PATHS.iter().find(|p| Path::new(p).exists()).copied()
}

/// Bind-mount the already-built combined bundle over the system
/// bundle path. The source file lives on the sandbox tmpfs;
/// pid-suffixed so two concurrent hermit children don't collide
/// on it (tmpfs is per-mount-namespace, but the suffix also
/// helps a human reading `ls /tmp` from inside the sandbox).
fn install_into_system_bundle(bundle_path: &str, combined: &str) -> Result<()> {
    info!("trust: patching system CA bundle at {}", bundle_path);

    let patched_path = format!("/tmp/.hermit-{}-ca-bundle.pem", std::process::id());
    std::fs::write(&patched_path, combined)
        .with_context(|| format!("failed to write {} (combined bundle)", patched_path))?;

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
    fn build_combined_bundle_concats_system_then_hermit() {
        // env-var-following tools (REQUESTS_CA_BUNDLE,
        // CURL_CA_BUNDLE, ...) replace system trust with whatever
        // file we point them at. The combined file must include
        // BOTH the system roots and the hermit CA so bypass-mode
        // TLS (which validates against real origin certs) and
        // MITM'd HTTPS (signed by the hermit CA) both work.
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("system.pem");
        std::fs::write(&system, "ORIGINAL_BUNDLE\n").unwrap();
        let combined = build_combined_bundle(
            Some(system.to_str().unwrap()),
            TEST_PEM,
        )
        .unwrap();

        assert!(combined.contains("ORIGINAL_BUNDLE"));
        assert!(combined.contains("# hermit ephemeral CA"));
        assert!(combined.contains("TESTDATA"));
        // System bundle comes FIRST so verifiers that early-out
        // on the first match still hit system roots before the
        // appended hermit CA.
        let sys_at = combined.find("ORIGINAL_BUNDLE").unwrap();
        let hermit_at = combined.find("TESTDATA").unwrap();
        assert!(sys_at < hermit_at, "hermit CA must follow system bundle");
    }

    #[test]
    fn build_combined_bundle_inserts_separating_newline() {
        // If the system bundle doesn't end with a newline (some
        // distros omit it), the appended hermit CA must still
        // start on its own line.
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("system.pem");
        std::fs::write(&system, "NO_TRAILING_NEWLINE").unwrap();
        let combined = build_combined_bundle(
            Some(system.to_str().unwrap()),
            TEST_PEM,
        )
        .unwrap();
        assert!(
            combined.contains("NO_TRAILING_NEWLINE\n# hermit"),
            "must inject newline between bundle and marker: {combined:?}"
        );
    }

    #[test]
    fn build_combined_bundle_works_without_system_bundle() {
        // Distros without any of SYSTEM_CA_PATHS still need the
        // hermit CA at HERMIT_CA_PATH (so MITM'd traffic
        // verifies); the file just lacks the system roots.
        let combined = build_combined_bundle(None, TEST_PEM).unwrap();
        assert!(combined.contains("# hermit ephemeral CA"));
        assert!(combined.contains("TESTDATA"));
        assert!(!combined.contains("ORIGINAL_BUNDLE"));
    }
}
