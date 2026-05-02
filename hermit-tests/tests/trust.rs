//! Tests for `hermit::trust`.

use hermit::trust::__test_internals::{
    build_combined_bundle, find_system_ca_bundle, HERMIT_CA_PATH,
};
use std::path::Path;

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
