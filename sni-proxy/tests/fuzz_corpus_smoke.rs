//! Smoke-runs the seed inputs from `sni-proxy/fuzz/seed/` through
//! the same parsers each `cargo fuzz` target points at.
//!
//! This is *not* a fuzzer — `cargo fuzz` proper needs nightly +
//! `libfuzzer-sys` and lives in `sni-proxy/fuzz/`. The smoke test
//! exists so two failure modes are caught on the regular stable
//! `cargo test` path:
//!
//! 1. The `fuzz_targets/*.rs` harnesses are using API paths that
//!    no longer exist (renamed function, moved module, etc.). The
//!    libfuzzer build won't fire on PRs but this test will.
//! 2. The seed corpora under `seed/<target>/` are corrupt or moved.
//!    A fuzzer with broken seeds wastes hours rediscovering happy
//!    paths.
//!
//! Each block below mirrors the call inside the matching
//! `fuzz_targets/<name>.rs`. Keep them in sync — when a fuzz
//! target's signature changes, update both.

use std::path::PathBuf;

use sni_proxy::{dns, dns_forwarder, http, sni};

fn seed_dir(target: &str) -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("fuzz").join("seed").join(target)
}

/// Walk `seed/<target>/` and pass each file's bytes to `f`.
/// Asserts at least one seed exists — a missing corpus dir means
/// somebody moved the seeds without updating this test.
fn for_each_seed(target: &str, mut f: impl FnMut(&str, &[u8])) {
    let dir = seed_dir(target);
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed dir {dir:?} unreadable: {e}"));
    let mut count = 0;
    for entry in entries {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        f(&name, &bytes);
        count += 1;
    }
    assert!(count > 0, "no seeds found in {dir:?}");
}

#[test]
fn sni_seeds_parse_without_panic() {
    for_each_seed("sni", |name, bytes| {
        // Drop the result — both Ok and Err are valid outcomes;
        // we only require no panic.
        let _ = sni::extract_sni(bytes);
        let _ = name;
    });
}

#[test]
fn dns_query_seeds_parse_without_panic() {
    for_each_seed("dns_query", |_name, bytes| {
        let _ = dns::parse_query(bytes);
    });
}

#[test]
fn dns_answers_seeds_parse_without_panic() {
    for_each_seed("dns_answers", |_name, bytes| {
        let _ = dns_forwarder::parse_answers(bytes);
    });
}

#[tokio::test]
async fn http_request_seeds_parse_without_panic() {
    let dir = seed_dir("http_request");
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed dir {dir:?} unreadable: {e}"));
    let mut count = 0;
    for entry in entries {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        let mut reader: &[u8] = &bytes;
        let _ = http::read_request(&mut reader).await;
        count += 1;
    }
    assert!(count > 0, "no seeds in http_request");
}

#[tokio::test]
async fn http_response_seeds_parse_without_panic() {
    let dir = seed_dir("http_response");
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed dir {dir:?} unreadable: {e}"));
    let mut count = 0;
    for entry in entries {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        let mut reader: &[u8] = &bytes;
        let _ = http::read_response(&mut reader).await;
        count += 1;
    }
    assert!(count > 0, "no seeds in http_response");
}

#[test]
fn set_header_buffer_unchanged_on_reject() {
    // Pin the load-bearing invariant on a couple of crafted
    // poison inputs the validators must reject. We don't have
    // a `seed/set_header/` corpus because the fuzz target
    // consumes structured `Arbitrary` inputs, not raw bytes.
    let baseline = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    let poisons: &[(&str, &str)] = &[
        ("Authorization", "tok\r\nX-Smuggled: 1"),
        ("Authorization", "tok\nX-Smuggled: 1"),
        ("Bad Name", "v"),
        ("Bad:Name", "v"),
        ("", "v"),
    ];
    for (name, value) in poisons {
        let mut buf = baseline.clone();
        let res = http::set_header(&mut buf, name, value);
        assert!(res.is_err(), "poison input ({name:?}, {value:?}) must reject");
        assert_eq!(buf, baseline, "buffer must be unchanged on reject");
    }
}
