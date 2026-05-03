//! Tests for `sni_proxy::credential`. All exercised items are part of
//! the public API.

use sni_proxy::credential::{Credential, CredentialResolver, Source};
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

fn resolver_with(name: &str, source: Source) -> CredentialResolver {
    let mut m = HashMap::new();
    m.insert(
        name.to_string(),
        Credential {
            source,
            inject: vec![],
        },
    );
    CredentialResolver::new(m)
}

#[tokio::test]
async fn resolves_env() {
    // SAFETY: tests run single-threaded inside this tokio runtime.
    unsafe { std::env::set_var("CRED_TEST_ENV", "secret-abc") };
    let r = resolver_with("k", Source::Env { name: "CRED_TEST_ENV".into() });
    let v = r.resolve("k", None).await.unwrap();
    assert_eq!(v, "secret-abc");
}

#[tokio::test]
async fn resolves_file_trims_newline() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "tok-xyz").unwrap();
    let r = resolver_with("k", Source::File { path: f.path().to_path_buf() });
    let v = r.resolve("k", None).await.unwrap();
    assert_eq!(v, "tok-xyz");
}

#[tokio::test]
async fn resolves_script_stdout() {
    let r = resolver_with(
        "k",
        Source::Script {
            command: vec!["/bin/echo".into(), "-n".into(), "from-script".into()],
            ttl_secs: 60,
        },
    );
    let v = r.resolve("k", None).await.unwrap();
    assert_eq!(v, "from-script");
}

#[tokio::test]
async fn script_cache_hit_returns_cached_value() {
    // Script returns the current timestamp in nanos. If we call twice
    // within the TTL, we should get the same value (cache hit).
    let r = resolver_with(
        "k",
        Source::Script {
            command: vec!["/bin/sh".into(), "-c".into(), "date +%s%N".into()],
            ttl_secs: 60,
        },
    );
    let v1 = r.resolve("k", None).await.unwrap();
    let v2 = r.resolve("k", None).await.unwrap();
    assert_eq!(v1, v2, "cached value should be reused");
}

#[tokio::test]
async fn script_ttl_zero_disables_cache() {
    let r = resolver_with(
        "k",
        Source::Script {
            command: vec!["/bin/sh".into(), "-c".into(), "date +%s%N".into()],
            ttl_secs: 0,
        },
    );
    let v1 = r.resolve("k", None).await.unwrap();
    // Sleep briefly so the timestamp advances
    tokio::time::sleep(Duration::from_millis(20)).await;
    let v2 = r.resolve("k", None).await.unwrap();
    assert_ne!(v1, v2, "ttl=0 should re-run the script each call");
}

#[tokio::test]
async fn script_passes_match_host_env() {
    let r = resolver_with(
        "k",
        Source::Script {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo -n $HERMIT_MATCH_HOST".into(),
            ],
            ttl_secs: 0,
        },
    );
    let v = r.resolve("k", Some("api.example.com")).await.unwrap();
    assert_eq!(v, "api.example.com");
}

#[tokio::test]
async fn script_failure_is_error() {
    let r = resolver_with(
        "k",
        Source::Script {
            command: vec!["/bin/sh".into(), "-c".into(), "exit 7".into()],
            ttl_secs: 60,
        },
    );
    let err = r.resolve("k", None).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn unknown_credential_is_error() {
    let r = CredentialResolver::new(HashMap::new());
    let err = r.resolve("missing", None).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn invalidate_drops_cached_value_so_next_resolve_reruns_source() {
    // Use a script whose output changes every invocation so
    // we can detect whether the cache served the old value
    // or the source ran fresh.
    // ttl_secs is huge so the cache wouldn't expire on its own.
    let path = std::env::temp_dir().join(format!(
        "hermit-cred-invalidate-{}",
        std::process::id()
    ));
    std::fs::write(&path, "0").unwrap();
    let r = resolver_with(
        "tok",
        Source::Script {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    "n=$(cat {p}); echo -n $n; expr $n + 1 > {p}",
                    p = path.display()
                ),
            ],
            ttl_secs: 86_400,
        },
    );
    // First resolve: source runs, returns "0", caches it.
    let v0 = r.resolve("tok", None).await.unwrap();
    assert_eq!(v0, "0");
    // Cached: source must NOT run again.
    let v0_again = r.resolve("tok", None).await.unwrap();
    assert_eq!(v0_again, "0", "cache hit must serve the original value");
    // Invalidate: next resolve re-runs the source.
    r.invalidate("tok");
    let v1 = r.resolve("tok", None).await.unwrap();
    assert_eq!(v1, "1", "after invalidate the source must run again");
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn invalidate_unknown_credential_is_a_noop() {
    // The 401 path may invalidate a credential whose entry
    // was never cached (it could have been a non-script
    // source with a one-shot acquisition that failed). The
    // call must succeed silently.
    let r = CredentialResolver::new(HashMap::new());
    r.invalidate("missing"); // does not panic
}

#[tokio::test]
async fn script_env_is_cleared_to_allowlist() {
    // The motivating threat: hermit was launched with another
    // service's secret in the env (e.g. `GITHUB_TOKEN`).
    // Without env_clear(), every credential script could read
    // that secret and exfiltrate it. The fix clears the env
    // and reinstates only an allowlist; this test asserts a
    // poison var is NOT visible to the child while an
    // allowlisted one (`HOME`) is.
    let poison_key = format!("HERMIT_TEST_POISON_{}", std::process::id());
    // Set both a poison var (must NOT reach the script) and
    // ensure HOME is set (allowlisted, must reach the script).
    unsafe {
        std::env::set_var(&poison_key, "secret-from-parent");
        if std::env::var("HOME").is_err() {
            std::env::set_var("HOME", "/tmp");
        }
    }

    // Script prints `<HOME>|<POISON>` so we can assert each
    // independently. `printenv` exits 1 on a missing var, so
    // we use parameter expansion which yields the empty string.
    let r = resolver_with(
        "tok",
        Source::Script {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    r#"printf '%s|%s' "${{HOME-}}" "${{{}-}}""#,
                    poison_key
                ),
            ],
            ttl_secs: 1, // short TTL doesn't matter — single call
        },
    );
    let v = r.resolve("tok", None).await.unwrap();
    let (home_seen, poison_seen) = v
        .split_once('|')
        .expect("script output should be HOME|POISON");
    assert!(
        !home_seen.is_empty(),
        "HOME is on the allowlist and must reach the script (got empty)"
    );
    assert_eq!(
        poison_seen, "",
        "the parent's poison env var must NOT reach the script (got {poison_seen:?})"
    );

    unsafe { std::env::remove_var(&poison_key) };
}

#[tokio::test]
async fn script_env_passes_match_host() {
    // The `match_host` arg becomes HERMIT_MATCH_HOST in the
    // script env — used by helper scripts that branch on
    // which upstream the credential is for. Must survive the
    // env_clear().
    let r = resolver_with(
        "tok",
        Source::Script {
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf '%s' \"$HERMIT_MATCH_HOST\"".into(),
            ],
            ttl_secs: 1,
        },
    );
    let v = r.resolve("tok", Some("api.example.com")).await.unwrap();
    assert_eq!(v, "api.example.com");
}
