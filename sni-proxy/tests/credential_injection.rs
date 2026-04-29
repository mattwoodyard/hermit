//! End-to-end integration test for the credential-injection pipeline.
//!
//! Exercises the full chain: TOML policy load → match DSL evaluation →
//! credential source acquisition → header template render → raw-bytes
//! edit via `transparent::apply_injection`. This is the same code path the MITM
//! loop executes per request; the only piece not exercised here is the
//! TLS plumbing, which is unchanged by this feature.

use std::io::Write;

use sni_proxy::http::Request;
use sni_proxy::mitm::apply_injection;
use sni_proxy::network_policy::NetworkPolicy;

/// Build a parsed `http::Request` from a raw HTTP head, mirroring what
/// `http::read_request` would produce.
fn parsed_request(head: &[u8]) -> Request {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    let status = parsed.parse(head).expect("parse head");
    assert!(status.is_complete());
    let method = parsed.method.unwrap().to_string();
    let path = parsed.path.unwrap().to_string();
    let host = parsed
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .map(|h| String::from_utf8_lossy(h.value).to_string());
    Request {
        method,
        path,
        version: 1,
        head_bytes: head.to_vec(),
        content_length: None,
        chunked: false,
        host,
        connection_close: false,
    }
}

#[tokio::test]
async fn injection_via_env_source() {
    // SAFETY: set_var is safe in single-threaded test startup.
    unsafe { std::env::set_var("INJ_INT_ENV", "env-secret-123") };

    let toml = r#"
[[rule]]
match = 'url.host == "api.example.com" && method == "GET"'
credential = "tok"

[credential.tok]
source = { type = "env", name = "INJ_INT_ENV" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#;
    let np = NetworkPolicy::from_toml(toml).unwrap();

    let mut req = parsed_request(
        b"GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: test\r\n\r\n",
    );

    apply_injection(&np, "api.example.com", &mut req).await;

    let out = std::str::from_utf8(&req.head_bytes).unwrap();
    assert!(
        out.contains("Authorization: Bearer env-secret-123\r\n"),
        "expected injected header, got:\n{out}"
    );
    // Original headers preserved
    assert!(out.contains("Host: api.example.com\r\n"));
    assert!(out.contains("User-Agent: test\r\n"));
}

#[tokio::test]
async fn injection_via_script_source_with_host_env() {
    // Script echoes the matched host, prefixed; verifies HERMIT_MATCH_HOST
    // is piped to the script and that stdout is used as the credential value.
    let toml = r#"
[[rule]]
match = 'url.host == "api.openai.com"'
credential = "dyn"

[credential.dyn]
source = { type = "script", command = ["/bin/sh", "-c", "echo -n tok-for-$HERMIT_MATCH_HOST"], ttl_secs = 60 }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#;
    let np = NetworkPolicy::from_toml(toml).unwrap();

    let mut req = parsed_request(
        b"POST /v1/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
    );
    apply_injection(&np, "api.openai.com", &mut req).await;

    let out = std::str::from_utf8(&req.head_bytes).unwrap();
    assert!(
        out.contains("Authorization: Bearer tok-for-api.openai.com\r\n"),
        "expected injected header, got:\n{out}"
    );
}

#[tokio::test]
async fn injection_replaces_existing_header() {
    unsafe { std::env::set_var("INJ_REPLACE", "new-token") };

    let toml = r#"
[[rule]]
match = 'url.host == "api.x.io"'
credential = "tok"

[credential.tok]
source = { type = "env", name = "INJ_REPLACE" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#;
    let np = NetworkPolicy::from_toml(toml).unwrap();

    let mut req = parsed_request(
        b"GET / HTTP/1.1\r\nHost: api.x.io\r\nauthorization: Bearer OLD-TOKEN\r\n\r\n",
    );
    apply_injection(&np, "api.x.io", &mut req).await;

    let out = std::str::from_utf8(&req.head_bytes).unwrap();
    assert!(out.contains("Authorization: Bearer new-token\r\n"));
    assert!(!out.contains("OLD-TOKEN"), "old credential must be removed");
    assert_eq!(out.matches("uthorization:").count(), 1);
}

#[tokio::test]
async fn no_match_leaves_request_unchanged() {
    let toml = r#"
[[rule]]
match = 'url.host == "api.example.com"'
credential = "tok"

[credential.tok]
source = { type = "env", name = "NEVER_USED" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#;
    let np = NetworkPolicy::from_toml(toml).unwrap();

    let original = b"GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n".to_vec();
    let mut req = parsed_request(&original);
    apply_injection(&np, "other.example.com", &mut req).await;
    assert_eq!(req.head_bytes, original);
}

#[tokio::test]
async fn credential_acquisition_failure_leaves_request_unchanged() {
    // Env var intentionally unset so env lookup fails; request must still
    // forward unmodified (fail-open for injection).
    unsafe { std::env::remove_var("INJ_MISSING_VAR_12345") };

    let toml = r#"
[[rule]]
match = 'url.host == "fail.example.com"'
credential = "tok"

[credential.tok]
source = { type = "env", name = "INJ_MISSING_VAR_12345" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#;
    let np = NetworkPolicy::from_toml(toml).unwrap();

    let original = b"GET / HTTP/1.1\r\nHost: fail.example.com\r\n\r\n".to_vec();
    let mut req = parsed_request(&original);
    apply_injection(&np, "fail.example.com", &mut req).await;
    assert_eq!(
        req.head_bytes, original,
        "request must not be mutated when credential acquisition fails"
    );
}

#[tokio::test]
async fn injection_via_file_source() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "file-token-xyz").unwrap();
    let path = f.path().to_string_lossy().to_string();

    let toml = format!(
        r#"
[[rule]]
match = 'url.host == "api.example.com"'
credential = "tok"

[credential.tok]
source = {{ type = "file", path = "{path}" }}
inject = [{{ header = "Authorization", value = "Bearer {{cred}}" }}]
"#
    );
    let np = NetworkPolicy::from_toml(&toml).unwrap();

    let mut req = parsed_request(b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
    apply_injection(&np, "api.example.com", &mut req).await;

    let out = std::str::from_utf8(&req.head_bytes).unwrap();
    assert!(
        out.contains("Authorization: Bearer file-token-xyz\r\n"),
        "got:\n{out}"
    );
}

#[tokio::test]
async fn first_match_wins_across_multiple_rules() {
    unsafe { std::env::set_var("INJ_FIRST", "first-tok") };
    unsafe { std::env::set_var("INJ_SECOND", "second-tok") };

    // Both rules would match; first should win.
    let toml = r#"
[[rule]]
match = 'url.host == "api.example.com"'
credential = "first"

[[rule]]
match = 'url.host ~ ".*\.example\.com"'
credential = "second"

[credential.first]
source = { type = "env", name = "INJ_FIRST" }
inject = [{ header = "X-Which", value = "{cred}" }]

[credential.second]
source = { type = "env", name = "INJ_SECOND" }
inject = [{ header = "X-Which", value = "{cred}" }]
"#;
    let np = NetworkPolicy::from_toml(toml).unwrap();

    let mut req = parsed_request(b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n");
    apply_injection(&np, "api.example.com", &mut req).await;

    let out = std::str::from_utf8(&req.head_bytes).unwrap();
    assert!(out.contains("X-Which: first-tok\r\n"));
    assert!(!out.contains("second-tok"));
}
