//! Tests for `sni_proxy::network_policy`. Uses the public
//! `NetworkPolicy` + `render_inject_value` API; the private `rules`
//! field length is read via `__test_internals::rule_count`.

use http::Request;
use sni_proxy::network_policy::{render_inject_value, NetworkPolicy};
use sni_proxy::network_policy::__test_internals::rule_count;

fn req(method: &str, uri: &str) -> Request<()> {
    Request::builder().method(method).uri(uri).body(()).unwrap()
}

const SAMPLE: &str = r#"
[[rule]]
match = 'url.host == "api.github.com" && method == "GET"'
credential = "gh_token"

[[rule]]
match = 'url.host ~ ".*\.openai\.com"'
credential = "openai_key"

[credential.gh_token]
source = { type = "env", name = "GITHUB_TOKEN" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]

[credential.openai_key]
source = { type = "script", command = ["/bin/echo", "-n", "sk-abc"], ttl_secs = 60 }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#;

#[test]
fn loads_and_compiles() {
    let p = NetworkPolicy::from_toml(SAMPLE).unwrap();
    assert_eq!(rule_count(&p), 2);
}

#[test]
fn first_match_wins() {
    let p = NetworkPolicy::from_toml(SAMPLE).unwrap();

    let r = p.resolve(&req("GET", "https://api.github.com/users")).unwrap();
    assert_eq!(r.credential, "gh_token");

    let r = p.resolve(&req("GET", "https://api.openai.com/v1")).unwrap();
    assert_eq!(r.credential, "openai_key");

    assert!(p.resolve(&req("GET", "https://example.com/")).is_none());

    // Method narrows: POST to github.com should not match the first rule
    assert!(p.resolve(&req("POST", "https://api.github.com/")).is_none());
}

#[test]
fn unknown_credential_reference_is_error() {
    let toml = r#"
[[rule]]
match = 'url.host == "x"'
credential = "ghost"
"#;
    assert!(NetworkPolicy::from_toml(toml).is_err());
}

#[test]
fn bad_match_expression_is_error() {
    let toml = r#"
[[rule]]
match = 'this is not valid'
credential = "k"

[credential.k]
source = { type = "env", name = "X" }
"#;
    assert!(NetworkPolicy::from_toml(toml).is_err());
}

#[test]
fn template_substitution() {
    assert_eq!(render_inject_value("Bearer {cred}", "tok"), "Bearer tok");
    assert_eq!(render_inject_value("no-placeholder", "tok"), "no-placeholder");
    assert_eq!(
        render_inject_value("{cred}/{cred}", "x"),
        "x/x",
        "multiple placeholders all get replaced"
    );
}

#[tokio::test]
async fn acquire_runs_source_and_returns_value() {
    let p = NetworkPolicy::from_toml(SAMPLE).unwrap();
    let rule = p
        .resolve(&req("GET", "https://api.openai.com/v1"))
        .unwrap();
    let v = p.acquire(rule, Some("api.openai.com")).await.unwrap();
    assert_eq!(v, "sk-abc");

    let actions = p.inject_actions(rule).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].header, "Authorization");
    assert_eq!(
        render_inject_value(&actions[0].value, &v),
        "Bearer sk-abc"
    );
}

#[test]
fn empty_policy_matches_nothing() {
    let p = NetworkPolicy::from_toml("").unwrap();
    assert!(p.resolve(&req("GET", "https://x/")).is_none());
}
