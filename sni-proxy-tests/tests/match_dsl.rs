//! Tests for `sni_proxy::match_dsl`. Exercises the DSL via the
//! public `Expr::compile` + `Expr::eval` API.

use http::Request;
use sni_proxy::match_dsl::Expr;

fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<()> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(()).unwrap()
}

#[test]
fn method_equality() {
    let e = Expr::compile(r#"method == "GET""#).unwrap();
    assert!(e.eval(&req("GET", "https://example.com/", &[])));
    assert!(!e.eval(&req("POST", "https://example.com/", &[])));
}

#[test]
fn url_host_equality() {
    let e = Expr::compile(r#"url.host == "api.github.com""#).unwrap();
    assert!(e.eval(&req("GET", "https://api.github.com/users", &[])));
    assert!(!e.eval(&req("GET", "https://example.com/", &[])));
}

#[test]
fn url_path_and_scheme() {
    let e = Expr::compile(r#"url.scheme == "https" && url.path == "/v1/users""#).unwrap();
    assert!(e.eval(&req("GET", "https://x/v1/users", &[])));
    assert!(!e.eval(&req("GET", "https://x/v2/users", &[])));
}

#[test]
fn regex_match() {
    let e = Expr::compile(r#"url.host ~ ".*\.openai\.com""#).unwrap();
    assert!(e.eval(&req("GET", "https://api.openai.com/v1", &[])));
    assert!(!e.eval(&req("GET", "https://example.com/", &[])));
}

#[test]
fn regex_not_match() {
    let e = Expr::compile(r#"url.host !~ "^api\.""#).unwrap();
    assert!(e.eval(&req("GET", "https://example.com/", &[])));
    assert!(!e.eval(&req("GET", "https://api.example.com/", &[])));
}

#[test]
fn not_equal() {
    let e = Expr::compile(r#"method != "GET""#).unwrap();
    assert!(e.eval(&req("POST", "https://x/", &[])));
    assert!(!e.eval(&req("GET", "https://x/", &[])));
}

#[test]
fn header_match_case_insensitive() {
    let e = Expr::compile(r#"headers.content-type == "application/json""#).unwrap();
    assert!(e.eval(&req(
        "POST",
        "https://x/",
        &[("Content-Type", "application/json")]
    )));
    assert!(!e.eval(&req(
        "POST",
        "https://x/",
        &[("Content-Type", "text/plain")]
    )));
}

#[test]
fn missing_header_is_false_for_eq() {
    let e = Expr::compile(r#"headers.authorization == "Bearer x""#).unwrap();
    assert!(!e.eval(&req("GET", "https://x/", &[])));
}

#[test]
fn missing_header_is_true_for_neq() {
    let e = Expr::compile(r#"headers.authorization != "Bearer x""#).unwrap();
    assert!(e.eval(&req("GET", "https://x/", &[])));
}

#[test]
fn parens_and_or() {
    let e = Expr::compile(
        r#"(method == "GET" || method == "HEAD") && url.host == "api.example.com""#,
    )
    .unwrap();
    assert!(e.eval(&req("GET", "https://api.example.com/", &[])));
    assert!(e.eval(&req("HEAD", "https://api.example.com/", &[])));
    assert!(!e.eval(&req("POST", "https://api.example.com/", &[])));
    assert!(!e.eval(&req("GET", "https://other.example.com/", &[])));
}

#[test]
fn escaped_quotes_in_literal() {
    let e = Expr::compile(r#"url.path == "/a\"b""#).unwrap();
    assert!(e.eval(&req("GET", r#"https://x/a"b"#, &[])));
}

#[test]
fn trailing_garbage_rejected() {
    let err = Expr::compile(r#"method == "GET" garbage"#);
    assert!(err.is_err());
}

#[test]
fn invalid_regex_rejected() {
    let err = Expr::compile(r#"url.host ~ "[unclosed""#);
    assert!(err.is_err());
}
