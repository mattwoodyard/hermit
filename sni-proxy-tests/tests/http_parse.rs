//! Tests for `sni_proxy::http::parse`.
//!
//! `split_absolute_form` is `pub(crate)` so it isn't reachable
//! directly from this crate. Reach it via
//! `sni_proxy::http::__test_internals` (only available because
//! sni-proxy-tests turns on the `__test_internals` feature).

use sni_proxy::http::{host_without_port, read_request};
use sni_proxy::http::__test_internals::split_absolute_form;

#[tokio::test]
async fn parse_simple_get() {
    let data = b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut reader = &data[..];
    let (req, leftover) = read_request(&mut reader).await.unwrap().unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/foo");
    assert_eq!(req.host.as_deref(), Some("example.com"));
    assert!(req.content_length.is_none());
    assert!(!req.chunked);
    assert!(leftover.is_empty());
}

#[tokio::test]
async fn parse_post_with_content_length() {
    let data = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
    let mut reader = &data[..];
    let (req, leftover) = read_request(&mut reader).await.unwrap().unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/upload");
    assert_eq!(req.content_length, Some(5));
    assert_eq!(leftover, b"hello");
}

#[tokio::test]
async fn parse_eof_returns_none() {
    let data: &[u8] = b"";
    let mut reader = data;
    let req = read_request(&mut reader).await.unwrap();
    assert!(req.is_none());
}

#[tokio::test]
async fn parse_rejects_conflicting_content_length() {
    let data = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello";
    let mut reader = &data[..];
    let err = read_request(&mut reader).await.unwrap_err();
    assert!(
        err.to_string().contains("conflicting Content-Length"),
        "expected smuggling guard, got: {err}"
    );
}

#[tokio::test]
async fn parse_accepts_identical_duplicate_content_length() {
    let data = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert_eq!(req.content_length, Some(5));
}

#[tokio::test]
async fn parse_rejects_multiple_transfer_encoding_headers() {
    let data = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n";
    let mut reader = &data[..];
    let err = read_request(&mut reader).await.unwrap_err();
    assert!(
        err.to_string().contains("multiple Transfer-Encoding"),
        "expected smuggling guard, got: {err}"
    );
}

#[test]
fn host_without_port_plain() {
    assert_eq!(host_without_port("example.com"), "example.com");
    assert_eq!(host_without_port("example.com:8080"), "example.com");
}

#[test]
fn host_without_port_ipv6() {
    assert_eq!(host_without_port("[::1]"), "[::1]");
    assert_eq!(host_without_port("[::1]:8080"), "[::1]");
    assert_eq!(host_without_port("[2001:db8::1]:443"), "[2001:db8::1]");
}

#[test]
fn host_without_port_bare_ipv6_kept_intact() {
    assert_eq!(host_without_port("::1"), "::1");
}

#[test]
fn split_absolute_form_extracts_authority_and_path() {
    let (path, auth) = split_absolute_form("http://example.com/foo?q=1");
    assert_eq!(path, "/foo?q=1");
    assert_eq!(auth.as_deref(), Some("example.com"));
}

#[test]
fn split_absolute_form_handles_port_in_authority() {
    let (path, auth) = split_absolute_form("http://example.com:8080/bar");
    assert_eq!(path, "/bar");
    assert_eq!(auth.as_deref(), Some("example.com:8080"));
}

#[test]
fn split_absolute_form_defaults_missing_path_to_root() {
    let (path, auth) = split_absolute_form("http://example.com");
    assert_eq!(path, "/");
    assert_eq!(auth.as_deref(), Some("example.com"));
}

#[test]
fn split_absolute_form_leaves_origin_form_unchanged() {
    let (path, auth) = split_absolute_form("/foo");
    assert_eq!(path, "/foo");
    assert!(auth.is_none());
}

#[tokio::test]
async fn parse_absolute_form_normalizes_to_origin_form() {
    let data = b"GET http://example.com/foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert_eq!(req.path, "/foo");
    assert_eq!(req.host.as_deref(), Some("example.com"));
    let head = std::str::from_utf8(&req.head_bytes).unwrap();
    assert!(
        head.starts_with("GET /foo HTTP/1.1\r\n"),
        "rewritten request line must be origin-form: {head:?}"
    );
}

#[tokio::test]
async fn parse_absolute_form_backfills_missing_host_header() {
    let data = b"GET http://example.com/ HTTP/1.1\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert_eq!(req.host.as_deref(), Some("example.com"));
    let head = std::str::from_utf8(&req.head_bytes).unwrap();
    assert!(head.contains("\r\nHost: example.com\r\n"),
        "rewrite must insert Host header: {head:?}");
}

#[tokio::test]
async fn parse_connect_keeps_authority_form_path() {
    let data = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert_eq!(req.method, "CONNECT");
    assert_eq!(req.path, "example.com:443");
}

#[tokio::test]
async fn rejects_cl_plus_chunked_smuggling_attempt() {
    let data =
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut reader = &data[..];
    let err = read_request(&mut reader).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("Content-Length") && msg.contains("chunked"), "got: {msg}");
}

#[tokio::test]
async fn http11_default_keep_alive() {
    let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert!(!req.connection_close);
}

#[tokio::test]
async fn http11_connection_close_honored() {
    let data = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert!(req.connection_close);
}

#[tokio::test]
async fn http10_default_closes() {
    let data = b"GET / HTTP/1.0\r\nHost: x\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert_eq!(req.version, 0);
    assert!(req.connection_close);
}

#[tokio::test]
async fn http10_keep_alive_opt_in() {
    let data = b"GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert!(!req.connection_close);
}

#[tokio::test]
async fn connection_header_multi_token() {
    let data = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, close\r\n\r\n";
    let mut reader = &data[..];
    let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
    assert!(req.connection_close);
}
