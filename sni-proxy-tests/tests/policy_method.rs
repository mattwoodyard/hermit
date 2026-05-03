//! Tests for `sni_proxy::policy` HTTP method parsing/display.
//! `HttpMethod` is part of the public policy API — no
//! `__test_internals` wrappers needed.

use sni_proxy::policy::HttpMethod;
use std::str::FromStr;

#[test]
fn parse_method_valid() {
    assert_eq!(HttpMethod::from_str("GET").unwrap(), HttpMethod::Get);
    assert_eq!(HttpMethod::from_str("get").unwrap(), HttpMethod::Get);
    assert_eq!(HttpMethod::from_str("Post").unwrap(), HttpMethod::Post);
    assert_eq!(HttpMethod::from_str("DELETE").unwrap(), HttpMethod::Delete);
    assert_eq!(HttpMethod::from_str("patch").unwrap(), HttpMethod::Patch);
}

#[test]
fn parse_method_invalid() {
    assert!(HttpMethod::from_str("CONNECT").is_err());
    assert!(HttpMethod::from_str("").is_err());
    assert!(HttpMethod::from_str("FOOBAR").is_err());
}

#[test]
fn method_display_roundtrip() {
    for m in [
        HttpMethod::Get,
        HttpMethod::Head,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Delete,
        HttpMethod::Patch,
        HttpMethod::Options,
    ] {
        assert_eq!(HttpMethod::from_str(&m.to_string()).unwrap(), m);
    }
}
