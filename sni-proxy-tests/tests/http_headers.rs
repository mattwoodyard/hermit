//! Tests for `sni_proxy::http::headers`. Uses only the public
//! `set_header` re-export under `sni_proxy::http`.

use sni_proxy::http::set_header;

#[test]
fn set_header_inserts_new() {
    let mut h = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    set_header(&mut h, "Authorization", "Bearer abc").unwrap();
    assert_eq!(
        std::str::from_utf8(&h).unwrap(),
        "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\n\r\n"
    );
}

#[test]
fn set_header_replaces_existing_case_insensitive() {
    let mut h = b"GET / HTTP/1.1\r\nHost: x\r\nauthorization: old\r\n\r\n".to_vec();
    set_header(&mut h, "Authorization", "Bearer new").unwrap();
    assert_eq!(
        std::str::from_utf8(&h).unwrap(),
        "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer new\r\n\r\n"
    );
}

#[test]
fn set_header_replaces_all_duplicates() {
    let mut h =
        b"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n".to_vec();
    set_header(&mut h, "Cookie", "only=this").unwrap();
    let out = std::str::from_utf8(&h).unwrap();
    assert_eq!(out.matches("Cookie:").count(), 1);
    assert!(out.contains("Cookie: only=this"));
}

#[test]
fn set_header_preserves_body() {
    let mut h =
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    set_header(&mut h, "X-Injected", "yes").unwrap();
    let out = std::str::from_utf8(&h).unwrap();
    assert!(out.ends_with("\r\n\r\nhello"));
    assert!(out.contains("X-Injected: yes"));
}

#[test]
fn set_header_errors_without_terminator() {
    let mut h = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
    assert!(set_header(&mut h, "X", "y").is_err());
}

#[test]
fn set_header_rejects_crlf_in_value() {
    let baseline = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    for poison in [
        "tok\r\nX-Smuggled: 1",
        "tok\nX-Smuggled: 1",
        "tok\rX-Smuggled: 1",
        "tok\0bad",
    ] {
        let mut h = baseline.clone();
        let err = set_header(&mut h, "Authorization", poison).unwrap_err();
        assert!(
            err.to_string().contains("forbidden byte"),
            "value {poison:?}: expected forbidden-byte error, got {err}"
        );
        assert_eq!(h, baseline, "buffer must be unchanged on reject");
    }
}

#[test]
fn set_header_rejects_invalid_chars_in_name() {
    let baseline = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    for poison in [
        "Bad Name",
        "Bad:Name",
        "Bad\r\nX-Other",
        "Bad\nX",
        "",
    ] {
        let mut h = baseline.clone();
        let err = set_header(&mut h, poison, "v").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid byte") || msg.contains("must not be empty"),
            "name {poison:?}: expected validation error, got {err}"
        );
        assert_eq!(h, baseline, "buffer must be unchanged on reject");
    }
}

#[test]
fn set_header_accepts_normal_tchar_names_and_printable_values() {
    let mut h = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    set_header(&mut h, "Authorization", "Bearer sk-ant_abc.def-ghi/jkl=").unwrap();
    set_header(&mut h, "X-Api-Key", "key|with~lots!of#tchars").unwrap();
    let out = std::str::from_utf8(&h).unwrap();
    assert!(out.contains("Authorization: Bearer sk-ant_abc.def-ghi/jkl=\r\n"));
    assert!(out.contains("X-Api-Key: key|with~lots!of#tchars\r\n"));
}
