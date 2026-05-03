//! Tests for `sni_proxy::http` 4xx canned responders. `write_403`
//! and `write_421` are re-exported via `sni_proxy::http`, no
//! `__test_internals` wrappers needed.

use sni_proxy::http::{write_403, write_421};
use tokio::io::{duplex, AsyncReadExt};

#[tokio::test]
async fn write_403_response() {
    let (mut client, mut server) = duplex(1024);
    tokio::spawn(async move {
        write_403(&mut server, "blocked by policy").await.unwrap();
    });
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("HTTP/1.1 403"));
    assert!(s.contains("blocked by policy"));
}

#[tokio::test]
async fn write_421_response() {
    let (mut client, mut server) = duplex(1024);
    tokio::spawn(async move {
        write_421(&mut server, "host mismatch").await.unwrap();
    });
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.starts_with("HTTP/1.1 421"));
    assert!(s.contains("host mismatch"));
}
