//! Tests for `sni_proxy::http` body forwarders. The three
//! forwarders are re-exported via `sni_proxy::http::*` — no
//! `__test_internals` wrappers needed.

use sni_proxy::http::{forward_body_content_length, forward_chunked_body, forward_until_eof};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn forward_chunked_simple() {
    let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let (mut reader, mut writer) = duplex(1024);
    let (mut out_tx, mut out_rx) = duplex(1024);

    tokio::spawn(async move {
        writer.write_all(body).await.unwrap();
        writer.shutdown().await.unwrap();
    });

    tokio::spawn(async move {
        forward_chunked_body(&mut reader, &mut out_tx, &[])
            .await
            .unwrap();
        out_tx.shutdown().await.unwrap();
    });

    let mut result = Vec::new();
    out_rx.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, body);
}

#[tokio::test]
async fn forward_chunked_with_leftover() {
    let body = b"3\r\nfoo\r\n0\r\n\r\n";
    let (mut reader, _writer) = duplex(64);
    let (mut out_tx, mut out_rx) = duplex(1024);

    tokio::spawn(async move {
        forward_chunked_body(&mut reader, &mut out_tx, body)
            .await
            .unwrap();
        out_tx.shutdown().await.unwrap();
    });

    let mut result = Vec::new();
    out_rx.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, body);
}

#[tokio::test]
async fn forward_content_length_body() {
    let body = b"hello";
    let (mut tx, mut rx) = duplex(1024);
    let (mut out_tx, mut out_rx) = duplex(1024);

    tokio::spawn(async move {
        tx.write_all(body).await.unwrap();
        tx.shutdown().await.unwrap();
    });

    tokio::spawn(async move {
        forward_body_content_length(&mut rx, &mut out_tx, 5, &[])
            .await
            .unwrap();
        out_tx.shutdown().await.unwrap();
    });

    let mut result = Vec::new();
    out_rx.read_to_end(&mut result).await.unwrap();
    assert_eq!(result, b"hello");
}

#[tokio::test]
async fn forward_until_eof_caps_runaway_response() {
    let (mut tx, mut rx) = duplex(1024);
    let (mut out_tx, _out_rx) = duplex(1024);

    tokio::spawn(async move {
        let _ = tx.write_all(&[b'a'; 64]).await;
        std::mem::forget(tx);
    });

    let err = forward_until_eof(&mut rx, &mut out_tx, &[], 16)
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("exceeded"));
}

#[tokio::test]
async fn forward_until_eof_passes_short_body() {
    let (mut tx, mut rx) = duplex(1024);
    let (mut out_tx, mut out_rx) = duplex(1024);
    tokio::spawn(async move {
        tx.write_all(b"short body").await.unwrap();
        tx.shutdown().await.unwrap();
    });
    tokio::spawn(async move {
        forward_until_eof(&mut rx, &mut out_tx, b"[prefix] ", 1024)
            .await
            .unwrap();
        out_tx.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    out_rx.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"[prefix] short body");
}

#[tokio::test]
async fn forward_chunked_streams_large_single_chunk() {
    let size = 256 * 1024usize;
    let mut wire: Vec<u8> = Vec::new();
    wire.extend_from_slice(format!("{size:x}\r\n").as_bytes());
    wire.extend(std::iter::repeat_n(b'x', size));
    wire.extend_from_slice(b"\r\n0\r\n\r\n");

    let (mut tx, mut rx) = duplex(64 * 1024);
    let (mut out_tx, mut out_rx) = duplex(64 * 1024);

    let wire_clone = wire.clone();
    tokio::spawn(async move {
        tx.write_all(&wire_clone).await.unwrap();
        tx.shutdown().await.unwrap();
    });

    tokio::spawn(async move {
        forward_chunked_body(&mut rx, &mut out_tx, &[]).await.unwrap();
        out_tx.shutdown().await.unwrap();
    });

    let mut got = Vec::new();
    out_rx.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, wire);
}
