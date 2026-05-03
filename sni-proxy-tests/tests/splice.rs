//! Tests for `sni_proxy::splice`. `relay` is part of the public
//! API; the lower-level `copy_with_idle` is private and is reached
//! through the `__test_internals` wrapper.

use sni_proxy::splice::__test_internals::copy_with_idle;
use sni_proxy::splice::relay;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn copy_with_idle_passes_bytes_and_terminates_on_eof() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let data = b"hello world";
    client.write_all(data).await.unwrap();
    drop(client);

    let mut sink: Vec<u8> = Vec::new();
    let bytes = copy_with_idle(&mut server, &mut sink, Duration::from_secs(5))
        .await
        .expect("clean EOF should not return an error");
    assert_eq!(bytes, data.len() as u64);
    assert_eq!(sink, data);
}

#[tokio::test]
async fn copy_with_idle_times_out_when_reader_stalls() {
    let (_client, mut server) = tokio::io::duplex(4096);
    let mut sink: Vec<u8> = Vec::new();
    let res = copy_with_idle(&mut server, &mut sink, Duration::from_millis(100)).await;
    let err = res.expect_err("stalled reader must trip idle timeout");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
}

/// `relay` forwards `replay` verbatim, then any subsequent
/// bytes the client sends after the call begins.
#[tokio::test]
async fn relay_writes_replay_then_splices() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let mut client_tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let (server_side, _) = proxy_listener.accept().await.unwrap();

    let upstream = TcpStream::connect(upstream_addr).await.unwrap();

    let replay = b"REPLAYED_HELLO";
    let join = tokio::spawn(async move {
        relay(server_side, upstream, replay).await.unwrap()
    });

    client_tcp.write_all(b"AFTER").await.unwrap();
    drop(client_tcp);

    let _ = join.await.unwrap();
    let received = echo.await.unwrap();
    assert!(received.starts_with(b"REPLAYED_HELLO"),
        "replay bytes must precede the spliced stream: {received:?}");
    assert!(received.ends_with(b"AFTER"),
        "post-replay bytes must reach upstream: {received:?}");
}

/// Empty `replay` is the forward CONNECT-splice case —
/// nothing prepended, just bidirectional copy.
#[tokio::test]
async fn relay_empty_replay_is_pure_splice() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let mut client_tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let (server_side, _) = proxy_listener.accept().await.unwrap();
    let upstream = TcpStream::connect(upstream_addr).await.unwrap();

    let join = tokio::spawn(async move {
        relay(server_side, upstream, &[]).await.unwrap()
    });

    client_tcp.write_all(b"only the post-200 bytes").await.unwrap();
    drop(client_tcp);

    let _ = join.await.unwrap();
    assert_eq!(echo.await.unwrap(), b"only the post-200 bytes");
}

/// `relay` returns the actual byte counts copied each direction.
#[tokio::test]
async fn relay_returns_byte_counts_each_direction() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        // After client closes, send an answer, then close.
        s.write_all(b"REPLY").await.unwrap();
        s.shutdown().await.unwrap();
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let mut client_tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let (server_side, _) = proxy_listener.accept().await.unwrap();
    let upstream = TcpStream::connect(upstream_addr).await.unwrap();

    let join = tokio::spawn(async move {
        relay(server_side, upstream, b"HELLO").await.unwrap()
    });

    client_tcp.write_all(b"DATA").await.unwrap();
    client_tcp.shutdown().await.unwrap();

    // Drain the upstream's reply so the upstream→client half
    // can finish copying before we read counts.
    let mut got_back = Vec::new();
    client_tcp.read_to_end(&mut got_back).await.unwrap();

    let (a_to_b, b_to_a) = join.await.unwrap();
    upstream_task.await.unwrap();

    // Replay (5) is written outside the bidirectional copy and
    // is NOT counted in `a_to_b`. The post-replay client bytes
    // ("DATA") are.
    assert_eq!(a_to_b, 4, "a_to_b should count only post-replay client bytes");
    assert_eq!(b_to_a, 5, "b_to_a should count the upstream reply");
    assert_eq!(&got_back, b"REPLY");
}
