//! Tests for `sni_proxy::dispatch`. The post-handshake dispatcher
//! is private; we reach it through the `__test_internals`
//! wrapper for `splice_after_sni`.

use sni_proxy::block_log::BlockLogger;
use sni_proxy::ca::CertificateAuthority;
use sni_proxy::connector::DirectConnector;
use sni_proxy::dispatch::__test_internals::splice_after_sni_wrapper;
use sni_proxy::mitm::MitmConfig;
use sni_proxy::policy::AllowAll;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn splice_after_sni_forwards_hello_and_bytes() {
    // The splice path's job is to replay the buffered
    // ClientHello to the upstream verbatim — without that
    // the client's TLS state machine has nothing to
    // continue against. This test stands up a mock
    // upstream, hands `splice_after_sni` an already-buffered
    // ClientHello, and asserts the upstream sees those
    // bytes and its reply flows back to the (fake) client.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (mut s, _) = upstream.accept().await.unwrap();
        let mut got = vec![0u8; 11];
        s.read_exact(&mut got).await.unwrap();
        s.write_all(b"UP").await.unwrap();
        s.shutdown().await.unwrap();
        got
    });

    let pair_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair_listener.local_addr().unwrap();
    let (accept_res, connect_res) = tokio::join!(
        pair_listener.accept(),
        tokio::net::TcpStream::connect(pair_addr),
    );
    let (server_side, _) = accept_res.unwrap();
    let mut client_side = connect_res.unwrap();

    let ca = Arc::new(CertificateAuthority::new().unwrap());
    let config = MitmConfig {
        policy: Arc::new(AllowAll),
        connector: Arc::new(DirectConnector),
        ca,
        upstream_port,
        network_policy: None,
        block_log: BlockLogger::disabled(),
        access_log: BlockLogger::disabled(),
        upstream_roots: None,
    };

    let hello = b"CLIENTHELLO".to_vec();

    let splice_done = tokio::spawn(async move {
        let _ = splice_after_sni_wrapper(server_side, &hello, "127.0.0.1", None, &config).await;
    });

    let mut resp = [0u8; 2];
    client_side.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"UP");

    drop(client_side);

    tokio::time::timeout(Duration::from_secs(2), splice_done)
        .await
        .expect("splice timed out")
        .unwrap();

    let received = upstream_task.await.unwrap();
    assert_eq!(&received, b"CLIENTHELLO");
}
