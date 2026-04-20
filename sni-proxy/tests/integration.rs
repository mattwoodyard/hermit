use std::sync::Arc;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use sni_proxy::connector::DirectConnector;
use sni_proxy::policy::{AllowList, AllowAll};
use sni_proxy::proxy::{self, ProxyConfig};

/// Install rustls' default crypto provider. rustls 0.23 requires a
/// process-wide provider and will panic on first use otherwise. This is
/// idempotent; the second caller's Err is ignored.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a real TLS ClientHello for the given hostname using rustls.
fn make_client_hello(server_name: &str) -> Vec<u8> {
    install_crypto_provider();
    use rustls::ClientConnection;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let name: rustls::pki_types::ServerName<'static> =
        server_name.to_string().try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).unwrap();
    buf
}

/// Spin up a mock "upstream" TCP server that echoes back a marker so we can
/// verify the proxy forwarded bytes correctly.
async fn mock_upstream(marker: &'static [u8]) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = vec![0u8; 4096];
        let n = stream.read(&mut received).await.unwrap();
        received.truncate(n);
        stream.write_all(marker).await.unwrap();
        stream.shutdown().await.unwrap();
        received
    });
    (port, handle)
}

#[tokio::test]
async fn allowed_host_is_forwarded() {
    let marker = b"UPSTREAM_OK";
    let (upstream_port, upstream_handle) = mock_upstream(marker).await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let config = Arc::new(ProxyConfig {
        policy: Arc::new(AllowList::new(["localhost".into()].into())),
        connector: Arc::new(DirectConnector),
        upstream_port,
    });

    let proxy_handle = tokio::spawn(async move {
        let (stream, addr) = proxy_listener.accept().await.unwrap();
        proxy::handle_connection_full(stream, addr, &config).await
    });

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let hello = make_client_hello("localhost");
    client.write_all(&hello).await.unwrap();

    let mut response = vec![0u8; 64];
    let n = client.read(&mut response).await.unwrap();
    assert_eq!(&response[..n], marker);

    drop(client);

    let received = upstream_handle.await.unwrap();
    assert_eq!(received, hello);

    proxy_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn denied_host_is_dropped() {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let config = Arc::new(ProxyConfig {
        policy: Arc::new(AllowList::new(["allowed.example.com".into()].into())),
        connector: Arc::new(DirectConnector),
        upstream_port: 443,
    });

    let proxy_handle = tokio::spawn(async move {
        let (stream, addr) = proxy_listener.accept().await.unwrap();
        proxy::handle_connection_full(stream, addr, &config).await
    });

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let hello = make_client_hello("blocked.example.com");
    client.write_all(&hello).await.unwrap();

    let mut response = vec![0u8; 64];
    let n = client.read(&mut response).await.unwrap();
    assert_eq!(n, 0, "expected connection to be closed by proxy");

    proxy_handle.await.unwrap().unwrap();
}

#[tokio::test]
async fn garbage_input_returns_error() {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let config = Arc::new(ProxyConfig {
        policy: Arc::new(AllowAll),
        connector: Arc::new(DirectConnector),
        upstream_port: 443,
    });

    let proxy_handle = tokio::spawn(async move {
        let (stream, addr) = proxy_listener.accept().await.unwrap();
        proxy::handle_connection_full(stream, addr, &config).await
    });

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(b"this is garbage not TLS").await.unwrap();
    client.shutdown().await.unwrap();

    let result = proxy_handle.await.unwrap();
    assert!(result.is_err(), "expected error for garbage input");
}

/// Test the SNI extraction directly with a Cursor (buffer-only, no network).
#[test]
fn sni_extraction_roundtrip() {
    install_crypto_provider();
    let hello = make_client_hello("myhost.example.org");
    let mut cursor = Cursor::new(&hello);
    let mut acceptor = rustls::server::Acceptor::default();
    acceptor.read_tls(&mut cursor).unwrap();
    let accepted = acceptor.accept().unwrap().expect("should have full ClientHello");
    assert_eq!(
        accepted.client_hello().server_name(),
        Some("myhost.example.org")
    );
}
