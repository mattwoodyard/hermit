//! Tests for `sni_proxy::connector`. The trait + `DirectConnector`
//! are part of the public API, so no `__test_internals` wrappers
//! are needed.

use sni_proxy::connector::{DirectConnector, UpstreamConnector};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::test]
async fn direct_connector_connects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let connector = DirectConnector;
    let stream = connector.connect("127.0.0.1", port, None).await.unwrap();
    assert!(stream.peer_addr().is_ok());
}

#[tokio::test]
async fn direct_connector_fails_on_refused_port() {
    let connector = DirectConnector;
    // Port 1 on localhost will be refused immediately, no timeout wait
    let result = connector.connect("127.0.0.1", 1, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn direct_connector_prefers_original_dst_port() {
    // Spin up a listener on an ephemeral port, advertise it via
    // original_dst, and pass a wrong `port` argument. The connector
    // must dial the original_dst port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let real_port = listener.local_addr().unwrap().port();
    let wrong_port = real_port.wrapping_add(1); // unlikely to be bound
    let original_dst: SocketAddr = format!("127.0.0.1:{real_port}").parse().unwrap();

    let connector = DirectConnector;
    let stream = connector
        .connect("127.0.0.1", wrong_port, Some(original_dst))
        .await
        .expect("connect via original_dst port");
    assert!(stream.peer_addr().is_ok());
}
