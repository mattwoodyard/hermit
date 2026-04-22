use anyhow::{Context, Result};
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Strategy for establishing upstream connections.
///
/// The default implementation connects directly via DNS + TCP.
/// Hermit will inject a connector that dials from the host network
/// namespace (outside the sandbox).
pub trait UpstreamConnector: Send + Sync {
    fn connect(
        &self,
        hostname: &str,
        port: u16,
        original_dst: Option<SocketAddr>,
    ) -> impl Future<Output = Result<TcpStream>> + Send;
}

/// Connects upstream by resolving the SNI hostname and dialing directly.
///
/// When `original_dst` is `Some`, the port from the pre-DNAT destination
/// wins over the proxy's default `upstream_port`. This matters for port
/// forwards: a client aiming at `host:8443` ends up at the MITM's 1443
/// listener, and we want the upstream connection on 8443 — not 443.
pub struct DirectConnector;

impl UpstreamConnector for DirectConnector {
    async fn connect(
        &self,
        hostname: &str,
        port: u16,
        original_dst: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        let upstream_port = original_dst.map(|a| a.port()).unwrap_or(port);
        TcpStream::connect(format!("{hostname}:{upstream_port}"))
            .await
            .with_context(|| format!("connecting to {hostname}:{upstream_port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
