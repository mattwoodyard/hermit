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
pub struct DirectConnector;

impl UpstreamConnector for DirectConnector {
    async fn connect(
        &self,
        hostname: &str,
        port: u16,
        _original_dst: Option<SocketAddr>,
    ) -> Result<TcpStream> {
        TcpStream::connect(format!("{hostname}:{port}"))
            .await
            .with_context(|| format!("connecting to {hostname}:{port}"))
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
}
