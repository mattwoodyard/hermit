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
