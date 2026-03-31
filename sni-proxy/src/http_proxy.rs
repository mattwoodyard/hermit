//! Plain HTTP proxy for port 80 traffic.
//!
//! Accepts TCP connections, parses the HTTP request to extract Host header,
//! path, and method, checks the request-level policy, then connects
//! upstream and relays the request/response.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::connector::UpstreamConnector;
use crate::http;
use crate::policy::{RequestPolicy, Verdict};

/// Configuration for the HTTP proxy.
pub struct HttpProxyConfig<P, C> {
    pub policy: Arc<P>,
    pub connector: Arc<C>,
    pub upstream_port: u16,
}

/// Run the HTTP proxy accept loop on port 80 traffic.
pub async fn run<P, C>(listener: TcpListener, config: Arc<HttpProxyConfig<P, C>>) -> Result<()>
where
    P: RequestPolicy + 'static,
    C: UpstreamConnector + 'static,
{
    loop {
        let (stream, addr) = listener.accept().await?;
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            info!(%addr, "http: accepted connection");
            if let Err(e) = handle_connection(stream, addr, &config).await {
                debug!(%addr, error = %e, "http: connection ended");
            }
        });
    }
}

/// Handle a single plain HTTP connection.
async fn handle_connection<P, C>(
    mut client: TcpStream,
    client_addr: SocketAddr,
    config: &HttpProxyConfig<P, C>,
) -> Result<()>
where
    P: RequestPolicy,
    C: UpstreamConnector,
{
    loop {
        let request = match http::read_request(&mut client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()),
            Err(e) => {
                debug!(%client_addr, error = %e, "http: error reading request");
                return Ok(());
            }
        };

        let hostname = match &request.host {
            Some(h) => {
                // Strip port from Host header if present
                h.split(':').next().unwrap_or(h).to_string()
            }
            None => {
                warn!(%client_addr, "http: no Host header, dropping");
                return Ok(());
            }
        };

        info!(
            %client_addr, %hostname,
            method = %request.method, path = %request.path,
            "http: request"
        );

        // Check request-level policy
        if config.policy.check_request(&hostname, &request.path, &request.method) == Verdict::Deny {
            warn!(
                %client_addr, %hostname,
                method = %request.method, path = %request.path,
                "http: request denied by policy"
            );
            http::write_403(&mut client, "blocked by hermit policy").await?;
            return Ok(());
        }

        // Connect upstream
        let mut upstream = config
            .connector
            .connect(&hostname, config.upstream_port, None)
            .await
            .context("connecting upstream")?;

        // Forward request headers
        upstream
            .write_all(&request.head_bytes)
            .await
            .context("forwarding request headers")?;

        // Forward request body
        if let Some(len) = request.content_length {
            http::forward_body_content_length(&mut client, &mut upstream, len, &[])
                .await
                .context("forwarding request body")?;
        }
        upstream.flush().await?;

        // Read and forward response
        let (response, leftover) = http::read_response(&mut upstream).await?;
        client
            .write_all(&response.head_bytes)
            .await
            .context("forwarding response headers")?;

        if let Some(len) = response.content_length {
            http::forward_body_content_length(&mut upstream, &mut client, len, &leftover)
                .await
                .context("forwarding response body")?;
        } else if response.chunked {
            if !leftover.is_empty() {
                client.write_all(&leftover).await?;
            }
            copy_bidirectional(&mut upstream, &mut client).await?;
            return Ok(());
        } else {
            if !leftover.is_empty() {
                client.write_all(&leftover).await?;
            }
            let mut buf = [0u8; 8192];
            loop {
                let n = upstream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n]).await?;
            }
            return Ok(());
        }

        client.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AllowAll, RuleSet, AccessRule};

    #[test]
    fn config_builds_with_allow_all() {
        let config = HttpProxyConfig {
            policy: Arc::new(AllowAll),
            connector: Arc::new(crate::connector::DirectConnector),
            upstream_port: 80,
        };
        assert_eq!(config.upstream_port, 80);
    }

    #[test]
    fn config_builds_with_ruleset() {
        let rules = vec![AccessRule::host_only("example.com")];
        let config = HttpProxyConfig {
            policy: Arc::new(RuleSet::new(rules)),
            connector: Arc::new(crate::connector::DirectConnector),
            upstream_port: 80,
        };
        assert_eq!(config.upstream_port, 80);
    }
}
