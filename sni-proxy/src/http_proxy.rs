//! Plain HTTP proxy for port 80 traffic.
//!
//! Accepts TCP connections, parses the HTTP request to extract Host header,
//! path, and method, checks the request-level policy, then connects
//! upstream and relays the request/response.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::connector::UpstreamConnector;
use crate::http;
use crate::policy::{RequestPolicy, Verdict};
use crate::proxy::{get_original_dst, MAX_CONCURRENT_CONNECTIONS};

/// Max time to wait for a full HTTP request head on an idle keep-alive
/// connection. Keeps slow clients from parking tokio tasks forever.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Max time for the upstream TCP connect.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Hard cap on response body bytes when upstream omits both Content-Length
/// and Transfer-Encoding. Without this a trickling upstream could drain
/// the task forever.
const MAX_CLOSE_DELIMITED_RESPONSE: u64 = 512 * 1024 * 1024;

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
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // EMFILE / ECONNABORTED / etc. must not kill the listener —
                // back off briefly and retry.
                warn!(error = %e, "http: accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        // Acquire a slot before spawning — bounds concurrent in-flight
        // connections to avoid unbounded task accumulation under load.
        let permit = Arc::clone(&conn_limit)
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            let _permit = permit; // released on task end
            debug!(%addr, "http: accepted connection");
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
    // The pre-DNAT destination tells us which port the client was really
    // aiming at (e.g. 8080). The connector uses this in preference to
    // `config.upstream_port` so additional port_forward entries work.
    let original_dst = get_original_dst(&client);
    loop {
        let (request, leftover) = match timeout(
            HEADER_READ_TIMEOUT,
            http::read_request(&mut client),
        )
        .await
        {
            Ok(Ok(Some(pair))) => pair,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => {
                debug!(%client_addr, error = %e, "http: error reading request");
                return Ok(());
            }
            Err(_) => {
                debug!(%client_addr, "http: header read timed out");
                return Ok(());
            }
        };

        let hostname = match &request.host {
            Some(h) => http::host_without_port(h).to_string(),
            None => {
                warn!(%client_addr, "hermit blocked: HTTP request without Host header");
                return Ok(());
            }
        };

        debug!(
            %client_addr, %hostname,
            method = %request.method, path = %request.path,
            "http: request"
        );

        // Check request-level policy
        if config.policy.check_request(&hostname, &request.path, &request.method) == Verdict::Deny {
            warn!(
                %client_addr, %hostname,
                method = %request.method, path = %request.path,
                "hermit blocked: HTTP request {} http://{}{}", request.method, hostname, request.path
            );
            http::write_403(&mut client, "blocked by hermit policy").await?;
            return Ok(());
        }

        let mut upstream = match timeout(
            UPSTREAM_CONNECT_TIMEOUT,
            config
                .connector
                .connect(&hostname, config.upstream_port, original_dst),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e).context("connecting upstream"),
            Err(_) => {
                warn!(%hostname, "http: upstream connect timed out");
                return Ok(());
            }
        };

        // Forward request headers
        upstream
            .write_all(&request.head_bytes)
            .await
            .context("forwarding request headers")?;

        // Forward request body (leftover bytes from the header read come first)
        if let Some(len) = request.content_length {
            http::forward_body_content_length(&mut client, &mut upstream, len, &leftover)
                .await
                .context("forwarding request body")?;
        } else if request.chunked {
            http::forward_chunked_body(&mut client, &mut upstream, &leftover)
                .await
                .context("forwarding chunked request body")?;
        } else if !leftover.is_empty() {
            // Non-standard: no length, no chunked, but extra bytes buffered.
            // Safest is to forward what we've got.
            upstream.write_all(&leftover).await?;
        }
        upstream.flush().await?;

        // Read and forward response
        let (response, resp_leftover) = http::read_response(&mut upstream).await?;
        client
            .write_all(&response.head_bytes)
            .await
            .context("forwarding response headers")?;

        if let Some(len) = response.content_length {
            http::forward_body_content_length(&mut upstream, &mut client, len, &resp_leftover)
                .await
                .context("forwarding response body")?;
        } else if response.chunked {
            http::forward_chunked_body(&mut upstream, &mut client, &resp_leftover)
                .await
                .context("forwarding chunked response body")?;
        } else {
            // No content-length, no chunked — body ends at connection close.
            // That is inherently incompatible with keep-alive, so drain
            // (bounded) and return.
            http::forward_until_eof(
                &mut upstream,
                &mut client,
                &resp_leftover,
                MAX_CLOSE_DELIMITED_RESPONSE,
            )
            .await
            .context("forwarding close-delimited response")?;
            return Ok(());
        }

        client.flush().await?;

        if request.connection_close {
            return Ok(());
        }
        // Otherwise loop back and read the next request on this connection.
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
