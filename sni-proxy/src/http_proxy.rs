//! Plain HTTP proxy for port 80 traffic.
//!
//! Accepts TCP connections, parses the HTTP request to extract Host header,
//! path, and method, checks the request-level policy, then connects
//! upstream and relays the request/response.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, trace, warn, Instrument};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::connector::UpstreamConnector;
use crate::http;
use crate::policy::{RequestPolicy, Verdict};
use crate::proxy::{get_original_dst, MAX_CONCURRENT_CONNECTIONS};

/// Connection counter used to tag every span with a fresh
/// `conn_id`. Lets an operator chasing a single request grep
/// `conn=1234` and see only that conversation's events even
/// when many requests are interleaved.
static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_conn_id() -> u64 {
    CONN_COUNTER.fetch_add(1, Ordering::Relaxed)
}

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
    /// Ports a `CONNECT` tunnel is permitted to target. Always
    /// includes 443 plus any `[[port_forward]]` entries with
    /// `protocol = "https"`. CONNECT to any other port is denied
    /// even when the host is allow-listed — otherwise an
    /// allow-listed hostname becomes a generic egress to arbitrary
    /// ports (SSH/etc.) on that hostname's IP.
    pub allowed_connect_ports: BTreeSet<u16>,
    /// Where to record block events. `BlockLogger::disabled()` by default.
    pub block_log: BlockLogger,
    /// Where to record *allowed* access events (learn-mode trace).
    /// `BlockLogger::disabled()` outside of `hermit learn`.
    pub access_log: BlockLogger,
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
        // Closed semaphore means accept a connection-drop rather than
        // taking out the whole listener.
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "http: connection semaphore closed; dropping connection");
            continue;
        };
        let config = Arc::clone(&config);

        let conn_id = next_conn_id();
        let span = tracing::trace_span!("http_conn", conn = conn_id, peer = %addr);
        tokio::spawn(
            async move {
                let _permit = permit; // released on task end
                debug!(%addr, "http: accepted connection");
                if let Err(e) = handle_connection(stream, addr, &config).await {
                    debug!(%addr, error = %e, "http: connection ended");
                }
                trace!("http_conn closed");
            }
            .instrument(span),
        );
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
    trace!(
        original_dst = ?original_dst,
        "http: SO_ORIGINAL_DST lookup (None in proxy mode without DNAT)"
    );
    loop {
        trace!("http: awaiting request head");
        let (request, leftover) = match timeout(
            HEADER_READ_TIMEOUT,
            http::read_request(&mut client),
        )
        .await
        {
            Ok(Ok(Some(pair))) => pair,
            Ok(Ok(None)) => {
                trace!("http: client closed cleanly before sending a request");
                return Ok(());
            }
            Ok(Err(e)) => {
                debug!(%client_addr, error = %e, "http: error reading request");
                return Ok(());
            }
            Err(_) => {
                debug!(%client_addr, "http: header read timed out");
                return Ok(());
            }
        };
        trace!(
            method = %request.method,
            path = %request.path,
            host = ?request.host,
            content_length = ?request.content_length,
            chunked = request.chunked,
            connection_close = request.connection_close,
            head_bytes = request.head_bytes.len(),
            leftover = leftover.len(),
            "http: request parsed"
        );

        // Proxy-aware clients send CONNECT when HTTPS_PROXY is set. We
        // terminate the CONNECT here, splice to the named upstream, and
        // return — the client then speaks TLS straight to the origin
        // through the tunnel. No HTTP inspection past this point.
        if request.method.eq_ignore_ascii_case("CONNECT") {
            trace!("http: dispatching to handle_connect");
            return handle_connect(client, client_addr, request, config).await;
        }

        let hostname = match &request.host {
            Some(h) => http::host_without_port(h).to_string(),
            None => {
                debug!(%client_addr, "hermit blocked: HTTP request without Host header");
                config.block_log.log(BlockEvent {
                    time_unix_ms: now_unix_ms(),
                    kind: BlockKind::HttpNoHost,
                    client: Some(client_addr.to_string()),
                    hostname: None,
                    method: Some(request.method.clone()),
                    path: Some(request.path.clone()),
                    port: None,
                    reason: Some("HTTP request without Host header".to_string()),
                });
                return Ok(());
            }
        };
        trace!(%hostname, "http: derived hostname for policy check");

        debug!(
            %client_addr, %hostname,
            method = %request.method, path = %request.path,
            "http: request"
        );

        // Check request-level policy
        let verdict = config.policy.check_request(&hostname, &request.path, &request.method);
        trace!(?verdict, %hostname, path = %request.path, method = %request.method, "http: policy verdict");
        if verdict == Verdict::Deny {
            debug!(
                %client_addr, %hostname,
                method = %request.method, path = %request.path,
                "hermit blocked: HTTP request {} http://{}{}", request.method, hostname, request.path
            );
            config.block_log.log(BlockEvent {
                time_unix_ms: now_unix_ms(),
                kind: BlockKind::Http,
                client: Some(client_addr.to_string()),
                hostname: Some(hostname.clone()),
                method: Some(request.method.clone()),
                path: Some(request.path.clone()),
                port: None,
                reason: Some("blocked by access rules".to_string()),
            });
            http::write_403(&mut client, "blocked by hermit policy").await?;
            return Ok(());
        }
        // Allowed: record the request for learn-mode trace.
        config.access_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(client_addr.to_string()),
            hostname: Some(hostname.clone()),
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
            port: None,
            reason: None,
        });

        let upstream_port = original_dst.map(|a| a.port()).unwrap_or(config.upstream_port);
        trace!(%hostname, upstream_port, "http: dialing upstream");
        let mut upstream = match timeout(
            UPSTREAM_CONNECT_TIMEOUT,
            config
                .connector
                .connect(&hostname, config.upstream_port, original_dst),
        )
        .await
        {
            Ok(Ok(s)) => {
                trace!(%hostname, upstream_port, "http: upstream connected");
                s
            }
            Ok(Err(e)) => {
                trace!(%hostname, upstream_port, error = %e, "http: upstream connect failed");
                return Err(e).context("connecting upstream");
            }
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
            trace!(len, "http: forwarding request body (Content-Length)");
            http::forward_body_content_length(&mut client, &mut upstream, len, &leftover)
                .await
                .context("forwarding request body")?;
        } else if request.chunked {
            trace!("http: forwarding request body (chunked)");
            http::forward_chunked_body(&mut client, &mut upstream, &leftover)
                .await
                .context("forwarding chunked request body")?;
        } else if !leftover.is_empty() {
            // Non-standard: no length, no chunked, but extra bytes buffered.
            // Safest is to forward what we've got.
            trace!(leftover = leftover.len(), "http: forwarding leftover bytes (no body framing)");
            upstream.write_all(&leftover).await?;
        }
        upstream.flush().await?;

        // Read and forward response
        trace!("http: awaiting response head");
        let (response, resp_leftover) = http::read_response(&mut upstream).await?;
        trace!(
            content_length = ?response.content_length,
            chunked = response.chunked,
            head_bytes = response.head_bytes.len(),
            "http: response head parsed"
        );
        client
            .write_all(&response.head_bytes)
            .await
            .context("forwarding response headers")?;

        if let Some(len) = response.content_length {
            trace!(len, "http: forwarding response body (Content-Length)");
            http::forward_body_content_length(&mut upstream, &mut client, len, &resp_leftover)
                .await
                .context("forwarding response body")?;
        } else if response.chunked {
            trace!("http: forwarding response body (chunked)");
            http::forward_chunked_body(&mut upstream, &mut client, &resp_leftover)
                .await
                .context("forwarding chunked response body")?;
        } else {
            // No content-length, no chunked — body ends at connection close.
            // That is inherently incompatible with keep-alive, so drain
            // (bounded) and return.
            trace!("http: forwarding close-delimited response (until EOF)");
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
            trace!("http: client requested Connection: close, ending");
            return Ok(());
        }
        trace!("http: keep-alive, awaiting next request");
        // Otherwise loop back and read the next request on this connection.
    }
}

/// Handle a CONNECT tunnel request. Arrives when a client has
/// `HTTPS_PROXY=http://127.0.0.1:<our-port>` set — the client opens a
/// TCP session to us and asks us to splice bytes to `host:port`.
///
/// We only inspect the target host against hostname-level policy; once
/// the tunnel is open the payload is (by design) opaque TLS. Deeper
/// filtering must route through the MITM proxy instead.
async fn handle_connect<P, C>(
    mut client: TcpStream,
    client_addr: SocketAddr,
    request: http::Request,
    config: &HttpProxyConfig<P, C>,
) -> Result<()>
where
    P: RequestPolicy,
    C: UpstreamConnector,
{
    let (host, port) = match parse_connect_target(&request.path) {
        Some(v) => v,
        None => {
            debug!(%client_addr, target = %request.path, "http: malformed CONNECT target");
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return Ok(());
        }
    };
    trace!(%host, port, raw_target = %request.path, "http: parsed CONNECT target");

    debug!(%client_addr, %host, %port, "http: CONNECT");

    trace!(
        port,
        allowed = ?config.allowed_connect_ports,
        "http: checking CONNECT port against allowlist"
    );
    // Port-allowlist check happens *before* the hostname check: an
    // allow-listed host on a non-HTTPS port (e.g. ssh on 22) must
    // be denied. Otherwise a malicious build could exfiltrate via
    // ssh/smtp/etc. to whatever hostname the policy permits.
    if !config.allowed_connect_ports.contains(&port) {
        debug!(
            %client_addr, %host, %port,
            "hermit blocked: CONNECT to disallowed port"
        );
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(client_addr.to_string()),
            hostname: Some(host.clone()),
            method: Some("CONNECT".to_string()),
            path: Some(request.path.clone()),
            port: None,
            reason: Some(format!(
                "CONNECT to port {port} is not in the HTTPS port allowlist"
            )),
        });
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await;
        return Ok(());
    }

    let conn_verdict = config.policy.check(&host);
    trace!(?conn_verdict, %host, "http: CONNECT host policy verdict");
    if conn_verdict == Verdict::Deny {
        debug!(%client_addr, %host, "hermit blocked: CONNECT to {}:{}", host, port);
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(client_addr.to_string()),
            hostname: Some(host.clone()),
            method: Some("CONNECT".to_string()),
            path: Some(request.path.clone()),
            port: None,
            reason: Some("blocked by access rules".to_string()),
        });
        // 403 over a CONNECT attempt is what curl/requests expect — the
        // tunnel is never established and the client surfaces a clear
        // "proxy rejected" error rather than a confusing TCP reset.
        let _ = client
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await;
        return Ok(());
    }
    // Allowed CONNECT: record the tunnel target for learn-mode
    // trace. We don't see anything inside the tunnel after this
    // point — the only cleartext signal is the host:port.
    config.access_log.log(BlockEvent {
        time_unix_ms: now_unix_ms(),
        kind: BlockKind::Http,
        client: Some(client_addr.to_string()),
        hostname: Some(host.clone()),
        method: Some("CONNECT".to_string()),
        path: Some(request.path.clone()),
        port: None,
        reason: None,
    });

    trace!(%host, port, "http: CONNECT dialing upstream");
    let mut upstream = match timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        config.connector.connect(&host, port, None),
    )
    .await
    {
        Ok(Ok(s)) => {
            trace!(%host, port, "http: CONNECT upstream connected");
            s
        }
        Ok(Err(e)) => {
            warn!(%host, port, error = %e, "http: CONNECT upstream failed");
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await;
            return Ok(());
        }
        Err(_) => {
            warn!(%host, port, "http: CONNECT upstream timed out");
            let _ = client
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("writing CONNECT 200")?;
    trace!("http: CONNECT 200 sent, starting bidirectional splice");

    // Splice bidirectionally. copy_bidirectional returns when either
    // side closes, which is the expected termination for a tunnel.
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((c2u, u2c)) => trace!(
            client_to_upstream = c2u,
            upstream_to_client = u2c,
            "http: CONNECT splice closed"
        ),
        Err(e) => trace!(error = %e, "http: CONNECT splice errored"),
    }
    Ok(())
}

/// Parse the `host:port` authority-form target from a CONNECT request
/// line. Accepts bracketed IPv6 (`[::1]:443`) and bare IPv4/hostname.
/// Returns `None` on any structural issue so the caller can surface a
/// 400 rather than panicking.
fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    // CONNECT must always carry an explicit port (RFC 7230 §5.3.3).
    // A bracketed IPv6 authority puts the port *after* the ']'.
    if let Some(rest) = target.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port_part = rest[end + 1..].strip_prefix(':')?;
        let port = port_part.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port = port.parse().ok()?;
    Some((host.to_string(), port))
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
            allowed_connect_ports: BTreeSet::from([443]),
            block_log: crate::block_log::BlockLogger::disabled(),
            access_log: crate::block_log::BlockLogger::disabled(),
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
            allowed_connect_ports: BTreeSet::from([443]),
            block_log: crate::block_log::BlockLogger::disabled(),
            access_log: crate::block_log::BlockLogger::disabled(),
        };
        assert_eq!(config.upstream_port, 80);
    }

    #[test]
    fn connect_target_parses_host_port() {
        assert_eq!(
            parse_connect_target("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn connect_target_parses_ipv4() {
        assert_eq!(
            parse_connect_target("10.0.0.1:8443"),
            Some(("10.0.0.1".to_string(), 8443))
        );
    }

    #[test]
    fn connect_target_parses_ipv6() {
        assert_eq!(
            parse_connect_target("[::1]:443"),
            Some(("::1".to_string(), 443))
        );
    }

    #[test]
    fn connect_target_rejects_missing_port() {
        // CONNECT authorities must carry a port. Tolerating a bare
        // hostname here would let a proxy-unaware client tunnel to an
        // ambiguous destination.
        assert_eq!(parse_connect_target("example.com"), None);
    }

    #[test]
    fn connect_target_rejects_empty_host() {
        assert_eq!(parse_connect_target(":443"), None);
    }

    #[test]
    fn connect_target_rejects_non_numeric_port() {
        assert_eq!(parse_connect_target("example.com:abc"), None);
    }

    #[test]
    fn connect_target_rejects_unterminated_ipv6() {
        assert_eq!(parse_connect_target("[::1:443"), None);
    }
}
