//! MITM proxy: terminates client TLS, inspects HTTP, connects upstream.
//!
//! Flow per connection:
//! 1. Read ClientHello, extract SNI hostname
//! 2. Check hostname-level policy — drop if denied
//! 3. TLS-accept with per-host cert from CA
//! 4. Read HTTP request, check request-level policy
//! 5. Connect upstream with real TLS, forward request + body
//! 6. Read upstream response, forward to client
//! 7. Loop for keep-alive

use anyhow::{Context, Result};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::ca::CertificateAuthority;
use crate::connector::UpstreamConnector;
use crate::http;
use crate::network_policy::{render_inject_value, NetworkPolicy};
use crate::policy::{Mechanism, RequestPolicy, Verdict};
use crate::proxy::{get_original_dst, read_sni_with_buffer, MAX_CONCURRENT_CONNECTIONS};

/// Max time to wait for the TLS ClientHello from the client.
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// Max time to wait for a full HTTP request head on an idle keep-alive
/// connection.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Max time for the upstream TCP connect (not the TLS handshake).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Max time for the upstream TLS handshake.
const UPSTREAM_TLS_TIMEOUT: Duration = Duration::from_secs(15);
/// Hard cap on close-delimited response body size. See http_proxy.rs.
const MAX_CLOSE_DELIMITED_RESPONSE: u64 = 512 * 1024 * 1024;

/// Configuration for the MITM proxy.
pub struct MitmConfig<P, C> {
    pub policy: Arc<P>,
    pub connector: Arc<C>,
    pub ca: Arc<CertificateAuthority>,
    pub upstream_port: u16,
    /// Optional credential-injection policy. When set, each request is
    /// matched against its rules and the first matching rule's credential
    /// is acquired and injected as configured headers.
    pub network_policy: Option<Arc<NetworkPolicy>>,
    /// Where to record block events. `BlockLogger::disabled()` by default.
    pub block_log: BlockLogger,
    /// Where to record *allowed* access events (learn-mode trace).
    /// `BlockLogger::disabled()` outside of `hermit learn`. Same
    /// writer machinery as `block_log`; semantic distinction is by
    /// the file path the writer is pointed at.
    pub access_log: BlockLogger,
}

/// Run the MITM proxy accept loop.
pub async fn run<P, C>(listener: TcpListener, config: Arc<MitmConfig<P, C>>) -> Result<()>
where
    P: RequestPolicy + 'static,
    C: UpstreamConnector + 'static,
{
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // EMFILE / ECONNABORTED etc. must not kill the listener.
                warn!(error = %e, "mitm: accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "mitm: connection semaphore closed; dropping connection");
            continue;
        };
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            let _permit = permit;
            debug!(%addr, "mitm: accepted connection");
            if let Err(e) = handle_connection(stream, addr, &config).await {
                // Connection resets and clean closes are noisy at error level
                debug!(%addr, error = %e, "mitm: connection ended");
            }
        });
    }
}

/// Handle a single MITM connection.
async fn handle_connection<P, C>(
    mut client_tcp: TcpStream,
    client_addr: SocketAddr,
    config: &MitmConfig<P, C>,
) -> Result<()>
where
    P: RequestPolicy,
    C: UpstreamConnector,
{
    let original_dst = get_original_dst(&client_tcp);

    // Step 1: Read ClientHello, extract SNI (with a timeout — a client that
    // opens a socket and never sends must not park a tokio task forever).
    let (hostname, client_hello_buf) = match timeout(
        CLIENT_HELLO_TIMEOUT,
        read_sni_with_buffer(&mut client_tcp),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            debug!(%client_addr, "mitm: ClientHello read timed out");
            return Ok(());
        }
    };

    let hostname = match hostname {
        Some(h) => h,
        None => {
            debug!(%client_addr, "hermit blocked: TLS connection without SNI");
            config.block_log.log(BlockEvent {
                time_unix_ms: now_unix_ms(),
                kind: BlockKind::TlsNoSni,
                client: Some(client_addr.to_string()),
                hostname: None,
                method: None,
                path: None,
                reason: Some("TLS connection without SNI".to_string()),
            });
            return Ok(());
        }
    };

    // Step 2: Hostname-level policy check
    if config.policy.check(&hostname) == Verdict::Deny {
        debug!(%client_addr, %hostname, "hermit blocked: TLS hostname not in allowlist");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::TlsHostname,
            client: Some(client_addr.to_string()),
            hostname: Some(hostname.clone()),
            method: None,
            path: None,
            reason: Some("hostname not in allowlist".to_string()),
        });
        return Ok(());
    }
    // Allowed at the hostname level: record an access event so
    // `hermit learn` users see the SNI even if the connection
    // never produces an HTTP request (e.g. SNI cut-through path).
    config.access_log.log(BlockEvent {
        time_unix_ms: now_unix_ms(),
        kind: BlockKind::TlsHostname,
        client: Some(client_addr.to_string()),
        hostname: Some(hostname.clone()),
        method: None,
        path: None,
        reason: None,
    });

    // Step 2b: Mechanism dispatch. If the rule for this host is
    // `sni`, skip MITM entirely and splice raw bytes — certificate
    // pinning clients require this. `mitm` continues below.
    if config.policy.mechanism(&hostname) == Mechanism::Sni {
        return splice_sni_cut_through(
            client_tcp,
            &client_hello_buf,
            &hostname,
            original_dst,
            config,
        )
        .await;
    }

    // Step 3: TLS-accept with per-host cert
    let certified_key = config
        .ca
        .cert_for_host(&hostname)
        .context("generating cert for host")?;

    let server_config = build_server_config(certified_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // We need to replay the ClientHello that we already consumed.
    // Create a "prefixed" stream that first yields the buffered bytes,
    // then reads from the real socket.
    let prefixed = PrefixedStream::new(client_hello_buf, client_tcp);
    let mut client_tls = acceptor
        .accept(prefixed)
        .await
        .context("TLS handshake with client")?;

    debug!(%client_addr, %hostname, "mitm: TLS established with client");

    // Step 4-7: HTTP request/response loop (keep-alive)
    loop {
        // Read HTTP request from the decrypted client stream (with timeout).
        let (mut request, leftover) = match timeout(
            HEADER_READ_TIMEOUT,
            http::read_request(&mut client_tls),
        )
        .await
        {
            Ok(Ok(Some(pair))) => pair,
            Ok(Ok(None)) => {
                debug!(%client_addr, "mitm: client closed connection");
                return Ok(());
            }
            Ok(Err(e)) => {
                debug!(%client_addr, error = %e, "mitm: error reading request");
                return Ok(());
            }
            Err(_) => {
                debug!(%client_addr, "mitm: request header read timed out");
                return Ok(());
            }
        };

        debug!(
            %client_addr, %hostname,
            method = %request.method, path = %request.path,
            "mitm: request"
        );

        // Check request-level policy
        if config.policy.check_request(&hostname, &request.path, &request.method) == Verdict::Deny {
            debug!(
                %client_addr, %hostname,
                method = %request.method, path = %request.path,
                "hermit blocked: HTTPS request {} https://{}{}", request.method, hostname, request.path
            );
            config.block_log.log(BlockEvent {
                time_unix_ms: now_unix_ms(),
                kind: BlockKind::Https,
                client: Some(client_addr.to_string()),
                hostname: Some(hostname.clone()),
                method: Some(request.method.clone()),
                path: Some(request.path.clone()),
                reason: Some("blocked by access rules".to_string()),
            });
            http::write_403(&mut client_tls, "blocked by hermit policy").await?;
            return Ok(());
        }
        // Allowed: record the request for learn-mode trace.
        // Emitted once per request so a multi-request keep-alive
        // session yields one access event per HTTP exchange.
        config.access_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Https,
            client: Some(client_addr.to_string()),
            hostname: Some(hostname.clone()),
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
            reason: None,
        });

        // Credential injection (if a network policy is configured)
        if let Some(np) = &config.network_policy {
            apply_injection(np, &hostname, &mut request).await;
        }

        // Connect upstream TCP (with timeout) then run real TLS handshake.
        let upstream_tcp = match timeout(
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
                warn!(%hostname, "mitm: upstream connect timed out");
                return Ok(());
            }
        };

        let mut upstream_tls = match timeout(
            UPSTREAM_TLS_TIMEOUT,
            connect_upstream_tls(upstream_tcp, &hostname),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                warn!(%hostname, "mitm: upstream TLS handshake timed out");
                return Ok(());
            }
        };

        // Forward request headers to upstream
        upstream_tls
            .write_all(&request.head_bytes)
            .await
            .context("forwarding request headers")?;

        // Forward request body. `leftover` contains any body bytes that
        // arrived in the same read as the headers — they MUST go first.
        if let Some(len) = request.content_length {
            http::forward_body_content_length(&mut client_tls, &mut upstream_tls, len, &leftover)
                .await
                .context("forwarding request body")?;
        } else if request.chunked {
            http::forward_chunked_body(&mut client_tls, &mut upstream_tls, &leftover)
                .await
                .context("forwarding chunked request body")?;
        } else if !leftover.is_empty() {
            upstream_tls.write_all(&leftover).await?;
        }

        upstream_tls.flush().await?;

        // Read upstream response. A slow upstream that completes TLS but
        // dribbles response bytes must not park the task — bound this the
        // same way the request header read is bounded.
        let (response, resp_leftover) = match timeout(
            HEADER_READ_TIMEOUT,
            http::read_response(&mut upstream_tls),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                warn!(%hostname, "mitm: upstream response header read timed out");
                return Ok(());
            }
        };

        // Forward response headers to client
        client_tls
            .write_all(&response.head_bytes)
            .await
            .context("forwarding response headers")?;

        if let Some(len) = response.content_length {
            http::forward_body_content_length(
                &mut upstream_tls,
                &mut client_tls,
                len,
                &resp_leftover,
            )
            .await
            .context("forwarding response body")?;
        } else if response.chunked {
            http::forward_chunked_body(&mut upstream_tls, &mut client_tls, &resp_leftover)
                .await
                .context("forwarding chunked response body")?;
        } else {
            // No content-length, no chunked — body ends at connection close.
            // That is inherently incompatible with keep-alive: drain (bounded)
            // and return.
            http::forward_until_eof(
                &mut upstream_tls,
                &mut client_tls,
                &resp_leftover,
                MAX_CLOSE_DELIMITED_RESPONSE,
            )
            .await
            .context("forwarding close-delimited response")?;
            return Ok(());
        }

        client_tls.flush().await?;

        if request.connection_close {
            return Ok(());
        }
        // Otherwise loop back and read the next request on this connection.
    }
}

/// SNI cut-through: the ClientHello has already been buffered in
/// `client_hello`. We dial the real upstream, forward the buffered
/// bytes, and then splice bidirectionally. No TLS termination and no
/// HTTP inspection happens here — by design, since the whole point of
/// this mechanism is preserving the client↔origin wire for cert-pinned
/// clients.
///
/// Note: this runs on the MITM listener (the one `HTTPS_PORT` DNAT's
/// to). We intentionally reuse that listener rather than standing up
/// a separate port so the SNI/MITM choice is per-rule-per-connection
/// and requires no additional nft rules.
async fn splice_sni_cut_through<P, C>(
    mut client_tcp: TcpStream,
    client_hello: &[u8],
    hostname: &str,
    original_dst: Option<SocketAddr>,
    config: &MitmConfig<P, C>,
) -> Result<()>
where
    P: RequestPolicy,
    C: UpstreamConnector,
{
    debug!(%hostname, "mitm: sni cut-through");
    let mut upstream = match timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        config
            .connector
            .connect(hostname, config.upstream_port, original_dst),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(%hostname, error = %e, "mitm: sni cut-through upstream failed");
            return Ok(());
        }
        Err(_) => {
            warn!(%hostname, "mitm: sni cut-through upstream timed out");
            return Ok(());
        }
    };

    // Forward the buffered ClientHello verbatim so the client's TLS
    // handshake lands on the real upstream. If this write fails the
    // upstream already dropped us and there's nothing to salvage.
    upstream
        .write_all(client_hello)
        .await
        .context("forwarding buffered ClientHello to sni cut-through upstream")?;

    let _ = tokio::io::copy_bidirectional(&mut client_tcp, &mut upstream).await;
    Ok(())
}

/// Build a rustls ServerConfig for the MITM handshake with the client.
fn build_server_config(
    certified_key: Arc<rustls::sign::CertifiedKey>,
) -> Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("setting protocol versions")?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(StaticCertResolver(certified_key)));

    // Force HTTP/1.1 ALPN — we don't support HTTP/2 MITM
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

/// A cert resolver that always returns the same CertifiedKey.
#[derive(Debug)]
struct StaticCertResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for StaticCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Connect to upstream with real TLS, verifying the server's certificate.
async fn connect_upstream_tls(
    tcp: TcpStream,
    hostname: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut root_store = rustls::RootCertStore::empty();

    // Use webpki built-in roots. In production, you might want
    // rustls-native-certs, but this avoids an extra dependency.
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("setting protocol versions")?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .context("invalid server name")?;

    connector
        .connect(server_name, tcp)
        .await
        .context("upstream TLS handshake")
}

// ---------------------------------------------------------------------------
// PrefixedStream: replay buffered bytes then read from underlying stream
// ---------------------------------------------------------------------------

use std::io;
use std::pin::Pin;
use std::task::{self, Poll};

/// A stream that first yields pre-buffered bytes, then reads from the
/// underlying stream. Used to replay the ClientHello we already consumed.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // First drain the prefix buffer
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.offset += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Then read from the underlying stream
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

// PrefixedStream also needs AsyncWrite (TLS handshake writes back to client)
impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Match the request against the network policy and, if a rule matches,
/// acquire the credential and overwrite the configured headers in
/// `request.head_bytes`.
///
/// Failures (bad URI, credential acquisition error, header edit error)
/// log a warning and leave the request unmodified — access control is
/// handled upstream, so a missing credential must never hide a request.
pub async fn apply_injection(
    np: &NetworkPolicy,
    hostname: &str,
    request: &mut http::Request,
) {
    let req_for_match = match build_match_request(request, hostname) {
        Some(r) => r,
        None => return,
    };
    let rule = match np.resolve(&req_for_match) {
        Some(r) => r,
        None => return,
    };
    let value = match np.acquire(rule, Some(hostname)).await {
        Ok(v) => v,
        Err(e) => {
            warn!(%hostname, credential = %rule.credential, error = %e,
                "credential acquisition failed; forwarding without injection");
            return;
        }
    };
    let actions = match np.inject_actions(rule) {
        Some(a) => a,
        None => return,
    };
    for action in actions {
        let rendered = render_inject_value(&action.value, &value);
        if let Err(e) = http::set_header(&mut request.head_bytes, &action.header, &rendered) {
            warn!(%hostname, header = %action.header, error = %e,
                "failed to set injected header; continuing");
        }
    }
    info!(%hostname, credential = %rule.credential, "injected credential");
}

/// Build an `http::Request<()>` from our parsed request for DSL matching.
///
/// Scheme is hardcoded to `https` (MITM only sees HTTPS); host comes from
/// the `Host` header (port stripped); headers are re-parsed from head_bytes.
fn build_match_request(
    request: &http::Request,
    fallback_host: &str,
) -> Option<::http::Request<()>> {
    let host_raw = request.host.as_deref().unwrap_or(fallback_host);
    let host = http::host_without_port(host_raw);
    let uri = format!("https://{host}{}", request.path);

    let mut builder = ::http::Request::builder()
        .method(request.method.as_str())
        .uri(&uri);

    let mut header_buf = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut header_buf);
    parsed.parse(&request.head_bytes).ok()?;
    for h in parsed.headers.iter() {
        builder = builder.header(h.name, h.value);
    }
    builder.body(()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn static_cert_resolver_returns_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = CertificateAuthority::new().unwrap();
        let ck = ca.cert_for_host("example.com").unwrap();
        let _resolver = StaticCertResolver(ck.clone());

        // We can't easily construct a ClientHello for testing resolve(),
        // but we can verify the server config builds without error.
        let config = build_server_config(ck).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[tokio::test]
    async fn prefixed_stream_replays_then_reads() {
        let prefix = b"hello ".to_vec();
        let inner: &[u8] = b"world";
        let mut stream = PrefixedStream::new(prefix, inner);

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn prefixed_stream_empty_prefix() {
        let prefix = Vec::new();
        let inner: &[u8] = b"just inner";
        let mut stream = PrefixedStream::new(prefix, inner);

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"just inner");
    }

    #[tokio::test]
    async fn splice_sni_cut_through_forwards_hello_and_bytes() {
        // The whole point of the Sni mechanism is that the ClientHello
        // (which the MITM layer already consumed) must reach the real
        // upstream verbatim — otherwise TLS would have nothing to work
        // with. This test stands up a mock "upstream" TCP server,
        // hands splice_sni_cut_through an already-buffered ClientHello,
        // and asserts the upstream receives those bytes and its reply
        // flows back to the (fake) client.
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

        // Build a TcpStream pair to stand in for the post-ClientHello
        // client socket. We bind a second listener, connect to it,
        // and use the accepted half as the stream splice operates on.
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
            policy: Arc::new(crate::policy::AllowAll),
            connector: Arc::new(crate::connector::DirectConnector),
            ca,
            upstream_port,
            network_policy: None,
            block_log: crate::block_log::BlockLogger::disabled(),
            access_log: crate::block_log::BlockLogger::disabled(),
        };

        let hello = b"CLIENTHELLO".to_vec();

        // Drive splice and the client side concurrently: splice writes
        // hello to upstream, upstream writes "UP", splice relays "UP"
        // to client_side, upstream closes, splice tears down. Dropping
        // our client handle then unblocks the other half of the copy.
        let splice_done = tokio::spawn(async move {
            let _ = splice_sni_cut_through(
                server_side,
                &hello,
                "127.0.0.1",
                None,
                &config,
            )
            .await;
        });

        let mut resp = [0u8; 2];
        client_side.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"UP");

        // Close our side so copy_bidirectional can finish.
        drop(client_side);

        tokio::time::timeout(Duration::from_secs(2), splice_done)
            .await
            .expect("splice timed out")
            .unwrap();

        let received = upstream_task.await.unwrap();
        assert_eq!(&received, b"CLIENTHELLO");
    }
}
