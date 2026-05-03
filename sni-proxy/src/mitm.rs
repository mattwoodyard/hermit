//! TLS-terminate + L7-filter engine — the **MITM** half of the matrix.
//!
//! Two callers, one engine:
//!
//! * [`crate::transparent`] — for `mechanism = "mitm"` rules. The
//!   listener has already read the ClientHello to extract SNI,
//!   so it passes the buffered bytes plus the SNI hostname here
//!   for replay and certificate minting.
//! * [`crate::forward`] — for `HTTPS_PROXY` clients after the
//!   `200 Connection Established` response. The listener
//!   doesn't peek SNI itself; today it dispatches via
//!   [`crate::transparent::handle_stream`] which performs the
//!   SNI peek + mechanism check, then ends up here for MITM-
//!   mechanism rules.
//!
//! What this engine does:
//! 1. Mint a per-host leaf certificate from `config.ca`.
//! 2. Build a rustls `ServerConfig` that resolves to that cert.
//! 3. TLS-accept the client, replaying the buffered ClientHello.
//! 4. Read each HTTP request from the decrypted client stream.
//! 5. Run the request-level policy check (`path_prefix`,
//!    `methods`, etc.). Block + log on deny.
//! 6. Apply credential injection if a network policy is wired in.
//! 7. Connect upstream TCP + TLS, forward request + body.
//! 8. Read upstream response, forward back to the client.
//! 9. Loop until either side signals close.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::ca::CertificateAuthority;
use crate::connector::UpstreamConnector;
use crate::http;
use crate::network_policy::{render_inject_value, NetworkPolicy};
use crate::policy::{RequestPolicy, Verdict};
use crate::timeouts::{HEADER_READ_TIMEOUT, UPSTREAM_CONNECT_TIMEOUT, UPSTREAM_TLS_TIMEOUT};

/// Hard cap on close-delimited response body size — see forward.rs.
const MAX_CLOSE_DELIMITED_RESPONSE: u64 = 512 * 1024 * 1024;

/// Configuration shared by the MITM engine and the transparent
/// listener. Both refer to the same `Arc<MitmConfig>` so the CA,
/// loggers, policy, and connector are guaranteed to match.
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
    /// Root certs the MITM engine trusts when verifying the upstream
    /// server's certificate. `None` (production default) uses
    /// `webpki_roots::TLS_SERVER_ROOTS`. End-to-end tests stand up a
    /// fake HTTPS upstream signed by a test CA and pass that CA in
    /// here so the MITM engine accepts the synthetic chain.
    ///
    /// Setting this to a custom root store does NOT disable
    /// verification — it just changes the trust anchor. To trust a
    /// specific test cert, callers add it to a `RootCertStore` and
    /// pass that store. There is intentionally no "trust any cert"
    /// option.
    pub upstream_roots: Option<Arc<rustls::RootCertStore>>,
}

/// Run the MITM engine on a single TCP connection.
///
/// `client_hello_buf` is the buffered first slice of the
/// client's TLS handshake (the listener has already read it to
/// extract SNI). It's replayed via [`PrefixedStream`] so the
/// downstream rustls `Acceptor` sees a complete handshake.
///
/// `original_dst` is a port hint for the upstream dial. The
/// transparent path passes the pre-DNAT destination; the
/// forward path passes a synthetic `Some((_, port))` carrying
/// the `CONNECT` target's port; `None` falls back to
/// `config.upstream_port`.
pub async fn run<P, C>(
    client_tcp: TcpStream,
    client_addr: SocketAddr,
    original_dst: Option<SocketAddr>,
    hostname: &str,
    client_hello_buf: Vec<u8>,
    config: &MitmConfig<P, C>,
) -> Result<()>
where
    P: RequestPolicy,
    C: UpstreamConnector,
{
    // Step 1: mint a per-host leaf cert.
    let certified_key = config
        .ca
        .cert_for_host(hostname)
        .context("generating cert for host")?;

    let server_config = build_server_config(certified_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Step 2: TLS-accept with the buffered ClientHello replayed
    // first so the rustls handshake state machine sees a
    // complete record stream.
    let prefixed = PrefixedStream::new(client_hello_buf, client_tcp);
    let mut client_tls = acceptor
        .accept(prefixed)
        .await
        .context("TLS handshake with client")?;

    debug!(%client_addr, %hostname, "mitm: TLS established with client");

    // Step 3+: HTTP request/response loop (keep-alive).
    loop {
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

        // SNI/Host cross-check. Without this, a client could
        // present a permissive SNI (passing the access-control
        // rule for `hostname`) and then send a different `Host:`
        // header on the inner HTTP request — `apply_injection`
        // and any future header-keyed logic match on the Host
        // header, opening a domain-fronting / rule-mismatch gap
        // between the access decision and the credential decision.
        // Reject the mismatch outright with 421.
        if !host_matches_sni(request.host.as_deref(), hostname) {
            let host_header = request.host.as_deref().unwrap_or("(missing)");
            warn!(
                %client_addr, sni = %hostname, host_header = %host_header,
                "mitm: rejecting request — Host header does not match SNI"
            );
            config.block_log.log(BlockEvent {
                time_unix_ms: now_unix_ms(),
                kind: BlockKind::Https,
                client: Some(client_addr.to_string()),
                hostname: Some(hostname.to_string()),
                method: Some(request.method.clone()),
                path: Some(request.path.clone()),
                port: None,
                reason: Some(format!(
                    "Host/SNI mismatch (sni={hostname}, host={host_header})"
                )),
            });
            http::write_421(&mut client_tls, "Host header does not match SNI").await?;
            return Ok(());
        }

        // Request-level policy check.
        if config.policy.check_request(hostname, &request.path, &request.method) == Verdict::Deny {
            debug!(
                %client_addr, %hostname,
                method = %request.method, path = %request.path,
                "hermit blocked: HTTPS request {} https://{}{}",
                request.method, hostname, request.path
            );
            config.block_log.log(BlockEvent {
                time_unix_ms: now_unix_ms(),
                kind: BlockKind::Https,
                client: Some(client_addr.to_string()),
                hostname: Some(hostname.to_string()),
                method: Some(request.method.clone()),
                path: Some(request.path.clone()),
                port: None,
                reason: Some("blocked by access rules".to_string()),
            });
            http::write_403(&mut client_tls, "blocked by hermit policy").await?;
            return Ok(());
        }
        // Allowed — record one access event per HTTP exchange.
        config.access_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Https,
            client: Some(client_addr.to_string()),
            hostname: Some(hostname.to_string()),
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
            port: None,
            reason: None,
        });

        // Credential injection if a network policy is configured.
        // Capture which credential (if any) we injected so we can
        // invalidate it on a 401 — the next request through this
        // rule will then re-run the source and get a fresh token
        // instead of replaying the stale one.
        let injected_credential: Option<String> = match &config.network_policy {
            Some(np) => apply_injection(np, hostname, &mut request).await,
            None => None,
        };

        // Connect upstream TCP, then real TLS handshake.
        let upstream_tcp = match timeout(
            UPSTREAM_CONNECT_TIMEOUT,
            config
                .connector
                .connect(hostname, config.upstream_port, original_dst),
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
            connect_upstream_tls(upstream_tcp, hostname, config.upstream_roots.as_ref()),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                warn!(%hostname, "mitm: upstream TLS handshake timed out");
                return Ok(());
            }
        };

        // Forward request headers + body.
        upstream_tls
            .write_all(&request.head_bytes)
            .await
            .context("forwarding request headers")?;

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

        // OAuth-style cache invalidation: when the upstream
        // returns 401 Unauthorized AND we injected a credential
        // on this request, the cached token is probably stale.
        // Drop it so the *next* request through this rule
        // re-runs the credential source. We don't retry the
        // current request — that'd require buffering its body
        // for replay, and the simple invalidate-and-let-the-
        // next-request-fix-it flow is enough for the typical
        // refresh-token loop.
        if response.status == 401 {
            if let (Some(np), Some(cred)) = (&config.network_policy, &injected_credential) {
                tracing::info!(
                    %hostname, credential = %cred,
                    "mitm: upstream 401 — invalidating cached credential"
                );
                np.invalidate(cred);
            }
        }

        // Forward response headers + body.
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
            // No content-length, no chunked — body ends at connection
            // close, which is incompatible with keep-alive: drain
            // (bounded) and return.
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

/// Build a rustls `ServerConfig` for the MITM handshake with the client.
pub(crate) fn build_server_config(
    certified_key: Arc<rustls::sign::CertifiedKey>,
) -> Result<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("setting protocol versions")?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(StaticCertResolver(certified_key)));

    // Force HTTP/1.1 ALPN — we don't support HTTP/2 MITM.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

/// A cert resolver that always returns the same `CertifiedKey`.
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
///
/// `roots` overrides the default webpki trust anchors when set —
/// production callers leave it `None` so the standard root list is
/// used; tests pass a `RootCertStore` containing their fake CA.
async fn connect_upstream_tls(
    tcp: TcpStream,
    hostname: &str,
    roots: Option<&Arc<rustls::RootCertStore>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let root_store = match roots {
        Some(custom) => Arc::clone(custom),
        None => {
            let mut rs = rustls::RootCertStore::empty();
            rs.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(rs)
        }
    };

    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("setting protocol versions")?
    .with_root_certificates(Arc::unwrap_or_clone(root_store))
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
/// underlying stream. Used to replay the ClientHello the listener
/// already consumed when peeking SNI.
pub(crate) struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
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

        // Drain the prefix buffer first.
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.offset += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Then read from the underlying stream.
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

// PrefixedStream needs AsyncWrite too (TLS handshake writes back to client).
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
/// `request.head_bytes`. Returns the **credential name** that was
/// injected — the caller passes this to
/// [`NetworkPolicy::invalidate`](crate::network_policy::NetworkPolicy::invalidate)
/// when the upstream response carries a 401, so the next request
/// re-runs the credential source instead of replaying a stale token.
///
/// Returns `None` when no rule matched, the credential could not be
/// acquired, or the rule has no inject actions — in those cases the
/// request is forwarded unmodified and there's nothing to invalidate.
///
/// Failures (bad URI, credential acquisition error, header edit error)
/// log a warning and leave the request unmodified — access control is
/// handled upstream, so a missing credential must never hide a request.
pub async fn apply_injection(
    np: &NetworkPolicy,
    hostname: &str,
    request: &mut http::Request,
) -> Option<String> {
    let req_for_match = build_match_request(request, hostname)?;
    let rule = np.resolve(&req_for_match)?;
    let value = match np.acquire(rule, Some(hostname)).await {
        Ok(v) => v,
        Err(e) => {
            warn!(%hostname, credential = %rule.credential, error = %e,
                "credential acquisition failed; forwarding without injection");
            return None;
        }
    };
    let actions = np.inject_actions(rule)?;
    let mut any_set = false;
    for action in actions {
        let rendered = render_inject_value(&action.value, &value);
        match http::set_header(&mut request.head_bytes, &action.header, &rendered) {
            Ok(()) => any_set = true,
            Err(e) => {
                warn!(%hostname, header = %action.header, error = %e,
                    "failed to set injected header; continuing");
            }
        }
    }
    if any_set {
        info!(%hostname, credential = %rule.credential, "injected credential");
        Some(rule.credential.clone())
    } else {
        None
    }
}

/// Compare the inner request's `Host:` header against the SNI
/// hostname the TLS connection was minted for. Returns true if
/// they refer to the same authority, false otherwise.
///
/// Rules:
/// - A missing Host header is treated as **mismatch**. HTTP/1.1
///   requires Host, and a request without one shouldn't reach
///   the MITM engine at all; rejecting is the conservative call.
/// - The Host header may carry a port (`example.com:8443`); we
///   strip it before comparing.
/// - Comparison is case-insensitive (DNS is case-insensitive,
///   and clients commonly send mixed-case Host).
/// - We deliberately do NOT compare against `request.path`'s
///   absolute-form authority (RFC 7230 §5.3.2) — that's a proxy
///   form the MITM never sees from a TLS-terminated client.
pub(crate) fn host_matches_sni(host_header: Option<&str>, sni: &str) -> bool {
    let host = match host_header {
        Some(h) => http::host_without_port(h),
        None => return false,
    };
    host.eq_ignore_ascii_case(sni)
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

#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use super::{build_server_config, host_matches_sni, PrefixedStream, StaticCertResolver};
    use anyhow::Result;
    use rustls::sign::CertifiedKey;
    use rustls::ServerConfig;
    use std::sync::Arc;
    use tokio::io::AsyncRead;

    pub fn build_server_config_for_test(ck: Arc<CertifiedKey>) -> Result<ServerConfig> {
        build_server_config(ck)
    }

    pub fn host_matches_sni_for_test(host_header: Option<&str>, sni: &str) -> bool {
        host_matches_sni(host_header, sni)
    }

    /// Wrap `inner` in a `PrefixedStream` that replays `prefix` first.
    /// Returns `impl AsyncRead + Unpin` so callers don't need to name
    /// the generic; a `'static` bound on `S` keeps the returned stream
    /// usable across `await` points without extra lifetimes.
    pub fn prefixed_stream<S>(prefix: Vec<u8>, inner: S) -> impl AsyncRead + Unpin + 'static
    where
        S: AsyncRead + Unpin + 'static,
    {
        PrefixedStream::new(prefix, inner)
    }

    /// Construct a `StaticCertResolver` and immediately drop it —
    /// exercises that the type's constructor is reachable for the
    /// `static_cert_resolver_returns_cert` test which only needs to
    /// witness that the type exists.
    pub fn touch_static_cert_resolver(ck: Arc<CertifiedKey>) {
        let _ = StaticCertResolver(ck);
    }
}
