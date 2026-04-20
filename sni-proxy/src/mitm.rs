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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::ca::CertificateAuthority;
use crate::connector::UpstreamConnector;
use crate::http;
use crate::network_policy::{render_inject_value, NetworkPolicy};
use crate::policy::{RequestPolicy, Verdict};
use crate::proxy::{get_original_dst, read_sni_with_buffer};

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
}

/// Run the MITM proxy accept loop.
pub async fn run<P, C>(listener: TcpListener, config: Arc<MitmConfig<P, C>>) -> Result<()>
where
    P: RequestPolicy + 'static,
    C: UpstreamConnector + 'static,
{
    loop {
        let (stream, addr) = listener.accept().await?;
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            info!(%addr, "mitm: accepted connection");
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

    // Step 1: Read ClientHello, extract SNI
    let (hostname, client_hello_buf) = read_sni_with_buffer(&mut client_tcp).await?;

    let hostname = match hostname {
        Some(h) => h,
        None => {
            warn!(%client_addr, "mitm: no SNI in ClientHello, dropping");
            return Ok(());
        }
    };

    // Step 2: Hostname-level policy check
    if config.policy.check(&hostname) == Verdict::Deny {
        warn!(%client_addr, %hostname, "mitm: hostname denied by policy");
        return Ok(());
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

    info!(%client_addr, %hostname, "mitm: TLS established with client");

    // Step 4-7: HTTP request/response loop (keep-alive)
    loop {
        // Read HTTP request from the decrypted client stream
        let mut request = match http::read_request(&mut client_tls).await {
            Ok(Some(req)) => req,
            Ok(None) => {
                debug!(%client_addr, "mitm: client closed connection");
                return Ok(());
            }
            Err(e) => {
                debug!(%client_addr, error = %e, "mitm: error reading request");
                return Ok(());
            }
        };

        info!(
            %client_addr, %hostname,
            method = %request.method, path = %request.path,
            "mitm: request"
        );

        // Check request-level policy
        if config.policy.check_request(&hostname, &request.path, &request.method) == Verdict::Deny {
            warn!(
                %client_addr, %hostname,
                method = %request.method, path = %request.path,
                "mitm: request denied by policy"
            );
            http::write_403(&mut client_tls, "blocked by hermit policy").await?;
            return Ok(());
        }

        // Credential injection (if a network policy is configured)
        if let Some(np) = &config.network_policy {
            apply_injection(np, &hostname, &mut request).await;
        }

        // Connect upstream with real TLS
        let upstream_tcp = config
            .connector
            .connect(&hostname, config.upstream_port, original_dst)
            .await
            .context("connecting upstream")?;

        let mut upstream_tls = connect_upstream_tls(upstream_tcp, &hostname).await?;

        // Forward request headers to upstream
        upstream_tls
            .write_all(&request.head_bytes)
            .await
            .context("forwarding request headers")?;

        // Forward request body if present
        if let Some(len) = request.content_length {
            // The head_bytes parsing may have consumed some body bytes.
            // For simplicity, we stream them from the client directly.
            http::forward_body_content_length(&mut client_tls, &mut upstream_tls, len, &[])
                .await
                .context("forwarding request body")?;
        }

        upstream_tls.flush().await?;

        // Read upstream response
        let (response, leftover) = http::read_response(&mut upstream_tls).await?;

        // Forward response headers to client
        client_tls
            .write_all(&response.head_bytes)
            .await
            .context("forwarding response headers")?;

        // Forward response body
        if let Some(len) = response.content_length {
            http::forward_body_content_length(&mut upstream_tls, &mut client_tls, len, &leftover)
                .await
                .context("forwarding response body")?;
        } else if response.chunked {
            // For chunked, just splice the remaining streams
            copy_bidirectional(&mut upstream_tls, &mut client_tls)
                .await
                .context("chunked body relay")?;
            return Ok(());
        } else {
            // No content-length, no chunked — read until close
            // Write leftover first
            if !leftover.is_empty() {
                client_tls.write_all(&leftover).await?;
            }
            let mut buf = [0u8; 8192];
            loop {
                let n = upstream_tls.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client_tls.write_all(&buf[..n]).await?;
            }
            return Ok(());
        }

        client_tls.flush().await?;

        // For keep-alive, loop back to read the next request.
        // (If the response indicated Connection: close, the client
        // will close and read_request will return None next iteration.)
    }
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
    let host = host_raw.split(':').next().unwrap_or(host_raw);
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
}
