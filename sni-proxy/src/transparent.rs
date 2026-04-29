//! Transparent intercept listener — the **transparent** column
//! of the matrix.
//!
//! Accepts TCP connections that arrived via DNAT (so `SO_ORIGINAL_DST`
//! recovers the pre-NAT destination), peeks the TLS ClientHello
//! to extract SNI, runs the hostname-level policy, and dispatches
//! based on the per-rule mechanism:
//!
//! * `mechanism = "mitm"` → [`crate::mitm::run`] — TLS terminated
//!   with the hermit CA, L7 filtering applied (`path_prefix`,
//!   `methods`), credentials injected if a network policy is wired
//!   in.
//! * `mechanism = "splice"` → [`crate::splice::relay`] — bytes
//!   spliced verbatim. Used for cert-pinning clients that would
//!   reject the hermit-minted leaf.
//!
//! For arrival via `HTTP_PROXY` / `HTTPS_PROXY` see
//! [`crate::forward`]; both modules call into the same engines.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn, Instrument};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind};
use crate::connector::UpstreamConnector;
use crate::mitm::MitmConfig;
use crate::policy::{Mechanism, RequestPolicy, Verdict};
use crate::proxy::{get_original_dst, read_sni_with_buffer, MAX_CONCURRENT_CONNECTIONS};

/// Per-connection ID counter — same shape as the one in
/// [`crate::forward`], but kept private here so the two
/// namespaces (`mitm_conn=…` vs `http_conn=…`) don't collide
/// in a single trace search.
static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_conn_id() -> u64 {
    CONN_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Max time to wait for the TLS ClientHello from the client.
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// Max time for the upstream TCP connect on the SNI cut-through
/// path. The MITM path has its own equivalent in `mitm.rs`.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Run the transparent intercept accept loop.
pub async fn run<P, C>(listener: TcpListener, config: Arc<MitmConfig<P, C>>) -> Result<()>
where
    P: RequestPolicy + 'static,
    C: UpstreamConnector + 'static,
{
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    info!("transparent: proxy listening on {}", listener.local_addr()?);

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // EMFILE / ECONNABORTED etc. must not kill the listener.
                warn!(error = %e, "transparent: accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "transparent: connection semaphore closed; dropping connection");
            continue;
        };
        let config = Arc::clone(&config);

        let conn_id = next_conn_id();
        let span = tracing::trace_span!("mitm_conn", conn = conn_id, peer = %addr);
        // Read SO_ORIGINAL_DST while the stream is still on the
        // accept side — once it moves into the spawned task the
        // borrow is gone. In proxy mode this returns `None`
        // (no DNAT installed); transparent-DNAT setups get the
        // pre-DNAT (ip, port).
        let original_dst = get_original_dst(&stream);
        tokio::spawn(
            async move {
                let _permit = permit;
                debug!(%addr, "transparent: accepted connection");
                if let Err(e) = handle_stream(stream, addr, original_dst, &config).await {
                    debug!(%addr, error = %e, "transparent: connection ended");
                }
                trace!("transparent_conn closed");
            }
            .instrument(span),
        );
    }
}

/// Handle one connection that arrived via DNAT (or via a forward-
/// proxy hand-off carrying a synthetic `original_dst`). Reads
/// SNI, applies hostname-level policy, dispatches to the MITM
/// engine or the splice engine based on per-rule mechanism.
///
/// `original_dst` is the pre-DNAT destination when the stream
/// arrived through transparent NAT, or a synthetic
/// `Some((_, port))` when [`crate::forward`] hands a post-`CONNECT`
/// tunnel here so the upstream dial uses the CONNECT port.
/// `None` is fine; the connector falls back to
/// `config.upstream_port`.
pub async fn handle_stream<P, C>(
    mut client_tcp: TcpStream,
    client_addr: SocketAddr,
    original_dst: Option<SocketAddr>,
    config: &MitmConfig<P, C>,
) -> Result<()>
where
    P: RequestPolicy,
    C: UpstreamConnector,
{
    trace!(
        original_dst = ?original_dst,
        "transparent: original_dst hint"
    );

    // Step 1: read the ClientHello, extract SNI (with a timeout —
    // a client that opens a socket and never sends must not park
    // a tokio task forever).
    trace!("transparent: awaiting ClientHello");
    let (hostname, client_hello_buf) = match timeout(
        CLIENT_HELLO_TIMEOUT,
        read_sni_with_buffer(&mut client_tcp),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            debug!(%client_addr, "transparent: ClientHello read timed out");
            return Ok(());
        }
    };
    trace!(
        hostname = ?hostname,
        client_hello_bytes = client_hello_buf.len(),
        "transparent: ClientHello parsed"
    );

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
                port: None,
                reason: Some("TLS connection without SNI".to_string()),
            });
            return Ok(());
        }
    };

    // Step 2: hostname-level policy check.
    let host_verdict = config.policy.check(&hostname);
    trace!(?host_verdict, %hostname, "transparent: SNI host policy verdict");
    if host_verdict == Verdict::Deny {
        debug!(%client_addr, %hostname, "hermit blocked: TLS hostname not in allowlist");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::TlsHostname,
            client: Some(client_addr.to_string()),
            hostname: Some(hostname.clone()),
            method: None,
            path: None,
            port: None,
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
        port: None,
        reason: None,
    });

    // Step 3: mechanism dispatch.
    let mechanism = config.policy.mechanism(&hostname);
    trace!(?mechanism, %hostname, "transparent: mechanism for host");
    match mechanism {
        Mechanism::Splice => {
            trace!(%hostname, "transparent: dispatching to splice");
            splice_after_sni(client_tcp, &client_hello_buf, &hostname, original_dst, config)
                .await
        }
        _ => {
            trace!(%hostname, "transparent: dispatching to mitm engine");
            crate::mitm::run(
                client_tcp,
                client_addr,
                original_dst,
                &hostname,
                client_hello_buf,
                config,
            )
            .await
        }
    }
}

/// Splice path on the transparent listener: dial the real
/// upstream and replay the buffered ClientHello so the client's
/// TLS handshake lands there verbatim, then hand the rest to
/// [`crate::splice::relay`]. The hostname came from the SNI
/// peek the listener already did; that's the only thing
/// "splice on the transparent path" needs that the splice
/// engine itself doesn't.
async fn splice_after_sni<P, C>(
    client_tcp: TcpStream,
    client_hello: &[u8],
    hostname: &str,
    original_dst: Option<SocketAddr>,
    config: &MitmConfig<P, C>,
) -> Result<()>
where
    P: RequestPolicy,
    C: UpstreamConnector,
{
    debug!(%hostname, "transparent: splice");
    let upstream = match timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        config
            .connector
            .connect(hostname, config.upstream_port, original_dst),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(%hostname, error = %e, "transparent: splice upstream failed");
            return Ok(());
        }
        Err(_) => {
            warn!(%hostname, "transparent: splice upstream timed out");
            return Ok(());
        }
    };

    let _ = crate::splice::relay(client_tcp, upstream, client_hello).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn splice_after_sni_forwards_hello_and_bytes() {
        // The whole point of the Splice mechanism on the
        // transparent path is that the ClientHello (which the
        // listener already consumed for the SNI peek) must reach
        // the real upstream verbatim — otherwise TLS would have
        // nothing to work with. This test stands up a mock
        // upstream TCP server, hands `splice_after_sni` an
        // already-buffered ClientHello, and asserts the upstream
        // receives those bytes and its reply flows back to the
        // (fake) client.
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

        let splice_done = tokio::spawn(async move {
            let _ = splice_after_sni(server_side, &hello, "127.0.0.1", None, &config).await;
        });

        let mut resp = [0u8; 2];
        client_side.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"UP");

        drop(client_side);

        tokio::time::timeout(Duration::from_secs(2), splice_done)
            .await
            .expect("splice timed out")
            .unwrap();

        let received = upstream_task.await.unwrap();
        assert_eq!(&received, b"CLIENTHELLO");
    }
}
