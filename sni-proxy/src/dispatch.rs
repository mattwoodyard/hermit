//! Shared post-handshake dispatcher used by both arrival modes.
//!
//! Once a TCP stream is positioned at the start of a TLS
//! ClientHello — whether it arrived via DNAT (the transparent
//! listener) or via a `CONNECT` tunnel that just got a
//! `200 Connection Established` (the forward listener) — the
//! work to do is identical:
//!
//! 1. Read the ClientHello, extract SNI.
//! 2. Apply hostname-level policy (deny → log + close).
//! 3. Record an access event (so `hermit learn` sees the SNI
//!    even if the connection never produces an HTTP request).
//! 4. Dispatch on per-rule mechanism:
//!    * [`Mechanism::Splice`] → dial upstream, replay
//!      ClientHello, hand to [`crate::splice::relay`].
//!    * Otherwise → hand to [`crate::mitm::run`].
//!
//! Centralising this here means [`crate::transparent`] and
//! [`crate::forward`] each call into one function, neither
//! depends on the other, and the four matrix cells map to four
//! engine calls without an intermediate triangle.

use std::net::SocketAddr;
#[cfg(test)]
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind};
use crate::connector::UpstreamConnector;
use crate::mitm::MitmConfig;
use crate::policy::{Mechanism, RequestPolicy, Verdict};
use crate::proxy::read_sni_with_buffer;
use crate::timeouts::{CLIENT_HELLO_TIMEOUT, UPSTREAM_CONNECT_TIMEOUT};

/// Read the ClientHello, run hostname policy, dispatch to the
/// MITM or splice engine.
///
/// `original_dst` is a port hint for the upstream dial. The
/// transparent listener supplies the pre-DNAT destination; the
/// forward listener supplies a synthetic `Some((_, port))` from
/// the `CONNECT` line; `None` falls back to
/// `config.upstream_port`.
pub async fn https_after_tcp<P, C>(
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
        "dispatch: original_dst hint"
    );

    // Step 1: read the ClientHello, extract SNI (with a timeout
    // — a client that opens a socket and never sends must not
    // park a tokio task forever).
    trace!("dispatch: awaiting ClientHello");
    let (hostname, client_hello_buf) = match timeout(
        CLIENT_HELLO_TIMEOUT,
        read_sni_with_buffer(&mut client_tcp),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            debug!(%client_addr, "dispatch: ClientHello read timed out");
            return Ok(());
        }
    };
    trace!(
        hostname = ?hostname,
        client_hello_bytes = client_hello_buf.len(),
        "dispatch: ClientHello parsed"
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
    trace!(?host_verdict, %hostname, "dispatch: SNI host policy verdict");
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
    // never produces an HTTP request (splice path).
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
    trace!(?mechanism, %hostname, "dispatch: mechanism for host");
    match mechanism {
        Mechanism::Splice => {
            trace!(%hostname, "dispatch: dispatching to splice");
            splice_after_sni(client_tcp, &client_hello_buf, &hostname, original_dst, config)
                .await
        }
        _ => {
            trace!(%hostname, "dispatch: dispatching to mitm engine");
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

/// Splice path: dial the real upstream and replay the buffered
/// ClientHello so the client's TLS handshake lands there
/// verbatim, then hand the rest to [`crate::splice::relay`].
/// The hostname came from the SNI peek above; that's the only
/// piece "splice after a TLS handshake start" needs that the
/// splice engine itself doesn't carry.
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
    debug!(%hostname, "dispatch: splice");
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
            warn!(%hostname, error = %e, "dispatch: splice upstream failed");
            return Ok(());
        }
        Err(_) => {
            warn!(%hostname, "dispatch: splice upstream timed out");
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
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn splice_after_sni_forwards_hello_and_bytes() {
        // The splice path's job is to replay the buffered
        // ClientHello to the upstream verbatim — without that
        // the client's TLS state machine has nothing to
        // continue against. This test stands up a mock
        // upstream, hands `splice_after_sni` an already-buffered
        // ClientHello, and asserts the upstream sees those
        // bytes and its reply flows back to the (fake) client.
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
            upstream_roots: None,
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
