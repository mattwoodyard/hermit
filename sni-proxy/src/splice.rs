//! Byte-relay engine — the **splice** half of the matrix.
//!
//! No TLS termination, no L7 inspection. Two callers:
//!
//! * [`crate::transparent`] — for `mechanism = "splice"` rules
//!   (cert-pinning clients). The listener has read the
//!   ClientHello to extract SNI for policy; those bytes are
//!   passed in as `replay` so the upstream sees the original
//!   handshake unchanged.
//! * [`crate::forward`] — for the legacy `CONNECT`-then-splice
//!   path (when no MITM hand-off is configured). The listener
//!   has already responded `200 Connection Established`; the
//!   client's first follow-up byte is whatever it was going to
//!   send anyway, so `replay` is empty.
//!
//! The engine itself is intentionally tiny: forward `replay`
//! to the upstream once, then `copy_bidirectional`. Every other
//! decision (dial succeeded?, send 200 or 502?, what to log?)
//! belongs to the listener that called us.

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Splice bytes between `client` and `upstream`. Optionally
/// forward `replay` to the upstream first — used when the
/// listener has already read the client's TLS ClientHello to
/// extract SNI and now needs the upstream to see those bytes
/// verbatim.
///
/// Returns the byte counts each direction so callers can log
/// them. A clean close on either side ends the splice; that's
/// the expected termination for both an HTTPS tunnel and a
/// cert-pinning TLS session.
pub async fn relay(
    mut client: TcpStream,
    mut upstream: TcpStream,
    replay: &[u8],
) -> Result<(u64, u64)> {
    if !replay.is_empty() {
        upstream
            .write_all(replay)
            .await
            .context("forwarding replay bytes to splice upstream")?;
    }
    let bytes = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// `relay` forwards `replay` verbatim, then any subsequent
    /// bytes the client sends after the call begins.
    #[tokio::test]
    async fn relay_writes_replay_then_splices() {
        // Echo upstream: reads everything until EOF, copies to a
        // shared buffer the test inspects.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });

        // Set up the client end + a TcpStream we hand to relay
        // playing the role of the proxy-to-client socket.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let mut client_tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let (server_side, _) = proxy_listener.accept().await.unwrap();

        let upstream = TcpStream::connect(upstream_addr).await.unwrap();

        let replay = b"REPLAYED_HELLO";
        let join = tokio::spawn(async move {
            relay(server_side, upstream, replay).await.unwrap()
        });

        client_tcp.write_all(b"AFTER").await.unwrap();
        // Half-close the client side so copy_bidirectional sees
        // a clean EOF.
        drop(client_tcp);

        let _ = join.await.unwrap();
        let received = echo.await.unwrap();
        assert!(received.starts_with(b"REPLAYED_HELLO"),
            "replay bytes must precede the spliced stream: {received:?}");
        assert!(received.ends_with(b"AFTER"),
            "post-replay bytes must reach upstream: {received:?}");
    }

    /// Empty `replay` is the forward CONNECT-splice case —
    /// nothing prepended, just bidirectional copy.
    #[tokio::test]
    async fn relay_empty_replay_is_pure_splice() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let mut client_tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let (server_side, _) = proxy_listener.accept().await.unwrap();
        let upstream = TcpStream::connect(upstream_addr).await.unwrap();

        let join = tokio::spawn(async move {
            relay(server_side, upstream, &[]).await.unwrap()
        });

        client_tcp.write_all(b"only the post-200 bytes").await.unwrap();
        drop(client_tcp);

        let _ = join.await.unwrap();
        assert_eq!(echo.await.unwrap(), b"only the post-200 bytes");
    }
}
