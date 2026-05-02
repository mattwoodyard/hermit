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
//! to the upstream once, then run the bidirectional copy with
//! per-direction idle timeouts so a peer that stops sending
//! without closing can't park the task forever.

use std::io;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Idle threshold for the bidirectional splice — if neither side
/// makes progress for this long, tear the connection down. This
/// is an idle-timer, not a deadline, so long-running legitimate
/// connections that keep sending bytes don't trip it.
pub(crate) const SPLICE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Max time for a single replay-write to upstream. Bounds the
/// case where upstream TCP-accepts but never drains the socket.
const REPLAY_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

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
        match timeout(REPLAY_WRITE_TIMEOUT, upstream.write_all(replay)).await {
            Ok(r) => r.context("forwarding replay bytes to splice upstream")?,
            Err(_) => anyhow::bail!(
                "replay write to splice upstream timed out after {}s",
                REPLAY_WRITE_TIMEOUT.as_secs()
            ),
        }
    }
    let bytes = copy_bidirectional_idle(&mut client, &mut upstream, SPLICE_IDLE_TIMEOUT).await?;
    Ok(bytes)
}

/// Bidirectional copy with a per-direction idle timeout. Returns
/// `(client→upstream, upstream→client)` byte counts.
///
/// `tokio::io::copy_bidirectional` is the usual tool here but it
/// has no notion of "nothing happened for a while" — a peer that
/// stops sending without closing would park the task. We run the
/// two halves via `try_join` so any error (idle, real I/O error,
/// short write) aborts both sides together.
pub(crate) async fn copy_bidirectional_idle(
    a: &mut TcpStream,
    b: &mut TcpStream,
    idle: Duration,
) -> io::Result<(u64, u64)> {
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    let a_to_b = copy_with_idle(&mut ar, &mut bw, idle);
    let b_to_a = copy_with_idle(&mut br, &mut aw, idle);
    tokio::try_join!(a_to_b, b_to_a)
}

/// Copy from reader to writer, timing out if no byte arrives
/// within `idle`. EOF on the reader shuts down the writer so the
/// other half sees the close. Returns the number of bytes copied.
async fn copy_with_idle<R, W>(r: &mut R, w: &mut W, idle: Duration) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = match timeout(idle, r.read(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "bidirectional copy idle timeout",
                ))
            }
        };
        if n == 0 {
            // Propagate EOF by half-closing the writer so the peer
            // observing the other half sees a clean shutdown.
            let _ = w.shutdown().await;
            return Ok(total);
        }
        w.write_all(&buf[..n]).await?;
        total = total.saturating_add(n as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn copy_with_idle_passes_bytes_and_terminates_on_eof() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let data = b"hello world";
        client.write_all(data).await.unwrap();
        drop(client);

        let mut sink: Vec<u8> = Vec::new();
        let bytes = copy_with_idle(&mut server, &mut sink, Duration::from_secs(5))
            .await
            .expect("clean EOF should not return an error");
        assert_eq!(bytes, data.len() as u64);
        assert_eq!(sink, data);
    }

    #[tokio::test]
    async fn copy_with_idle_times_out_when_reader_stalls() {
        let (_client, mut server) = tokio::io::duplex(4096);
        let mut sink: Vec<u8> = Vec::new();
        let res = copy_with_idle(&mut server, &mut sink, Duration::from_millis(100)).await;
        let err = res.expect_err("stalled reader must trip idle timeout");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }


    /// `relay` forwards `replay` verbatim, then any subsequent
    /// bytes the client sends after the call begins.
    #[tokio::test]
    async fn relay_writes_replay_then_splices() {
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

        let replay = b"REPLAYED_HELLO";
        let join = tokio::spawn(async move {
            relay(server_side, upstream, replay).await.unwrap()
        });

        client_tcp.write_all(b"AFTER").await.unwrap();
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

    /// `relay` returns the actual byte counts copied each direction.
    #[tokio::test]
    async fn relay_returns_byte_counts_each_direction() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            // After client closes, send an answer, then close.
            s.write_all(b"REPLY").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let mut client_tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let (server_side, _) = proxy_listener.accept().await.unwrap();
        let upstream = TcpStream::connect(upstream_addr).await.unwrap();

        let join = tokio::spawn(async move {
            relay(server_side, upstream, b"HELLO").await.unwrap()
        });

        client_tcp.write_all(b"DATA").await.unwrap();
        client_tcp.shutdown().await.unwrap();

        // Drain the upstream's reply so the upstream→client half
        // can finish copying before we read counts.
        let mut got_back = Vec::new();
        client_tcp.read_to_end(&mut got_back).await.unwrap();

        let (a_to_b, b_to_a) = join.await.unwrap();
        upstream_task.await.unwrap();

        // Replay (5) is written outside the bidirectional copy and
        // is NOT counted in `a_to_b`. The post-replay client bytes
        // ("DATA") are.
        assert_eq!(a_to_b, 4, "a_to_b should count only post-replay client bytes");
        assert_eq!(b_to_a, 5, "b_to_a should count the upstream reply");
        assert_eq!(&got_back, b"REPLY");
    }
}
