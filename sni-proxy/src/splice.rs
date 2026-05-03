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
pub(crate) async fn copy_with_idle<R, W>(r: &mut R, w: &mut W, idle: Duration) -> io::Result<u64>
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
/// Test-only wrappers around `splice`'s private items.
/// Off by default; `sni-proxy-tests` flips on `__test_internals`.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use std::io;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite};

    /// Wrapper around the private `copy_with_idle` helper. The
    /// generic bounds are reproduced verbatim so callers don't
    /// need to depend on the helper's exact signature.
    pub async fn copy_with_idle<R, W>(r: &mut R, w: &mut W, idle: Duration) -> io::Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        super::copy_with_idle(r, w, idle).await
    }
}
