use anyhow::{Context, Result};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, error, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::connector::UpstreamConnector;
use crate::policy::{ConnectionPolicy, Verdict};
use crate::sni::{self, SniResult};

/// Hard cap on ClientHello buffer growth. A real ClientHello fits in one
/// TLS record (<16KB); anything larger is either garbage or an attempt to
/// OOM us by streaming junk.
const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;
/// Max time to wait for the TLS ClientHello.
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// Max time for the upstream TCP connect.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Max time for each of the write calls that replay the ClientHello and
/// subsequent bulk traffic. An upstream that TCP-accepts but never drains
/// the socket must not park the handler forever.
const UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
/// Idle threshold for bidirectional splicing — if neither side makes
/// progress for this long, tear the connection down. This is an
/// idle-timer, not a deadline, so long-running legitimate connections
/// that keep sending bytes don't trip it.
const COPY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Max concurrent in-flight connections per listener. Bounds task/fd
/// accumulation under load so a burst of accepts can't exhaust resources.
/// Shared across the three proxy flavors.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Configuration for the proxy accept loop.
pub struct ProxyConfig<P, C> {
    pub policy: Arc<P>,
    pub connector: Arc<C>,
    pub upstream_port: u16,
    /// Where to record block events. Defaults to a disabled (no-op)
    /// logger when the caller didn't request one.
    pub block_log: BlockLogger,
}

/// Run the proxy accept loop on an already-bound listener.
///
/// The caller controls how the listener is created — this is the key
/// decoupling point for hermit integration where the listener fd comes
/// from the child netns via CLONE_FILES.
pub async fn run<P, C>(listener: TcpListener, config: Arc<ProxyConfig<P, C>>) -> Result<()>
where
    P: ConnectionPolicy + 'static,
    C: UpstreamConnector + 'static,
{
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        // If the semaphore is ever closed (future refactor), drop the
        // connection rather than panic the whole listener.
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "connection semaphore closed; dropping connection");
            continue;
        };
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            let _permit = permit;
            debug!(%addr, "accepted connection");
            if let Err(e) = handle_connection_full(stream, addr, &config).await {
                error!(%addr, error = %e, "connection handler failed");
            }
        });
    }
}

/// Handle a single proxied connection.
///
/// Reads the TLS ClientHello to extract SNI, checks policy, then
/// connects upstream and splices the streams.
/// Read the TLS ClientHello from the client, extracting the SNI hostname.
/// Returns the hostname and the raw bytes that were read (for replay).
pub async fn read_sni_with_buffer(client: &mut TcpStream) -> Result<(Option<String>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);

    let hostname = loop {
        let mut tmp = [0u8; 1024];
        let n = client
            .read(&mut tmp)
            .await
            .context("reading from client")?;
        if n == 0 {
            anyhow::bail!("client disconnected before completing ClientHello");
        }
        buf.extend_from_slice(&tmp[..n]);

        // Hard cap: a real ClientHello is well under this. Anything bigger
        // is junk and we'd rather drop than keep growing the buffer.
        if buf.len() > MAX_CLIENT_HELLO_BYTES {
            anyhow::bail!(
                "ClientHello exceeded {} bytes without completing",
                MAX_CLIENT_HELLO_BYTES
            );
        }

        match sni::extract_sni(&buf)? {
            SniResult::Hostname(name) => break Some(name),
            SniResult::NoSni => break None,
            SniResult::Incomplete => continue,
        }
    };

    Ok((hostname, buf))
}

/// Handle a single connection end-to-end: SNI extraction, policy check,
/// upstream connect, ClientHello replay, and bidirectional copy.
pub async fn handle_connection_full<P, C>(
    mut client: TcpStream,
    client_addr: SocketAddr,
    config: &ProxyConfig<P, C>,
) -> Result<()>
where
    P: ConnectionPolicy,
    C: UpstreamConnector,
{
    let original_dst = get_original_dst(&client);

    let (hostname, client_hello_buf) = match timeout(
        CLIENT_HELLO_TIMEOUT,
        read_sni_with_buffer(&mut client),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            warn!(%client_addr, "ClientHello read timed out");
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
                port: None,
                reason: Some("TLS connection without SNI".to_string()),
            });
            return Ok(());
        }
    };

    match config.policy.check(&hostname) {
        Verdict::Allow => {}
        Verdict::Deny => {
            debug!(%client_addr, hostname, "hermit blocked: TLS hostname not in allowlist");
            config.block_log.log(BlockEvent {
                time_unix_ms: now_unix_ms(),
                kind: BlockKind::TlsHostname,
                client: Some(client_addr.to_string()),
                hostname: Some(hostname),
                method: None,
                path: None,
                port: None,
                reason: Some("hostname not in allowlist".to_string()),
            });
            return Ok(());
        }
    }

    debug!(%client_addr, hostname, "forwarding");
    let mut upstream = match timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        config
            .connector
            .connect(&hostname, config.upstream_port, original_dst),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            warn!(%hostname, "upstream connect timed out");
            return Ok(());
        }
    };

    // A timeout around write_all bounds the case where upstream TCP
    // accepts but never drains the socket — write_all otherwise stalls
    // indefinitely waiting for the send window.
    match timeout(
        UPSTREAM_WRITE_TIMEOUT,
        upstream.write_all(&client_hello_buf),
    )
    .await
    {
        Ok(r) => r.context("replaying ClientHello to upstream")?,
        Err(_) => {
            warn!(%hostname, "upstream ClientHello replay timed out");
            return Ok(());
        }
    }

    // Splice bytes with an idle timeout on each side. `copy_bidirectional`
    // from tokio has no idle detection — a peer that stalls at the TLS
    // layer or application layer would park this task until the kernel
    // eventually tears the socket down.
    if let Err(e) = copy_bidirectional_idle(&mut client, &mut upstream, COPY_IDLE_TIMEOUT).await {
        // Clean close and idle-timeout are expected terminations, not
        // failures worth surfacing to the caller.
        debug!(%hostname, error = %e, "bidirectional copy ended");
    }

    Ok(())
}

/// Copy bytes in both directions between two streams with an idle
/// timeout on each half. Returns when either side closes or either
/// half stays idle longer than `idle`.
///
/// `tokio::io::copy_bidirectional` is the usual tool here but it has no
/// notion of "nothing happened for a while" — a peer that stops sending
/// without closing would park the task. We run the two halves via
/// [`try_join`] so any error (idle, real I/O error, short write) aborts
/// both sides together.
async fn copy_bidirectional_idle(
    a: &mut TcpStream,
    b: &mut TcpStream,
    idle: Duration,
) -> io::Result<()> {
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    let a_to_b = copy_with_idle(&mut ar, &mut bw, idle);
    let b_to_a = copy_with_idle(&mut br, &mut aw, idle);
    tokio::try_join!(a_to_b, b_to_a).map(|_| ())
}

/// Copy from reader to writer, timing out if no byte arrives within
/// `idle`. EOF on the reader shuts down the writer so the other half
/// sees the close.
async fn copy_with_idle<R, W>(r: &mut R, w: &mut W, idle: Duration) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
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
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
    }
}

/// Attempt to recover the original destination address from a REDIRECTed socket.
///
/// Returns `None` if the getsockopt fails (e.g. not a redirected connection).
pub fn get_original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();

    // SOL_IP = 0, SO_ORIGINAL_DST = 80
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            80, // SO_ORIGINAL_DST
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 {
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddr::new(ip.into(), port))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_original_dst_returns_none_on_normal_socket() {
        // A regular socket (not redirected) should return None, not crash
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            assert!(get_original_dst(&client).is_none());
        });
    }

    #[tokio::test]
    async fn copy_with_idle_passes_bytes_and_terminates_on_eof() {
        // Happy path: normal bytes flow through and EOF on the reader
        // ends the copy cleanly.
        let (mut client, mut server) = tokio::io::duplex(4096);
        let data = b"hello world";
        client.write_all(data).await.unwrap();
        drop(client); // EOF on the read half once the buffer drains

        let mut sink: Vec<u8> = Vec::new();
        let res = copy_with_idle(&mut server, &mut sink, Duration::from_secs(5)).await;
        assert!(res.is_ok(), "clean EOF should not return an error: {res:?}");
        assert_eq!(sink, data);
    }

    #[tokio::test]
    async fn copy_with_idle_times_out_when_reader_stalls() {
        // A reader that never produces a byte must trip the idle timeout
        // instead of parking forever. We hold `_client` alive so the
        // server side sees neither data nor EOF.
        let (_client, mut server) = tokio::io::duplex(4096);
        let mut sink: Vec<u8> = Vec::new();
        let res = copy_with_idle(&mut server, &mut sink, Duration::from_millis(100)).await;
        let err = res.expect_err("stalled reader must trip idle timeout");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
