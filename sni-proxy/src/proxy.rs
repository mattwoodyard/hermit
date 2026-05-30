use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, error, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::connector::UpstreamConnector;
use crate::policy::{ConnectionPolicy, Verdict};
use crate::sni::{self, SniResult};
use crate::splice;
use crate::timeouts::{CLIENT_HELLO_TIMEOUT, UPSTREAM_CONNECT_TIMEOUT};

/// Hard cap on ClientHello buffer growth. A real ClientHello fits in one
/// TLS record (<16KB); anything larger is either garbage or an attempt to
/// OOM us by streaming junk.
const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;
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
    let upstream = match timeout(
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

    // Hand to the canonical splice engine: it forwards the buffered
    // ClientHello to upstream (with a write timeout) and then runs
    // a bidirectional copy with per-direction idle timeouts. Clean
    // close and idle-timeout are expected terminations.
    if let Err(e) = splice::relay(client, upstream, &client_hello_buf).await {
        debug!(%hostname, error = %e, "splice ended");
    }

    Ok(())
}

/// Attempt to recover the original destination address from a
/// DNAT'd (REDIRECTed) socket. Probes the socket's local-address
/// family to pick the right `getsockopt` ABI; returns `None` if
/// the call fails (typically because no DNAT was in the path).
///
/// IPv4: `getsockopt(SOL_IP, SO_ORIGINAL_DST=80, sockaddr_in)`.
/// IPv6: `getsockopt(IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST=80,
/// sockaddr_in6)` — same option *number*, different level, larger
/// struct. The two ABIs are distinct and asking with the wrong
/// one silently truncates or returns EOPNOTSUPP.
pub fn get_original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    match stream.local_addr().ok()? {
        SocketAddr::V4(_) => get_original_dst_v4(fd),
        SocketAddr::V6(_) => get_original_dst_v6(fd),
    }
}

fn get_original_dst_v4(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t =
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            80, // SO_ORIGINAL_DST
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(SocketAddr::new(ip.into(), port))
}

fn get_original_dst_v6(fd: std::os::unix::io::RawFd) -> Option<SocketAddr> {
    use std::net::{Ipv6Addr, SocketAddrV6};
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t =
        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    // `IP6T_SO_ORIGINAL_DST` is 80 (same number as the v4 option,
    // but at `IPPROTO_IPV6`). libc doesn't expose the constant
    // directly; the kernel header `linux/netfilter_ipv6/ip6_tables.h`
    // defines it as 80.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            80, // IP6T_SO_ORIGINAL_DST
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    Some(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(addr.sin6_addr.s6_addr),
        u16::from_be(addr.sin6_port),
        u32::from_be(addr.sin6_flowinfo),
        u32::from_be(addr.sin6_scope_id),
    )))
}
