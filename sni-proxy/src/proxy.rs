use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, error, warn};

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
/// Max concurrent in-flight connections per listener. Bounds task/fd
/// accumulation under load so a burst of accepts can't exhaust resources.
/// Shared across the three proxy flavors.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Configuration for the proxy accept loop.
pub struct ProxyConfig<P, C> {
    pub policy: Arc<P>,
    pub connector: Arc<C>,
    pub upstream_port: u16,
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
        let permit = Arc::clone(&conn_limit)
            .acquire_owned()
            .await
            .expect("semaphore never closed");
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
            warn!(%client_addr, "hermit blocked: TLS connection without SNI");
            return Ok(());
        }
    };

    match config.policy.check(&hostname) {
        Verdict::Allow => {}
        Verdict::Deny => {
            warn!(%client_addr, hostname, "hermit blocked: TLS hostname not in allowlist");
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

    upstream
        .write_all(&client_hello_buf)
        .await
        .context("replaying ClientHello to upstream")?;

    copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("bidirectional copy")?;

    Ok(())
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
}
