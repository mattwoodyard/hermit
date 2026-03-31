use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::connector::UpstreamConnector;
use crate::policy::{ConnectionPolicy, Verdict};
use crate::sni::{self, SniResult};

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
    loop {
        let (stream, addr) = listener.accept().await?;
        let config = Arc::clone(&config);

        tokio::spawn(async move {
            info!(%addr, "accepted connection");
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

    let (hostname, client_hello_buf) = read_sni_with_buffer(&mut client).await?;

    let hostname = match hostname {
        Some(h) => h,
        None => {
            warn!(%client_addr, "no SNI in ClientHello, dropping");
            return Ok(());
        }
    };

    match config.policy.check(&hostname) {
        Verdict::Allow => {}
        Verdict::Deny => {
            warn!(%client_addr, hostname, "denied by policy, dropping");
            return Ok(());
        }
    }

    info!(%client_addr, hostname, "forwarding");
    let mut upstream = config
        .connector
        .connect(&hostname, config.upstream_port, original_dst)
        .await?;

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
