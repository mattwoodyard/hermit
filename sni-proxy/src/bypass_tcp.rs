//! Transparent TCP relay for `Mechanism::Bypass` rules.
//!
//! The listener sits on a dedicated loopback port inside the child
//! netns; nft DNATs the real target port (e.g. `389` for LDAP) to it.
//! For each accepted connection we:
//!
//! 1. Pull the pre-DNAT destination out of `SO_ORIGINAL_DST`.
//! 2. Reverse-map that dst IP to a hostname via the shared
//!    [`DnsCache`] — the child's own DNS lookup populated it moments
//!    ago. IPs not in the cache are denied (the child is attempting
//!    to reach a literal IP we never handed out).
//! 3. Check the bypass policy: was this hostname declared with a
//!    matching `(protocol, port)`?
//! 4. If allowed, dial the real destination from the host netns and
//!    splice bytes both ways until one side closes.
//!
//! No payload inspection. No protocol awareness. That's the point —
//! Kerberos, SSH, raw LDAP, etc. all work as long as their hostnames
//! were resolved through hermit DNS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::connector::UpstreamConnector;
use crate::dns_cache::DnsCache;
use crate::policy::{BypassProtocol, RuleSet};
use crate::proxy::{get_original_dst, MAX_CONCURRENT_CONNECTIONS};
use crate::timeouts::UPSTREAM_CONNECT_TIMEOUT;

/// Per-listener configuration. Each bypass `(protocol=tcp, port=N)`
/// gets its own `BypassTcpConfig` and its own accept loop.
pub struct BypassTcpConfig<C> {
    /// The port this relay is authoritative for. Used both to
    /// evaluate the policy match and to log a meaningful entry.
    pub port: u16,
    pub rules: Arc<RuleSet>,
    pub cache: Arc<DnsCache>,
    pub connector: Arc<C>,
    pub block_log: BlockLogger,
}

/// Run the TCP bypass accept loop until the listener is closed.
pub async fn run<C>(listener: TcpListener, config: Arc<BypassTcpConfig<C>>) -> Result<()>
where
    C: UpstreamConnector + 'static,
{
    let local = listener.local_addr().ok();
    tracing::info!(port = config.port, ?local, "bypass-tcp: accept loop starting");
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "bypass-tcp: accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        debug!(%addr, port = config.port, "bypass-tcp: accepted connection");
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "bypass-tcp: connection semaphore closed; dropping");
            continue;
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(stream, addr, &config).await {
                debug!(%addr, error = %e, "bypass-tcp: connection ended");
            }
        });
    }
}

/// Accept-side wrapper: reads `SO_ORIGINAL_DST`, then delegates to
/// [`handle_connection_at`] which holds the real logic (and is what
/// unit tests target since they can supply their own fake dst).
async fn handle_connection<C>(
    client: TcpStream,
    client_addr: SocketAddr,
    config: &BypassTcpConfig<C>,
) -> Result<()>
where
    C: UpstreamConnector,
{
    let Some(orig) = get_original_dst(&client) else {
        // Only ever happens on a direct connect to the bypass port
        // from inside the sandbox (no DNAT applied). Treat as a
        // block-worthy anomaly so it's visible in the log, but
        // don't escalate — closing the socket is enough.
        debug!(%client_addr, port = config.port,
            "bypass-tcp: no SO_ORIGINAL_DST, closing (direct-to-relay connect?)");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(client_addr.to_string()),
            hostname: None,
            method: None,
            path: None,
            port: None,
            reason: Some("bypass-tcp: missing SO_ORIGINAL_DST".to_string()),
        });
        return Ok(());
    };
    debug!(%client_addr, dst_ip = %orig.ip(), dst_port = orig.port(),
        "bypass-tcp: SO_ORIGINAL_DST recovered");
    handle_connection_at(client, client_addr, orig.ip(), orig.port(), config).await
}

/// Core per-connection logic with an injected destination. Kept
/// separate from [`handle_connection`] so tests don't need to stage
/// a real DNAT. A deny path closes the client socket with no data
/// (bypass is transparent — there's no HTTP status we could return).
pub async fn handle_connection_at<C>(
    mut client: TcpStream,
    client_addr: SocketAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    config: &BypassTcpConfig<C>,
) -> Result<()>
where
    C: UpstreamConnector,
{
    // Reverse-lookup: the child's DNS query populated `cache`, so a
    // dst IP that we just handed out resolves back to the hostname
    // asked for. If it doesn't, fall through to the literal-IP rule
    // path — the child may have been given a raw IP that was
    // pre-authorized via `ip = "…"` in config.
    let hostname_opt = config.cache.reverse(dst_ip);
    debug!(%client_addr, %dst_ip, dst_port, port = config.port,
        hostname = ?hostname_opt,
        "bypass-tcp: policy check");
    let allowed = match &hostname_opt {
        Some(h) => config
            .rules
            .is_bypass_allowed(h, BypassProtocol::Tcp, config.port),
        None => config
            .rules
            .is_bypass_allowed_by_ip(dst_ip, BypassProtocol::Tcp, config.port),
    };
    debug!(%client_addr, hostname = ?hostname_opt, allowed,
        "bypass-tcp: policy decision");
    if !allowed {
        debug!(%client_addr, ?hostname_opt, %dst_ip, port = config.port,
            "bypass-tcp: no matching rule, denying");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(client_addr.to_string()),
            hostname: hostname_opt.clone(),
            method: None,
            path: Some(format!("{dst_ip}:{dst_port}")),
            port: None,
            reason: Some(match hostname_opt.as_ref() {
                Some(_) => "bypass-tcp: no matching host rule".to_string(),
                None => "bypass-tcp: dst IP not in DNS cache and not allowed by ip rule".to_string(),
            }),
        });
        return Ok(());
    }

    // Dial: prefer the hostname (so TLS SNI / cert verification
    // further downstream sees the real name), otherwise fall back
    // to the IP literal for IP-only rules.
    let dial_target: String = hostname_opt
        .clone()
        .unwrap_or_else(|| dst_ip.to_string());
    debug!(%client_addr, dial_target = %dial_target, %dst_ip, port = dst_port,
        "bypass-tcp: dialing upstream");

    let mut upstream = match timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        config.connector.connect(&dial_target, dst_port, None),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(%dial_target, port = dst_port, error = %e,
                "bypass-tcp: upstream connect failed");
            let _ = client.shutdown().await;
            return Ok(());
        }
        Err(_) => {
            warn!(%dial_target, port = dst_port, "bypass-tcp: upstream connect timed out");
            let _ = client.shutdown().await;
            return Ok(());
        }
    };

    // Bidirectional splice. We intentionally use `copy_bidirectional`
    // rather than the raw `splice(2)` syscall for v1: it's already
    // non-blocking and driven by tokio's reactor, and the extra
    // zero-copy gains of splice-via-pipe are only measurable on bulk
    // data transfer — not the request/response pattern typical of
    // LDAP/SSH/Kerberos. Swap to a splice-based implementation if
    // throughput ever shows up in a profile.
    let splice_start = std::time::Instant::now();
    debug!(%client_addr, %dial_target, port = dst_port,
        "bypass-tcp: splice begin");
    let splice = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    let elapsed_ms = splice_start.elapsed().as_millis();
    match splice {
        Ok((c2u, u2c)) => debug!(%client_addr, %dial_target, port = dst_port,
            client_to_upstream_bytes = c2u, upstream_to_client_bytes = u2c,
            elapsed_ms, "bypass-tcp: splice end"),
        Err(ref e) => debug!(%client_addr, %dial_target, port = dst_port,
            elapsed_ms, error = %e, "bypass-tcp: splice error"),
    }
    Ok(())
}
