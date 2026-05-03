//! Catch-all TCP observer for `hermit learn`.
//!
//! In learn mode hermit installs a wildcard nft DNAT rule that
//! catches every TCP connection on a port without a more specific
//! rule (i.e. anything outside `{80, 443} ∪ port_forwards ∪
//! bypass_tcp`). Those connections land on this listener instead
//! of failing with "no route to host", and the listener turns
//! them into a JSONL access-log event so `hermit learn-convert`
//! can suggest a `[[access_rule]]` (mechanism = "bypass") for the
//! port the build actually used.
//!
//! No bytes are forwarded. The whole point is to *observe* — the
//! build sees a connection that opens and immediately closes,
//! same as a refused service. That's good enough to drive the
//! authoring workflow; if the build needs the connection to
//! succeed the user adds an explicit bypass rule and re-runs.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Duration;
use tracing::{debug, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::dns_cache::DnsCache;
use crate::proxy::{get_original_dst, MAX_CONCURRENT_CONNECTIONS};

/// Configuration for the learn-mode TCP observer.
pub struct LearnObserverConfig {
    /// Reverse-map an SO_ORIGINAL_DST IP back to the hostname the
    /// build resolved to reach it. Shared with the DNS server +
    /// bypass relays.
    pub dns_cache: Arc<DnsCache>,
    /// Where to record the observed-tcp events. The block log is
    /// not used by this listener — there is no "block" path in
    /// learn mode.
    pub access_log: BlockLogger,
}

/// Run the observer accept loop. Mirrors the structure of
/// [`crate::forward::run`] / [`crate::transparent::run`]: bounded
/// concurrency via a semaphore, accept-loop survives transient
/// errors with a short backoff.
pub async fn run(listener: TcpListener, config: Arc<LearnObserverConfig>) -> Result<()> {
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "learn-observer: accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "learn-observer: connection semaphore closed; dropping");
            continue;
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _permit = permit;
            handle_connection(stream, addr, &config).await;
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    client_addr: SocketAddr,
    config: &LearnObserverConfig,
) {
    // Read the pre-DNAT destination so we know which port the
    // build was *really* aiming at. Without this the trace would
    // collapse every observed connection to "loopback at the
    // observer's port", which carries no signal for rule
    // authoring.
    let original_dst = get_original_dst(&stream);
    let (hostname, port) = match original_dst {
        Some(dst) => {
            let host = config.dns_cache.reverse(dst.ip());
            (host, Some(dst.port()))
        }
        None => {
            // Unusual on the catch-all DNAT path, but possible if
            // the kernel didn't tag the connection (e.g. the rule
            // didn't match for some reason and we got a direct
            // loopback connect). Log without the dst info so the
            // event is still visible in the trace.
            debug!(%client_addr, "learn-observer: no SO_ORIGINAL_DST");
            (None, None)
        }
    };

    let host_for_log = hostname.clone().unwrap_or_else(|| {
        // Synthesise a stable "unknown host" key so learn-convert
        // can still aggregate by IP literal when the DNS cache has
        // no entry — e.g. the build connected to a hard-coded IP.
        match original_dst {
            Some(dst) => format!("ip:{}", dst.ip()),
            None => "ip:unknown".to_string(),
        }
    });
    debug!(%client_addr, host = %host_for_log, port = ?port, "learn-observer: tcp");

    config.access_log.log(BlockEvent {
        time_unix_ms: now_unix_ms(),
        kind: BlockKind::TcpObserve,
        client: Some(client_addr.to_string()),
        hostname: Some(host_for_log),
        method: None,
        path: None,
        port,
        reason: None,
    });

    // Drop the stream — the connection closes without bytes
    // exchanged. We make no attempt to fool the build into
    // succeeding; the trace exists so the operator can author a
    // bypass rule and re-run.
    drop(stream);
}
