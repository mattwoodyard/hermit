//! Transparent intercept listener — the **transparent** column
//! of the matrix.
//!
//! Accepts TCP connections that arrived via DNAT (so
//! `SO_ORIGINAL_DST` recovers the pre-NAT destination) and
//! hands each one to [`crate::dispatch::https_after_tcp`], which
//! peeks SNI, runs hostname policy, and routes to either
//! [`crate::mitm::run`] or [`crate::splice::relay`] based on the
//! per-rule mechanism.
//!
//! The forward listener uses the same dispatcher after its
//! `200 Connection Established` — neither file needs to know
//! about the other. See [`crate::forward`] for that side.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn, Instrument};

use crate::connector::UpstreamConnector;
use crate::mitm::MitmConfig;
use crate::policy::RequestPolicy;
use crate::proxy::{get_original_dst, MAX_CONCURRENT_CONNECTIONS};

/// Per-connection ID counter. Tags every span with `conn=N` so an
/// operator chasing one connection can grep `transparent_conn=N`
/// and see only that conversation's events.
static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_conn_id() -> u64 {
    CONN_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Run the transparent intercept accept loop.
pub async fn run<P, C>(listener: TcpListener, config: Arc<MitmConfig<P, C>>) -> Result<()>
where
    P: RequestPolicy + 'static,
    C: UpstreamConnector + 'static,
{
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    info!("transparent: proxy listening on {}", listener.local_addr()?);

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // EMFILE / ECONNABORTED etc. must not kill the listener.
                warn!(error = %e, "transparent: accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "transparent: connection semaphore closed; dropping connection");
            continue;
        };
        let config = Arc::clone(&config);

        let conn_id = next_conn_id();
        let span = tracing::trace_span!("transparent_conn", conn = conn_id, peer = %addr);
        // Read SO_ORIGINAL_DST while the stream is still on the
        // accept side — once it moves into the spawned task the
        // borrow is gone. In proxy mode this returns `None`
        // (no DNAT installed); transparent-DNAT setups get the
        // pre-DNAT (ip, port).
        let original_dst = get_original_dst(&stream);
        tokio::spawn(
            async move {
                let _permit = permit;
                debug!(%addr, "transparent: accepted connection");
                if let Err(e) = crate::dispatch::https_after_tcp(
                    stream, addr, original_dst, &config,
                )
                .await
                {
                    debug!(%addr, error = %e, "transparent: connection ended");
                }
                trace!("transparent_conn closed");
            }
            .instrument(span),
        );
    }
}
