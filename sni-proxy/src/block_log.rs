//! Append-only JSON-lines block-event log.
//!
//! When hermit blocks a connection or request, the event is emitted to a
//! file the operator can tail. Each line is a self-describing JSON object
//! so downstream tooling can filter without re-parsing text.
//!
//! Architecture: proxy/DNS tasks call [`BlockLogger::log`], which hands
//! the event to a single writer task over a bounded channel. One writer
//! serialises all output — no interleaving of partial lines, no lock
//! contention on the hot path. If the channel fills (writer stalled on
//! disk), events are dropped rather than backpressuring the proxy.

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Bound on queued but not-yet-written events. A slow disk shouldn't stall
/// the proxy, so we drop events past this point and count the drops.
const CHANNEL_CAPACITY: usize = 1024;

/// Kind of block, emitted verbatim in the log line.
///
/// Using an enum (not a free-form string) prevents drift between call
/// sites — each block site picks one of these variants.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockKind {
    /// DNS query name was not in the allowlist.
    Dns,
    /// TLS connection arrived with no SNI extension.
    TlsNoSni,
    /// TLS SNI hostname was not in the allowlist.
    TlsHostname,
    /// Plain HTTP request arrived without a Host header.
    HttpNoHost,
    /// Plain HTTP request was denied by access rules.
    Http,
    /// HTTPS request (post-MITM) was denied by access rules.
    Https,
    /// Learn-mode catch-all observer saw a TCP connection on a port
    /// that wasn't being intercepted by any of the named proxies.
    /// Emitted to the access log only — there is no "block" path
    /// for this kind in run mode (the connection would simply fail
    /// because no DNAT exists for the port).
    TcpObserve,
}

/// One block event. Owned strings because the event crosses a channel
/// into the writer task.
#[derive(Debug, Clone, Serialize)]
pub struct BlockEvent {
    /// Milliseconds since the Unix epoch. Integer so the log is stable
    /// across time-formatting changes; consumers can render however
    /// they prefer.
    pub time_unix_ms: u128,
    #[serde(rename = "type")]
    pub kind: BlockKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Destination port. Only set by [`BlockKind::TcpObserve`]
    /// today; other kinds embed the port in `client` / `path` /
    /// `hostname` per their own conventions and leave this field
    /// `None` so the JSONL stays terse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A handle that proxy/DNS tasks clone to report block events.
///
/// When disabled, [`BlockLogger::log`] is a no-op; call sites pay one
/// enum-match and nothing else.
#[derive(Clone)]
pub struct BlockLogger(Arc<Inner>);

enum Inner {
    Disabled,
    Enabled(mpsc::Sender<BlockEvent>),
}

impl BlockLogger {
    /// A no-op logger. Used when the operator didn't request a block log.
    pub fn disabled() -> Self {
        Self(Arc::new(Inner::Disabled))
    }

    /// Open (or create) `path` for append and spawn a writer task on the
    /// current tokio runtime. Returns the handle clones pass to proxies.
    ///
    /// Writes are flushed after every line so a crash loses at most the
    /// currently-in-channel events, not buffered ones.
    ///
    /// `O_NOFOLLOW` is set so a pre-planted symlink at the configured
    /// path can't redirect log writes elsewhere — the default location
    /// `$XDG_STATE_HOME/hermit/blocks.jsonl` is in user-writable space
    /// and would otherwise be a small symlink-redirect surface.
    pub async fn to_file(path: &Path) -> Result<Self> {
        // tokio's OpenOptions exposes `custom_flags` directly on
        // unix — no trait import needed.
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .await
            .with_context(|| format!("opening block log {}", path.display()))?;
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("opening block log {}", path.display()))?;

        // `append` mode implies writes go to end-of-file regardless of
        // seek position — but seek to end anyway so an initial flush
        // doesn't surprise a reader that opened the file before us.
        let _ = file.seek(SeekFrom::End(0)).await;

        let (tx, mut rx) = mpsc::channel::<BlockEvent>(CHANNEL_CAPACITY);
        let path_display = path.display().to_string();

        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                match serde_json::to_vec(&evt) {
                    Ok(mut line) => {
                        line.push(b'\n');
                        if let Err(e) = file.write_all(&line).await {
                            warn!(path = %path_display, error = %e,
                                "block log: write failed, closing writer");
                            return;
                        }
                        if let Err(e) = file.flush().await {
                            warn!(path = %path_display, error = %e,
                                "block log: flush failed, closing writer");
                            return;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "block log: serialise failed; dropping event");
                    }
                }
            }
            debug!(path = %path_display, "block log: channel closed, writer exiting");
        });

        Ok(Self(Arc::new(Inner::Enabled(tx))))
    }

    /// Hand an event to the writer task.
    ///
    /// Non-blocking: if the queue is full we drop the event rather than
    /// stall the caller. A slow disk must not become a denial-of-service
    /// surface against the proxy.
    pub fn log(&self, event: BlockEvent) {
        let Inner::Enabled(tx) = &*self.0 else { return };
        if let Err(e) = tx.try_send(event) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    debug!("block log: channel full, dropping event");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    debug!("block log: writer closed, dropping event");
                }
            }
        }
    }
}

impl Default for BlockLogger {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Current wall-clock time as milliseconds since the Unix epoch.
///
/// Falls back to 0 if the system clock is before 1970 — which can only
/// happen if the system clock is badly misconfigured, and losing a
/// single timestamp is not worth a panic at a block site.
pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
