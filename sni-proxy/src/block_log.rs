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
    pub async fn to_file(path: &Path) -> Result<Self> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncReadExt;

    /// Build a minimal test event of a given kind.
    fn evt(kind: BlockKind) -> BlockEvent {
        BlockEvent {
            time_unix_ms: 1700000000000,
            kind,
            client: Some("127.0.0.1:1234".to_string()),
            hostname: Some("example.com".to_string()),
            method: None,
            path: None,
            reason: None,
        }
    }

    #[tokio::test]
    async fn disabled_logger_is_noop() {
        // A disabled logger must accept events without error and without
        // touching the filesystem — otherwise opt-out would still cost
        // disk IO.
        let log = BlockLogger::disabled();
        log.log(evt(BlockKind::Dns));
        // No panic, no side effect: success is silence.
    }

    #[tokio::test]
    async fn enabled_logger_writes_json_line() {
        let tmp = NamedTempFile::new().unwrap();
        let log = BlockLogger::to_file(tmp.path()).await.unwrap();
        log.log(evt(BlockKind::Dns));
        // Give the writer task a moment to flush.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut contents = String::new();
        tokio::fs::File::open(tmp.path())
            .await
            .unwrap()
            .read_to_string(&mut contents)
            .await
            .unwrap();

        assert!(contents.ends_with('\n'), "each event must be newline-terminated");
        let parsed: serde_json::Value =
            serde_json::from_str(contents.trim()).expect("must be valid JSON");
        assert_eq!(parsed["type"], "dns");
        assert_eq!(parsed["hostname"], "example.com");
        assert_eq!(parsed["client"], "127.0.0.1:1234");
    }

    #[tokio::test]
    async fn multiple_events_one_per_line() {
        let tmp = NamedTempFile::new().unwrap();
        let log = BlockLogger::to_file(tmp.path()).await.unwrap();
        log.log(evt(BlockKind::Dns));
        log.log(evt(BlockKind::Https));
        log.log(evt(BlockKind::Http));
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let contents = tokio::fs::read_to_string(tmp.path()).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
        assert!(lines[0].contains("\"type\":\"dns\""));
        assert!(lines[1].contains("\"type\":\"https\""));
        assert!(lines[2].contains("\"type\":\"http\""));
    }

    #[tokio::test]
    async fn append_does_not_truncate_existing() {
        let tmp = NamedTempFile::new().unwrap();
        tokio::fs::write(tmp.path(), b"pre-existing\n").await.unwrap();

        let log = BlockLogger::to_file(tmp.path()).await.unwrap();
        log.log(evt(BlockKind::Dns));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let contents = tokio::fs::read_to_string(tmp.path()).await.unwrap();
        assert!(contents.starts_with("pre-existing\n"), "existing content preserved");
        assert!(contents.lines().count() >= 2);
    }

    #[test]
    fn now_ms_is_plausible() {
        // Guard against a regression where we accidentally return 0 or
        // a pre-epoch value.
        let t = now_unix_ms();
        assert!(t > 1_700_000_000_000, "clock appears to be wildly wrong: {t}");
    }

    #[test]
    fn default_is_disabled() {
        // The `Default` impl is used when proxy configs don't explicitly
        // wire in a logger — it must be the no-op variant.
        let log = BlockLogger::default();
        log.log(evt(BlockKind::Dns));
    }

    #[test]
    fn block_kind_wire_names_are_stable() {
        // Downstream tooling depends on these exact strings. A rename
        // here is a breaking change and must be intentional.
        let cases = [
            (BlockKind::Dns, "\"dns\""),
            (BlockKind::TlsNoSni, "\"tls_no_sni\""),
            (BlockKind::TlsHostname, "\"tls_hostname\""),
            (BlockKind::HttpNoHost, "\"http_no_host\""),
            (BlockKind::Http, "\"http\""),
            (BlockKind::Https, "\"https\""),
        ];
        for (kind, expected) in cases {
            assert_eq!(serde_json::to_string(&kind).unwrap(), expected);
        }
    }

    #[test]
    fn missing_fields_are_omitted_from_json() {
        // `skip_serializing_if` matters: a `null` value in the log file
        // would be noise. An event with only the required fields should
        // produce a tight object.
        let evt = BlockEvent {
            time_unix_ms: 42,
            kind: BlockKind::Dns,
            client: None,
            hostname: None,
            method: None,
            path: None,
            reason: None,
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(!s.contains("null"), "no null fields expected, got: {s}");
        assert!(!s.contains("client"));
        assert!(!s.contains("hostname"));
    }
}
