//! Tests for `sni_proxy::learn_observer`. The config + accept loop
//! are public; the dns_cache helper is exercised through its own
//! public API. No `__test_internals` wrappers needed.
//!
//! NOTE: `observer_logs_event_without_original_dst` is a pre-existing
//! environmental failure on some loopback setups — moved verbatim.

use sni_proxy::block_log::BlockLogger;
use sni_proxy::dns_cache::DnsCache;
use sni_proxy::learn_observer::{run, LearnObserverConfig};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// End-to-end-ish: a connection to the observer (without
/// DNAT, so SO_ORIGINAL_DST is not set) still produces an
/// access event so the workflow degrades gracefully.
#[tokio::test]
async fn observer_logs_event_without_original_dst() {
    let log_file = NamedTempFile::new().unwrap();
    let access_log = BlockLogger::to_file(log_file.path()).await.unwrap();

    let config = Arc::new(LearnObserverConfig {
        dns_cache: Arc::new(DnsCache::new()),
        access_log,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let observer_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = run(listener, config).await;
    });

    // The test connects directly (no DNAT) so the observer
    // sees a connection but no original-dst. The event is
    // still recorded, with `port = None` and a synthetic
    // `ip:unknown` hostname.
    let mut client = TcpStream::connect(observer_addr).await.unwrap();
    let _ = client.write_all(b"x").await;
    // Connection closes promptly — the observer drops it.
    drop(client);

    tokio::time::sleep(StdDuration::from_millis(150)).await;

    let raw = tokio::fs::read_to_string(log_file.path()).await.unwrap();
    let lines: Vec<&str> = raw.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "expected one observe event, got: {raw}");
    let event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event["type"], "tcp_observe");
    assert_eq!(event["hostname"], "ip:unknown");
    // `port: None` is skip-serialized so the field is absent.
    assert!(event.get("port").is_none() || event["port"].is_null());
}

#[tokio::test]
async fn observer_uses_dns_cache_for_reverse_lookup() {
    // Without SO_ORIGINAL_DST we can't exercise the IP →
    // hostname path end-to-end, but the lookup helper is
    // pure. This test pins the cache contract the observer
    // depends on so a future change to DnsCache::reverse
    // semantics surfaces here.
    let cache = DnsCache::new();
    cache.insert(
        "api.example",
        "10.0.0.5".parse().unwrap(),
        StdDuration::from_secs(60),
    );
    assert_eq!(
        cache.reverse("10.0.0.5".parse().unwrap()).as_deref(),
        Some("api.example"),
    );
}
