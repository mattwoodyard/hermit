//! End-to-end tests for the block-event log.
//!
//! Each test exercises a different proxy surface (DNS, HTTP proxy) and
//! asserts that a denial produces a JSON line in the configured file.

use std::collections::BTreeSet;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use sni_proxy::block_log::BlockLogger;
use sni_proxy::connector::DirectConnector;
use sni_proxy::dns::DnsServer;
use sni_proxy::http_proxy::{self, HttpProxyConfig};
use sni_proxy::policy::{AccessRule, AllowList, RuleSet};

/// Read the block log file to a vector of parsed JSON objects.
async fn read_events(path: &std::path::Path) -> Vec<serde_json::Value> {
    let text = tokio::fs::read_to_string(path).await.unwrap_or_default();
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("block log line must be valid JSON"))
        .collect()
}

/// Build a DNS A-query packet for `name`.
fn dns_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes()); // qtype = A
    buf.extend_from_slice(&1u16.to_be_bytes()); // qclass = IN
    buf
}

#[tokio::test]
async fn dns_deny_writes_block_event() {
    let log_file = NamedTempFile::new().unwrap();
    let block_log = BlockLogger::to_file(log_file.path()).await.unwrap();

    // Allowlist contains only "ok.example" — anything else is denied.
    let policy = Arc::new(AllowList::new(["ok.example".into()].into()));
    let server = Arc::new(DnsServer::new(policy).with_block_log(block_log));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let server_clone = Arc::clone(&server);
    let server_handle = tokio::spawn(async move {
        let _ = server_clone.run(socket).await;
    });

    // Send a denied query.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&dns_a_query(1, "blocked.example"), server_addr)
        .await
        .unwrap();

    // Read the refused response to synchronise with the server having
    // processed the packet.
    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("DNS server must respond");

    // Give the writer task a moment to flush.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let events = read_events(log_file.path()).await;
    assert_eq!(events.len(), 1, "expected exactly one block event, got: {:?}", events);
    let e = &events[0];
    assert_eq!(e["type"], "dns");
    assert_eq!(e["hostname"], "blocked.example");
    assert!(e["reason"].as_str().unwrap().contains("allowlist"));
    assert!(e["time_unix_ms"].as_u64().unwrap() > 0);

    server_handle.abort();
}

#[tokio::test]
async fn dns_allow_does_not_emit_block_event() {
    let log_file = NamedTempFile::new().unwrap();
    let block_log = BlockLogger::to_file(log_file.path()).await.unwrap();

    let policy = Arc::new(AllowList::new(["ok.example".into()].into()));
    let server = Arc::new(DnsServer::new(policy).with_block_log(block_log));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let server_clone = Arc::clone(&server);
    let server_handle = tokio::spawn(async move {
        let _ = server_clone.run(socket).await;
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&dns_a_query(2, "ok.example"), server_addr)
        .await
        .unwrap();

    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("DNS server must respond");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let events = read_events(log_file.path()).await;
    assert!(
        events.is_empty(),
        "allowed query must not produce block events, got: {:?}",
        events
    );

    server_handle.abort();
}

#[tokio::test]
async fn http_proxy_deny_writes_block_event() {
    let log_file = NamedTempFile::new().unwrap();
    let block_log = BlockLogger::to_file(log_file.path()).await.unwrap();

    // Only "allowed.example" is permitted — a Host: blocked.example
    // request will be denied.
    let rules = vec![AccessRule::host_only("allowed.example")];
    let config = Arc::new(HttpProxyConfig {
        policy: Arc::new(RuleSet::new(rules)),
        connector: Arc::new(DirectConnector),
        upstream_port: 80,
        allowed_connect_ports: BTreeSet::from([443]),
        block_log,
        access_log: BlockLogger::disabled(),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = http_proxy::run(listener, config).await;
    });

    // Send a plain HTTP/1.1 request for a denied host.
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"GET /secret HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .await
        .unwrap();

    // The proxy is supposed to write a 403 and close.
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"),
        "expected 403, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    // Wait briefly for the writer task to flush.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let events = read_events(log_file.path()).await;
    assert_eq!(events.len(), 1, "expected one block event, got: {:?}", events);
    let e = &events[0];
    assert_eq!(e["type"], "http");
    assert_eq!(e["hostname"], "blocked.example");
    assert_eq!(e["method"], "GET");
    assert_eq!(e["path"], "/secret");
    assert!(e["client"].as_str().unwrap().starts_with("127.0.0.1:"));
}

#[tokio::test]
async fn http_proxy_missing_host_emits_block_event() {
    let log_file = NamedTempFile::new().unwrap();
    let block_log = BlockLogger::to_file(log_file.path()).await.unwrap();

    let rules = vec![AccessRule::host_only("allowed.example")];
    let config = Arc::new(HttpProxyConfig {
        policy: Arc::new(RuleSet::new(rules)),
        connector: Arc::new(DirectConnector),
        upstream_port: 80,
        allowed_connect_ports: BTreeSet::from([443]),
        block_log,
        access_log: BlockLogger::disabled(),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = http_proxy::run(listener, config).await;
    });

    // HTTP/1.0 request with no Host header — legal wire-format, but
    // hermit's policy requires a Host to check, so the request is blocked.
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut sink),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let events = read_events(log_file.path()).await;
    assert_eq!(events.len(), 1, "expected one block event, got: {:?}", events);
    assert_eq!(events[0]["type"], "http_no_host");
}

#[tokio::test]
async fn disabled_logger_writes_nothing_even_on_block() {
    // Same scenario as `http_proxy_deny_writes_block_event`, but with a
    // disabled logger. The point is to verify that wiring a logger into
    // every proxy doesn't accidentally impose any disk IO on the default
    // "no file configured" path.
    let rules = vec![AccessRule::host_only("allowed.example")];
    let config = Arc::new(HttpProxyConfig {
        policy: Arc::new(RuleSet::new(rules)),
        connector: Arc::new(DirectConnector),
        upstream_port: 80,
        allowed_connect_ports: BTreeSet::from([443]),
        block_log: BlockLogger::disabled(),
        access_log: BlockLogger::disabled(),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = http_proxy::run(listener, config).await;
    });

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .await
        .unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut sink),
    )
    .await;

    // No assertion on filesystem — the assertion is that this test
    // reaches the end without panic/hang, and that the proxy returned
    // a 403 (i.e., the block path executed end-to-end with a disabled
    // logger).
    assert!(String::from_utf8_lossy(&sink).starts_with("HTTP/1.1 403"));
}

#[tokio::test]
async fn http_proxy_connect_tunnel_splices_bytes() {
    // Exercises the CONNECT path that HTTPS_PROXY-aware clients use.
    // We stand up a bogus "origin" TCP server, let the proxy tunnel
    // to it, and assert bytes flow in both directions. No real TLS —
    // CONNECT splices raw bytes.
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();

    // The origin echoes whatever it receives (single read/write is
    // enough for a regression-catching signal).
    tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.unwrap();
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });

    let rules = vec![AccessRule::host_only("127.0.0.1")];
    let config = Arc::new(HttpProxyConfig {
        policy: Arc::new(RuleSet::new(rules)),
        connector: Arc::new(DirectConnector),
        upstream_port: 80,
        // Whitelist the dynamic origin port so the splice path is
        // exercised without tripping the new CONNECT-port guard.
        allowed_connect_ports: BTreeSet::from([origin_addr.port()]),
        block_log: BlockLogger::disabled(),
        access_log: BlockLogger::disabled(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = http_proxy::run(listener, config).await;
    });

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        origin_addr.port()
    );
    client.write_all(req.as_bytes()).await.unwrap();

    // Read the "200 Connection Established" status line + headers.
    let mut status = [0u8; 64];
    let n = client.read(&mut status).await.unwrap();
    let status = std::str::from_utf8(&status[..n]).unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected 200, got: {status:?}"
    );

    client.write_all(b"ping!").await.unwrap();
    let mut echo = [0u8; 5];
    tokio::time::timeout(std::time::Duration::from_secs(2),
        client.read_exact(&mut echo)).await.unwrap().unwrap();
    assert_eq!(&echo, b"ping!");
}

#[tokio::test]
async fn http_proxy_connect_denied_writes_block_event_and_403() {
    let log_file = NamedTempFile::new().unwrap();
    let block_log = BlockLogger::to_file(log_file.path()).await.unwrap();

    // Rule allows only "allowed.example"; CONNECT to blocked.example
    // must be denied *before* we try to open any upstream socket.
    let rules = vec![AccessRule::host_only("allowed.example")];
    let config = Arc::new(HttpProxyConfig {
        policy: Arc::new(RuleSet::new(rules)),
        connector: Arc::new(DirectConnector),
        upstream_port: 80,
        allowed_connect_ports: BTreeSet::from([443]),
        block_log,
        access_log: BlockLogger::disabled(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = http_proxy::run(listener, config).await;
    });

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"),
        "expected 403, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let events = read_events(log_file.path()).await;
    assert_eq!(events.len(), 1, "expected one block event, got: {events:?}");
    assert_eq!(events[0]["type"], "http");
    assert_eq!(events[0]["method"], "CONNECT");
    assert_eq!(events[0]["hostname"], "blocked.example");
}

#[tokio::test]
async fn http_proxy_connect_to_disallowed_port_blocks() {
    // An allow-listed host on a non-HTTPS port (e.g. ssh on 22) must
    // be denied even though the hostname rule would otherwise permit
    // it. Otherwise a malicious build could use any allow-listed
    // hostname as a generic egress to ssh/smtp/etc.
    let log_file = NamedTempFile::new().unwrap();
    let block_log = BlockLogger::to_file(log_file.path()).await.unwrap();

    let rules = vec![AccessRule::host_only("allowed.example")];
    let config = Arc::new(HttpProxyConfig {
        policy: Arc::new(RuleSet::new(rules)),
        connector: Arc::new(DirectConnector),
        upstream_port: 80,
        allowed_connect_ports: BTreeSet::from([443]),
        block_log,
        access_log: BlockLogger::disabled(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = http_proxy::run(listener, config).await;
    });

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT allowed.example:22 HTTP/1.1\r\nHost: allowed.example:22\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"),
        "expected 403, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let events = read_events(log_file.path()).await;
    assert_eq!(events.len(), 1, "expected one block event, got: {events:?}");
    let e = &events[0];
    assert_eq!(e["type"], "http");
    assert_eq!(e["method"], "CONNECT");
    assert_eq!(e["hostname"], "allowed.example");
    assert!(
        e["reason"].as_str().unwrap().contains("port 22"),
        "block reason should name the bad port: {e:?}"
    );
}
