//! Tests for `sni_proxy::bypass_tcp`. `BypassTcpConfig`,
//! `handle_connection_at`, and the `RuleSet`/`IpRule`/`AccessRule`
//! types are all part of the public API. The private `WriteCounter`
//! adapter is reached through `__test_internals::write_counter`.

use sni_proxy::block_log::BlockLogger;
use sni_proxy::bypass_tcp::__test_internals::{tcp_info_for_test, write_counter};
use sni_proxy::bypass_tcp::{handle_connection_at, BypassTcpConfig};
use sni_proxy::connector::DirectConnector;
use sni_proxy::dns_cache::DnsCache;
use sni_proxy::policy::{AccessRule, BypassProtocol, IpRule, Mechanism, RuleSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Make a RuleSet containing a single bypass rule for the given
/// host/proto/port — the common shape in these tests.
fn single_bypass_ruleset(host: &str, proto: BypassProtocol, port: u16) -> Arc<RuleSet> {
    Arc::new(RuleSet::new(vec![AccessRule {
        hostname: host.to_string(),
        path_prefix: None,
        methods: None,
        mechanism: Mechanism::Bypass { protocol: proto, port },
    }]))
}

#[tokio::test]
async fn allowed_host_is_dialed_and_bytes_splice() {
    // Mock upstream echoes whatever it receives once.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (mut s, _) = upstream.accept().await.unwrap();
        let mut got = vec![0u8; 5];
        s.read_exact(&mut got).await.unwrap();
        s.write_all(&got).await.unwrap();
        got
    });

    // Build a client TcpStream + its mirror in the same manner
    // mitm.rs tests do — bind a listener, connect to it, use the
    // accepted half as the input to the relay.
    let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair.local_addr().unwrap();
    let (accept_res, connect_res) = tokio::join!(
        pair.accept(),
        TcpStream::connect(pair_addr),
    );
    let (server_side, _) = accept_res.unwrap();
    let mut client_side = connect_res.unwrap();

    // Populate the cache so the reverse lookup succeeds. Using
    // "localhost" as the stored hostname lets `DirectConnector`
    // actually reach our mock upstream — tests don't run a real
    // DNS stub, so we need a name the host's resolver can
    // handle. The relay's dial uses the hostname, not the IP.
    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "localhost",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        StdDuration::from_secs(60),
    );

    let config = BypassTcpConfig {
        port: upstream_port,
        rules: single_bypass_ruleset("localhost", BypassProtocol::Tcp, upstream_port),
        cache,
        connector: Arc::new(DirectConnector),
        block_log: BlockLogger::disabled(),
    };

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let relay = tokio::spawn(async move {
        let _ = handle_connection_at(
            server_side,
            client_addr,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream_port,
            &config,
        )
        .await;
    });

    client_side.write_all(b"hello").await.unwrap();
    let mut echo = [0u8; 5];
    tokio::time::timeout(
        StdDuration::from_secs(2),
        client_side.read_exact(&mut echo),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&echo, b"hello");
    drop(client_side);

    tokio::time::timeout(StdDuration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();

    let received = upstream_task.await.unwrap();
    assert_eq!(&received, b"hello");
}

#[tokio::test]
async fn dst_ip_not_in_cache_is_denied_without_dial() {
    // Rule exists for svc.example, but cache is empty — the
    // child connected to a literal IP we never handed out. The
    // relay must NOT attempt an upstream dial; we verify that
    // by pointing the "upstream" at a port we never bind.
    let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair.local_addr().unwrap();
    let (accept_res, connect_res) =
        tokio::join!(pair.accept(), TcpStream::connect(pair_addr),);
    let (server_side, _) = accept_res.unwrap();
    let client_side = connect_res.unwrap();

    let cache = Arc::new(DnsCache::new()); // empty
    let config = BypassTcpConfig {
        port: 9999,
        rules: single_bypass_ruleset("svc.example", BypassProtocol::Tcp, 9999),
        cache,
        connector: Arc::new(DirectConnector),
        block_log: BlockLogger::disabled(),
    };
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let fake_dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let relay = tokio::spawn(async move {
        handle_connection_at(server_side, client_addr, fake_dst, 9999, &config).await
    });
    let result = tokio::time::timeout(StdDuration::from_secs(2), relay)
        .await
        .expect("relay did not return promptly on deny")
        .unwrap();
    assert!(result.is_ok(), "relay should return Ok on deny, not error");
    drop(client_side);
}

#[tokio::test]
async fn host_in_cache_but_wrong_port_is_denied() {
    // Rule is for port 88. Traffic arrived at port 389. Deny.
    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "kdc.example",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        StdDuration::from_secs(60),
    );

    let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair.local_addr().unwrap();
    let (accept_res, connect_res) =
        tokio::join!(pair.accept(), TcpStream::connect(pair_addr));
    let (server_side, _) = accept_res.unwrap();
    let _client_side = connect_res.unwrap();

    let config = BypassTcpConfig {
        // Listener port doesn't match the rule's 88.
        port: 389,
        rules: single_bypass_ruleset("kdc.example", BypassProtocol::Tcp, 88),
        cache,
        connector: Arc::new(DirectConnector),
        block_log: BlockLogger::disabled(),
    };
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let result = handle_connection_at(
        server_side,
        client_addr,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        389,
        &config,
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn ip_rule_authorizes_when_dns_cache_is_empty() {
    // No cache entry, but an `ip = "…"` rule — the relay must
    // still dial. Proves the literal-IP fallback works.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (mut s, _) = upstream.accept().await.unwrap();
        let mut got = [0u8; 2];
        s.read_exact(&mut got).await.unwrap();
        s.write_all(&got).await.unwrap();
        got
    });

    let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair.local_addr().unwrap();
    let (accept_res, connect_res) =
        tokio::join!(pair.accept(), TcpStream::connect(pair_addr));
    let (server_side, _) = accept_res.unwrap();
    let mut client_side = connect_res.unwrap();

    let cache = Arc::new(DnsCache::new()); // empty — forces IP-rule path
    let rules = Arc::new(
        RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            mechanism: Mechanism::Bypass {
                protocol: BypassProtocol::Tcp,
                port: upstream_port,
            },
        }]),
    );
    let config = BypassTcpConfig {
        port: upstream_port,
        rules,
        cache,
        connector: Arc::new(DirectConnector),
        block_log: BlockLogger::disabled(),
    };

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let relay = tokio::spawn(async move {
        let _ = handle_connection_at(
            server_side,
            client_addr,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream_port,
            &config,
        )
        .await;
    });

    client_side.write_all(b"hi").await.unwrap();
    let mut echo = [0u8; 2];
    tokio::time::timeout(StdDuration::from_secs(2), client_side.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"hi");
    drop(client_side);
    tokio::time::timeout(StdDuration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&upstream_task.await.unwrap(), b"hi");
}

#[tokio::test]
async fn udp_rule_does_not_match_tcp_listener() {
    // Same host + same port, but UDP rule vs TCP listener.
    // The relay must not cross-over protocols.
    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "kdc.example",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        StdDuration::from_secs(60),
    );

    let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair.local_addr().unwrap();
    let (accept_res, connect_res) =
        tokio::join!(pair.accept(), TcpStream::connect(pair_addr));
    let (server_side, _) = accept_res.unwrap();
    let _client_side = connect_res.unwrap();

    let config = BypassTcpConfig {
        port: 88,
        rules: single_bypass_ruleset("kdc.example", BypassProtocol::Udp, 88),
        cache,
        connector: Arc::new(DirectConnector),
        block_log: BlockLogger::disabled(),
    };
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let result = handle_connection_at(
        server_side,
        client_addr,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        88,
        &config,
    )
    .await;
    assert!(result.is_ok());
}

// --- WriteCounter tests ----------------------------------------------
//
// Surface check for the adapter used to log per-direction byte
// totals on the splice path even when `copy_bidirectional` returns
// an error. We exercise it through the public AsyncRead/AsyncWrite
// surface so the test matches how the real callers use it.

#[tokio::test]
async fn write_counter_ticks_on_successful_writes() {
    // duplex(64) is an in-memory pair that's both AsyncRead +
    // AsyncWrite, matching the trait bound the real call site
    // (TcpStream) carries. We drain the peer in a task so the
    // 64-byte buffer never back-pressures and our writes complete
    // synchronously.
    let (a, b) = tokio::io::duplex(64);
    let drain = tokio::spawn(async move {
        let mut sink = a;
        let mut buf = [0u8; 32];
        let mut total = 0usize;
        while let Ok(n) = sink.read(&mut buf).await {
            if n == 0 {
                break;
            }
            total += n;
        }
        total
    });

    let counter = Arc::new(AtomicU64::new(0));
    let mut wc = write_counter(b, Arc::clone(&counter));
    wc.write_all(&[1, 2, 3, 4]).await.unwrap();
    wc.write_all(&[5, 6]).await.unwrap();
    wc.shutdown().await.unwrap();
    drop(wc);
    assert_eq!(drain.await.unwrap(), 6);
    assert_eq!(
        counter.load(Ordering::Relaxed),
        6,
        "every byte that completes a poll_write must be counted exactly once"
    );
}

#[tokio::test]
async fn write_counter_does_not_count_reads() {
    // Reads must leave the write counter alone — the splice direction
    // accounting only tracks egress through this wrapper.
    let (mut a, b) = tokio::io::duplex(64);
    let counter = Arc::new(AtomicU64::new(0));
    let mut wc = write_counter(b, Arc::clone(&counter));

    a.write_all(&[9, 9, 9]).await.unwrap();
    let mut buf = [0u8; 8];
    let n = wc.read(&mut buf).await.unwrap();
    assert_eq!(n, 3);
    assert_eq!(
        counter.load(Ordering::Relaxed),
        0,
        "reads through the wrapper must not increment the write counter"
    );
}

#[tokio::test]
async fn write_counter_is_zero_when_no_writes_attempted() {
    let (_a, b) = tokio::io::duplex(8);
    let counter = Arc::new(AtomicU64::new(0));
    let _wc = write_counter(b, Arc::clone(&counter));
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn relay_does_not_hang_when_upstream_rsts() {
    // Smoke test for the close-forwarding path: when upstream
    // forcibly RSTs, the relay must finish promptly. This won't
    // catch the FIN-vs-RST distinction (see the
    // shutdown(SHUT_RDWR) fix and its commit message for the
    // kernel-level reasoning), but it does catch the
    // worst-case regression where copy_bidirectional's error
    // path stalls indefinitely instead of returning.
    use std::os::fd::AsRawFd;

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let (s, _) = upstream.accept().await.unwrap();
        tokio::time::sleep(StdDuration::from_millis(20)).await;
        // SO_LINGER 0 + drop forces RST on the wire.
        let std_s = s.into_std().unwrap();
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        unsafe {
            libc::setsockopt(
                std_s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const _ as *const _,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
        drop(std_s);
    });

    let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pair_addr = pair.local_addr().unwrap();
    let (accept_res, connect_res) =
        tokio::join!(pair.accept(), TcpStream::connect(pair_addr));
    let (server_side, _) = accept_res.unwrap();
    let _client_side = connect_res.unwrap();

    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "localhost",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        StdDuration::from_secs(60),
    );
    let config = BypassTcpConfig {
        port: upstream_port,
        rules: single_bypass_ruleset("localhost", BypassProtocol::Tcp, upstream_port),
        cache,
        connector: Arc::new(DirectConnector),
        block_log: BlockLogger::disabled(),
    };

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let relay = tokio::spawn(async move {
        let _ = handle_connection_at(
            server_side,
            client_addr,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream_port,
            &config,
        )
        .await;
    });

    tokio::time::timeout(StdDuration::from_secs(2), relay)
        .await
        .expect("relay must return promptly after upstream RSTs")
        .unwrap();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn tcp_info_reports_established_on_live_loopback_pair() {
    // Surface check for the diagnostic helper used to enrich the
    // splice-end / splice-error log line. The shape we care about:
    //  - returns Some on a live TCP fd (any user can call it — no
    //    root needed)
    //  - state is ESTABLISHED while the peer is still connected
    //  - last_data_recv is small (we just received bytes)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"hi").await.unwrap();
        // Keep the connection open so TCP_INFO on the client side
        // still sees ESTABLISHED when we read it below.
        tokio::time::sleep(StdDuration::from_millis(200)).await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await.unwrap();

    use std::os::fd::AsRawFd;
    let (state, last_recv_ms) =
        tcp_info_for_test(client.as_raw_fd()).expect("TCP_INFO must work on a live TCP fd");
    assert_eq!(state, "ESTABLISHED");
    assert!(
        last_recv_ms < 1000,
        "we just read bytes; tcpi_last_data_recv ({last_recv_ms}ms) should be small"
    );

    drop(client);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_info_returns_none_on_non_tcp_fd() {
    // Helper must degrade gracefully when handed a non-TCP fd —
    // the splice-end log path tolerates None and substitutes "?" /
    // u32::MAX rather than crashing.
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open("/dev/null").unwrap();
    assert!(
        tcp_info_for_test(f.as_raw_fd()).is_none(),
        "TCP_INFO on a non-TCP fd must return None"
    );
}

#[tokio::test]
async fn write_counter_accumulates_across_many_short_writes() {
    // Diagnostic value lives in seeing partial bytes-before-RST,
    // so the count must accumulate across multiple separate
    // poll_writes rather than being reset per call.
    let (a, b) = tokio::io::duplex(1024);
    let drain = tokio::spawn(async move {
        let mut sink = a;
        let mut buf = [0u8; 256];
        while let Ok(n) = sink.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    });

    let counter = Arc::new(AtomicU64::new(0));
    let mut wc = write_counter(b, Arc::clone(&counter));
    for _ in 0..100 {
        wc.write_all(&[42u8]).await.unwrap();
    }
    wc.shutdown().await.unwrap();
    drop(wc);
    drain.await.unwrap();
    assert_eq!(counter.load(Ordering::Relaxed), 100);
}
