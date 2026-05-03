//! Tests for `sni_proxy::bypass_tcp`. `BypassTcpConfig`,
//! `handle_connection_at`, and the `RuleSet`/`IpRule`/`AccessRule`
//! types are all part of the public API — no `__test_internals`
//! wrappers needed.

use sni_proxy::block_log::BlockLogger;
use sni_proxy::bypass_tcp::{handle_connection_at, BypassTcpConfig};
use sni_proxy::connector::DirectConnector;
use sni_proxy::dns_cache::DnsCache;
use sni_proxy::policy::{AccessRule, BypassProtocol, IpRule, Mechanism, RuleSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
