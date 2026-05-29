//! Tests for `sni_proxy::bypass_udp`. The internal helpers used here
//! (`authorize`, `handle_datagram`, `recv_with_orig_dst`,
//! `enable_recv_orig_dst`, `extract_orig_dst`, `RecvPacket`,
//! `Sessions`, `IpFamily`) were promoted from `pub(crate)` to `pub`
//! with `#[doc(hidden)]` for test access.

#![allow(private_interfaces)]

use sni_proxy::block_log::BlockLogger;
use sni_proxy::bypass_udp::{
    authorize, enable_recv_orig_dst, extract_orig_dst, handle_datagram, recv_with_orig_dst,
    BypassUdpConfig, IpFamily, RecvPacket, Sessions,
};
use sni_proxy::dns_cache::DnsCache;
use sni_proxy::policy::{
    AccessRule, BypassProtocol, IpRule, Mechanism, RuleSet,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

fn single_bypass_ruleset(host: &str, port: u16) -> Arc<RuleSet> {
    Arc::new(RuleSet::new(vec![AccessRule {
        hostname: host.to_string(),
        path_prefix: None,
        methods: None,
        mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port },
    }]))
}

fn sample_config(port: u16, cache: Arc<DnsCache>, rules: Arc<RuleSet>) -> BypassUdpConfig {
    sample_config_with_family(port, cache, rules, IpFamily::V4)
}

fn sample_config_with_family(
    port: u16,
    cache: Arc<DnsCache>,
    rules: Arc<RuleSet>,
    family: IpFamily,
) -> BypassUdpConfig {
    BypassUdpConfig {
        port,
        family,
        rules,
        cache,
        block_log: BlockLogger::disabled(),
    }
}

#[tokio::test]
async fn authorize_allows_matching_rule() {
    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "kdc.example",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        Duration::from_secs(60),
    );
    let cfg = sample_config(
        88,
        Arc::clone(&cache),
        single_bypass_ruleset("kdc.example", 88),
    );
    let src: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    let dst: SocketAddr = "203.0.113.10:88".parse().unwrap();
    assert!(authorize(&cfg, &src, dst).await);
}

#[tokio::test]
async fn authorize_denies_when_ip_not_in_cache() {
    // Empty cache → literal-IP connect, must be denied.
    let cache = Arc::new(DnsCache::new());
    let cfg = sample_config(
        88,
        Arc::clone(&cache),
        single_bypass_ruleset("kdc.example", 88),
    );
    let src: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    let dst: SocketAddr = "203.0.113.10:88".parse().unwrap();
    assert!(!authorize(&cfg, &src, dst).await);
}

#[tokio::test]
async fn authorize_accepts_ip_rule_when_cache_empty() {
    // No DNS cache entry — the IP rule is the only thing
    // authorizing the flow. Without it the packet would be
    // denied.
    let cache = Arc::new(DnsCache::new());
    let rules = Arc::new(
        RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            mechanism: Mechanism::Bypass {
                protocol: BypassProtocol::Udp,
                port: 88,
            },
        }]),
    );
    let cfg = BypassUdpConfig {
        port: 88,
        family: IpFamily::V4,
        rules,
        cache,
        block_log: BlockLogger::disabled(),
    };
    let src: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    let dst: SocketAddr = "203.0.113.10:88".parse().unwrap();
    assert!(authorize(&cfg, &src, dst).await);
}

#[tokio::test]
async fn authorize_denies_wrong_port() {
    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "kdc.example",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        Duration::from_secs(60),
    );
    // Rule is for port 88; relay is listening on 99 (mismatch).
    let cfg = sample_config(
        99,
        Arc::clone(&cache),
        single_bypass_ruleset("kdc.example", 88),
    );
    let src: SocketAddr = "127.0.0.1:10000".parse().unwrap();
    let dst: SocketAddr = "203.0.113.10:99".parse().unwrap();
    assert!(!authorize(&cfg, &src, dst).await);
}

#[tokio::test]
async fn recv_with_orig_dst_pulls_the_expected_cmsg() {
    // No DNAT staged, so `IP_ORIGDSTADDR` reports the addr we
    // actually bound — which is still enough to confirm that
    // cmsg parsing works end-to-end on this kernel.
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    enable_recv_orig_dst(listener.as_raw_fd(), IpFamily::V4).unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let listener_fd = listener.as_raw_fd();

    // Wrap in AsyncFd so we can async-wait for readiness.
    let async_fd = AsyncFd::new(listener).unwrap();

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    sender.send_to(b"hello", listener_addr).await.unwrap();

    let mut guard = async_fd.readable().await.unwrap();
    let pkt = loop {
        match recv_with_orig_dst(listener_fd, IpFamily::V4).unwrap() {
            Some(p) => break p,
            None => {
                guard.clear_ready();
                guard = async_fd.readable().await.unwrap();
            }
        }
    };

    assert_eq!(pkt.data, b"hello");
    assert_eq!(pkt.src, sender_addr);
    // On a non-DNAT'd socket the cmsg echoes the local bind.
    assert_eq!(pkt.orig_dst, Some(listener_addr));
}

#[tokio::test]
async fn recv_with_orig_dst_v6_pulls_the_expected_cmsg() {
    // IPv6 counterpart. Same structure, but IPPROTO_IPV6 +
    // IPV6_ORIGDSTADDR. Binding to `[::1]` (not `[::]`) keeps
    // the listener v6-only without any socket-option dance —
    // v4 traffic simply never routes here.
    let listener = std::net::UdpSocket::bind("[::1]:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    enable_recv_orig_dst(listener.as_raw_fd(), IpFamily::V6).unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let listener_fd = listener.as_raw_fd();
    let async_fd = AsyncFd::new(listener).unwrap();

    let sender = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let sender_addr = sender.local_addr().unwrap();
    sender.send_to(b"hello v6", listener_addr).await.unwrap();

    let mut guard = async_fd.readable().await.unwrap();
    let pkt = loop {
        match recv_with_orig_dst(listener_fd, IpFamily::V6).unwrap() {
            Some(p) => break p,
            None => {
                guard.clear_ready();
                guard = async_fd.readable().await.unwrap();
            }
        }
    };

    assert_eq!(pkt.data, b"hello v6");
    assert_eq!(pkt.src, sender_addr);
    assert_eq!(pkt.orig_dst, Some(listener_addr));
}

#[tokio::test]
async fn full_relay_round_trips_through_a_mock_upstream() {
    // End-to-end: spawn handle_datagram for a packet whose
    // orig_dst points at a real upstream we control. Then feed
    // a second packet on the same flow to verify session reuse.
    let _ = tracing_subscriber::fmt::try_init();

    // Mock "real upstream" that echoes anything with "ACK: " prefix.
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let (n, from) = match upstream.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let reply = [b"ACK: ".as_slice(), &buf[..n]].concat();
            let _ = upstream.send_to(&reply, from).await;
        }
    });

    // Listener bound on a loopback ephemeral port; we hand its
    // fd to the relay as if it had arrived via SCM_RIGHTS.
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    enable_recv_orig_dst(listener.as_raw_fd(), IpFamily::V4).unwrap();
    let listener_fd = listener.as_raw_fd();

    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "localhost",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_secs(60),
    );
    let config = Arc::new(sample_config(
        upstream_addr.port(),
        Arc::clone(&cache),
        single_bypass_ruleset("localhost", upstream_addr.port()),
    ));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    // Stand in for "the child" — when we call handle_datagram
    // the upstream reply will be sent via sendto_listener to
    // this address; so we bind a socket here and read from it.
    let child = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let child_addr = child.local_addr().unwrap();

    let pkt = RecvPacket {
        data: b"ping".to_vec(),
        src: child_addr,
        orig_dst: Some(upstream_addr),
    };
    handle_datagram(
        listener_fd,
        IpFamily::V4,
        pkt,
        Arc::clone(&config),
        Arc::clone(&sessions),
    )
    .await;

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(
        Duration::from_secs(2),
        child.recv_from(&mut buf),
    )
    .await
    .expect("child never received relay reply")
    .unwrap();
    assert_eq!(&buf[..n], b"ACK: ping");

    // Session reuse: second datagram from the same src must
    // land on the same outbound socket.
    assert_eq!(sessions.lock().await.len(), 1);
    let pkt2 = RecvPacket {
        data: b"pong".to_vec(),
        src: child_addr,
        orig_dst: Some(upstream_addr),
    };
    handle_datagram(
        listener_fd,
        IpFamily::V4,
        pkt2,
        Arc::clone(&config),
        Arc::clone(&sessions),
    )
    .await;
    let (n, _) = tokio::time::timeout(
        Duration::from_secs(2),
        child.recv_from(&mut buf),
    )
    .await
    .expect("second relay reply never arrived")
    .unwrap();
    assert_eq!(&buf[..n], b"ACK: pong");
    assert_eq!(sessions.lock().await.len(), 1);
}

#[tokio::test]
async fn full_relay_round_trips_v6() {
    // IPv6 counterpart of the v4 round-trip test above. The
    // whole path — session creation, outbound UDP bind, reply
    // via raw sendto on the v6 listener — exercises the IPv6
    // branches of each helper.
    let upstream = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let (n, from) = match upstream.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let reply = [b"v6ACK: ".as_slice(), &buf[..n]].concat();
            let _ = upstream.send_to(&reply, from).await;
        }
    });

    let listener = std::net::UdpSocket::bind("[::1]:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    enable_recv_orig_dst(listener.as_raw_fd(), IpFamily::V6).unwrap();
    let listener_fd = listener.as_raw_fd();

    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "ip6-localhost",
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        Duration::from_secs(60),
    );
    let config = Arc::new(sample_config_with_family(
        upstream_addr.port(),
        Arc::clone(&cache),
        single_bypass_ruleset("ip6-localhost", upstream_addr.port()),
        IpFamily::V6,
    ));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    let child = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let child_addr = child.local_addr().unwrap();

    let pkt = RecvPacket {
        data: b"ping".to_vec(),
        src: child_addr,
        orig_dst: Some(upstream_addr),
    };
    handle_datagram(
        listener_fd,
        IpFamily::V6,
        pkt,
        Arc::clone(&config),
        Arc::clone(&sessions),
    )
    .await;

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(
        Duration::from_secs(2),
        child.recv_from(&mut buf),
    )
    .await
    .expect("v6 child never received relay reply")
    .unwrap();
    assert_eq!(&buf[..n], b"v6ACK: ping");
    assert_eq!(sessions.lock().await.len(), 1);
}

#[tokio::test]
async fn two_concurrent_first_packets_coalesce_to_one_session() {
    // Race regression: two datagrams from the same src arriving
    // back-to-back used to both find no session, both bind a
    // fresh outbound, both insert — with the second clobbering
    // the first and orphaning its outbound + reader. After the
    // fix the second caller waits on the sessions lock, takes
    // the fast path on the entry the first one installed, and
    // both packets egress from the *same* upstream-side source
    // port.
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    enable_recv_orig_dst(listener.as_raw_fd(), IpFamily::V4).unwrap();
    let listener_fd = listener.as_raw_fd();

    let cache = Arc::new(DnsCache::new());
    cache.insert(
        "localhost",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_secs(60),
    );
    let config = Arc::new(sample_config(
        upstream_addr.port(),
        Arc::clone(&cache),
        single_bypass_ruleset("localhost", upstream_addr.port()),
    ));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    // We never read from this socket, but it has to exist so the
    // src address in the RecvPackets is a real bindable endpoint
    // (matches what a real recvmsg would surface).
    let child = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let child_addr = child.local_addr().unwrap();

    let p1 = RecvPacket {
        data: b"a".to_vec(),
        src: child_addr,
        orig_dst: Some(upstream_addr),
    };
    let p2 = RecvPacket {
        data: b"b".to_vec(),
        src: child_addr,
        orig_dst: Some(upstream_addr),
    };

    tokio::join!(
        handle_datagram(
            listener_fd,
            IpFamily::V4,
            p1,
            Arc::clone(&config),
            Arc::clone(&sessions),
        ),
        handle_datagram(
            listener_fd,
            IpFamily::V4,
            p2,
            Arc::clone(&config),
            Arc::clone(&sessions),
        ),
    );

    // Both packets must have reached upstream from the same
    // outbound socket — i.e. the same source port.
    let mut buf = [0u8; 64];
    let (_, from1) = tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
        .await
        .expect("first packet never reached upstream")
        .unwrap();
    let (_, from2) = tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
        .await
        .expect("second packet never reached upstream")
        .unwrap();
    assert_eq!(
        from1, from2,
        "concurrent first-packets must share one outbound socket"
    );
    assert_eq!(sessions.lock().await.len(), 1);
}

#[tokio::test]
async fn denied_packet_does_not_create_a_session() {
    // Policy denies (empty cache) → no outbound socket, no
    // session-table entry.
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listener_fd = listener.as_raw_fd();

    let cache = Arc::new(DnsCache::new()); // empty
    let config = Arc::new(sample_config(
        99,
        Arc::clone(&cache),
        single_bypass_ruleset("kdc.example", 99),
    ));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    let pkt = RecvPacket {
        data: b"nope".to_vec(),
        src: "127.0.0.1:12345".parse().unwrap(),
        orig_dst: Some("203.0.113.99:99".parse().unwrap()),
    };
    handle_datagram(
        listener_fd,
        IpFamily::V4,
        pkt,
        Arc::clone(&config),
        Arc::clone(&sessions),
    )
    .await;

    assert!(sessions.lock().await.is_empty());
}

/// Build a `msghdr` whose control buffer contains a single
/// IP_ORIGDSTADDR cmsg. `cmsg_len_override` lets a caller
/// inject a deliberately-short cmsg_len to exercise the
/// truncation guard. `payload` provides the bytes following
/// the cmsghdr; the caller controls how many are valid.
fn build_origdstaddr_msg_v4(
    control_buf: &mut [u8],
    cmsg_len_override: Option<u32>,
    payload: &[u8],
) -> libc::msghdr {
    // Zero the buffer so any unset bytes are deterministic.
    for b in control_buf.iter_mut() {
        *b = 0;
    }
    let cmsghdr_size = std::mem::size_of::<libc::cmsghdr>();
    // Default cmsg_len = CMSG_LEN(payload.len()) — a well-formed
    // entry. Caller can override with a smaller value.
    let cmsg_len =
        cmsg_len_override.unwrap_or_else(|| unsafe { libc::CMSG_LEN(payload.len() as u32) });
    // Lay out the cmsghdr.
    let hdr = libc::cmsghdr {
        cmsg_len: cmsg_len as _,
        cmsg_level: libc::SOL_IP,
        cmsg_type: libc::IP_ORIGDSTADDR,
    };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &hdr as *const _ as *const u8,
            control_buf.as_mut_ptr(),
            cmsghdr_size,
        );
        // Payload sits at CMSG_DATA offset (cmsghdr + alignment
        // padding). On Linux/glibc this is just `cmsghdr_size`
        // because cmsghdr is already aligned for the data.
        let payload_offset = cmsghdr_size;
        std::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            control_buf.as_mut_ptr().add(payload_offset),
            payload.len().min(control_buf.len() - payload_offset),
        );
    }

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    // controllen is the *buffer* size; the cmsg's own cmsg_len
    // is what we're testing.
    msg.msg_controllen = control_buf.len() as _;
    msg
}

#[test]
fn extract_orig_dst_returns_none_when_cmsg_truncated() {
    // The motivating threat: kernel (or, more realistically, a
    // mock/test harness or future kernel quirk) ships a cmsg
    // marked as ORIGDSTADDR but with cmsg_len < sizeof(sockaddr_in)
    // worth of payload. Without the guard, copy_nonoverlapping
    // would read past the cmsg into adjacent control-buffer
    // memory. With the guard, we skip it and return None.
    let buf_size = unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::sockaddr_in>() as u32)
    } as usize;
    let mut control = vec![0u8; buf_size];
    // Fake a cmsg marked as ORIGDSTADDR but with cmsg_len of
    // just CMSG_LEN(0) — header only, no payload.
    let truncated_len = unsafe { libc::CMSG_LEN(0) };
    let msg = build_origdstaddr_msg_v4(&mut control, Some(truncated_len), &[]);
    assert_eq!(extract_orig_dst(&msg, IpFamily::V4), None);
}

#[test]
fn extract_orig_dst_parses_well_formed_v4_cmsg() {
    // Companion to the truncation test: with a properly-sized
    // sockaddr_in payload, the function should return the
    // address. This locks in the parse so future refactors of
    // the bounds check don't accidentally break the happy path.
    let buf_size = unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::sockaddr_in>() as u32)
    } as usize;
    let mut control = vec![0u8; buf_size];

    // 192.0.2.42:8443 in network-byte-order sockaddr_in form.
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 8443u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(Ipv4Addr::new(192, 0, 2, 42)).to_be(),
        },
        sin_zero: [0; 8],
    };
    let payload = unsafe {
        std::slice::from_raw_parts(
            &sa as *const _ as *const u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        )
    };
    let msg = build_origdstaddr_msg_v4(&mut control, None, payload);
    let parsed = extract_orig_dst(&msg, IpFamily::V4).expect("should parse");
    assert_eq!(parsed, "192.0.2.42:8443".parse::<SocketAddr>().unwrap());
}
