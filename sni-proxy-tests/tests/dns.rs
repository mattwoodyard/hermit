//! Tests for `sni_proxy::dns`. Constants used here are exposed
//! via the `__test_internals` feature.

use sni_proxy::dns::{
    build_a_response, build_aaaa_response, build_empty, build_refused, parse_query, DnsError,
    DnsServer,
};
use sni_proxy::dns::__test_internals::{
    CLASS_IN, FLAG_AA, FLAG_QR, FLAG_RD, HEADER_LEN, RCODE_REFUSED, RCODE_SERVFAIL, TYPE_A,
    TYPE_AAAA,
};
use sni_proxy::policy::{AllowAll, AllowList};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Build a minimal DNS query packet for an A record.
fn make_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&FLAG_RD.to_be_bytes()); // flags: RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // Question: name
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // name terminator
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    buf
}

#[test]
fn parse_simple_a_query() {
    let pkt = make_query(0x1234, "example.com", TYPE_A);
    let q = parse_query(&pkt).unwrap();
    assert_eq!(q.id, 0x1234);
    assert_eq!(q.name, "example.com");
    assert_eq!(q.qtype, TYPE_A);
    assert_eq!(q.qclass, CLASS_IN);
}

#[test]
fn parse_aaaa_query() {
    let pkt = make_query(0xABCD, "test.dev", TYPE_AAAA);
    let q = parse_query(&pkt).unwrap();
    assert_eq!(q.name, "test.dev");
    assert_eq!(q.qtype, TYPE_AAAA);
}

#[test]
fn parse_rejects_too_short() {
    assert!(matches!(parse_query(&[0; 5]), Err(DnsError::TooShort)));
}

#[test]
fn parse_rejects_response() {
    let mut pkt = make_query(1, "x.com", TYPE_A);
    // Set QR bit
    pkt[2] |= 0x80;
    assert!(matches!(parse_query(&pkt), Err(DnsError::NotAQuery)));
}

#[test]
fn parse_name_case_insensitive() {
    let pkt = make_query(1, "Example.COM", TYPE_A);
    let q = parse_query(&pkt).unwrap();
    assert_eq!(q.name, "example.com");
}

#[test]
fn build_a_response_roundtrip() {
    let pkt = make_query(0x5678, "foo.bar", TYPE_A);
    let q = parse_query(&pkt).unwrap();
    let resp = build_a_response(&q, Ipv4Addr::LOCALHOST);

    // Parse the response header
    assert!(resp.len() >= HEADER_LEN);
    let id = u16::from_be_bytes([resp[0], resp[1]]);
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);

    assert_eq!(id, 0x5678);
    assert!(flags & FLAG_QR != 0, "QR bit should be set");
    assert!(flags & FLAG_AA != 0, "AA bit should be set");
    assert_eq!(ancount, 1);

    // Find the A record rdata at the end
    let rdata_start = resp.len() - 4;
    assert_eq!(&resp[rdata_start..], &[127, 0, 0, 1]);
}

#[test]
fn build_aaaa_response_has_16_byte_rdata() {
    let pkt = make_query(1, "v6.test", TYPE_AAAA);
    let q = parse_query(&pkt).unwrap();
    let resp = build_aaaa_response(&q, Ipv6Addr::LOCALHOST);

    let rdata_start = resp.len() - 16;
    assert_eq!(&resp[rdata_start..], Ipv6Addr::LOCALHOST.octets());
}

#[test]
fn build_refused_has_rcode_5() {
    let pkt = make_query(1, "bad.com", TYPE_A);
    let q = parse_query(&pkt).unwrap();
    let resp = build_refused(&q);

    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_eq!(flags & 0x000F, RCODE_REFUSED);
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert_eq!(ancount, 0);
}

#[test]
fn build_empty_has_no_answers() {
    let pkt = make_query(1, "mx.test", 15); // MX
    let q = parse_query(&pkt).unwrap();
    let resp = build_empty(&q);

    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_eq!(flags & 0x000F, 0); // NOERROR
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert_eq!(ancount, 0);
}

#[tokio::test]
async fn server_allows_matching_host() {
    let policy = Arc::new(AllowList::new(["good.com".into()].into()));
    let server = DnsServer::new(policy);
    let pkt = make_query(1, "good.com", TYPE_A);
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let resp = server.handle_packet(&pkt, src).await.unwrap();
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert_eq!(ancount, 1);
    // Check rdata is 127.0.0.1
    let rdata_start = resp.len() - 4;
    assert_eq!(&resp[rdata_start..], &[127, 0, 0, 1]);
}

#[tokio::test]
async fn server_refuses_denied_host() {
    let policy = Arc::new(AllowList::new(["good.com".into()].into()));
    let server = DnsServer::new(policy);
    let pkt = make_query(1, "evil.com", TYPE_A);
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let resp = server.handle_packet(&pkt, src).await.unwrap();
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_eq!(flags & 0x000F, RCODE_REFUSED);
}

#[tokio::test]
async fn server_drops_garbage() {
    let policy = Arc::new(AllowAll);
    let server = DnsServer::new(policy);
    let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    assert!(server.handle_packet(&[0; 3], src).await.is_none());
}

#[tokio::test]
async fn server_integration_a_query() {
    let policy = Arc::new(AllowList::new(["test.example".into()].into()));
    let server = Arc::new(DnsServer::new(policy));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let server_clone = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        let _ = server_clone.run(socket).await;
    });

    // Send a query from a client socket
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = make_query(0x9999, "test.example", TYPE_A);
    client.send_to(&query, server_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("timeout waiting for DNS response")
    .unwrap();

    let resp = &buf[..len];
    let id = u16::from_be_bytes([resp[0], resp[1]]);
    assert_eq!(id, 0x9999);
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert_eq!(ancount, 1);
    // A record rdata
    assert_eq!(&resp[len - 4..], &[127, 0, 0, 1]);

    handle.abort();
}

#[tokio::test]
async fn server_integration_denied_query() {
    let policy = Arc::new(AllowList::new(HashSet::new()));
    let server = Arc::new(DnsServer::new(policy));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();

    let server_clone = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        let _ = server_clone.run(socket).await;
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = make_query(0x1111, "denied.com", TYPE_A);
    client.send_to(&query, server_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("timeout waiting for DNS response")
    .unwrap();

    let resp = &buf[..len];
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    assert_eq!(flags & 0x000F, RCODE_REFUSED);

    handle.abort();
}

/// Build a canned A-record answer for use as a mock upstream.
fn canned_a_response(txn_id_from: &[u8], qname: &str, ip: Ipv4Addr) -> Vec<u8> {
    // Echo the incoming query's txn id so the client (our DNS
    // server) accepts it.
    let mut out = Vec::new();
    out.extend_from_slice(&txn_id_from[..2]);
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR + RD + RA
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name pointer
    out.extend_from_slice(&1u16.to_be_bytes()); // type A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&60u32.to_be_bytes()); // ttl
    out.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    out.extend_from_slice(&ip.octets());
    out
}

#[tokio::test]
async fn server_forwards_to_upstream_and_populates_cache() {
    // Spin up a mock upstream resolver that answers any query
    // with 203.0.113.9.
    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut qbuf = [0u8; 512];
        loop {
            let (n, from) = match upstream_sock.recv_from(&mut qbuf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let resp = canned_a_response(
                &qbuf[..n],
                "svc.example",
                Ipv4Addr::new(203, 0, 113, 9),
            );
            let _ = upstream_sock.send_to(&resp, from).await;
        }
    });

    let cache = Arc::new(sni_proxy::dns_cache::DnsCache::new());
    let forwarder = Arc::new(sni_proxy::dns_forwarder::DnsForwarder::new(upstream_addr));
    let policy = Arc::new(AllowList::new(["svc.example".into()].into()));
    let server = Arc::new(
        DnsServer::new(policy)
            .with_upstream(forwarder)
            .with_cache(Arc::clone(&cache)),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let server_clone = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        let _ = server_clone.run(socket).await;
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = make_query(0x4242, "svc.example", TYPE_A);
    client.send_to(&query, server_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("client never received DNS response")
    .unwrap();

    // The upstream's real IP made it back to the child — not a
    // loopback sinkhole.
    assert_eq!(&buf[len - 4..len], &[203, 0, 113, 9]);

    // And the cache now knows svc.example -> 203.0.113.9 so a
    // later relay reverse-lookup will succeed.
    let reversed = cache.reverse(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    assert_eq!(reversed.as_deref(), Some("svc.example"));

    handle.abort();
}

#[tokio::test]
async fn server_returns_servfail_when_upstream_is_down() {
    // Bind an upstream address, then immediately close it — the
    // forwarder will hit recv() on a closed socket. The child
    // must see SERVFAIL rather than hang.
    let bound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = bound.local_addr().unwrap();
    drop(bound);

    let forwarder = Arc::new(sni_proxy::dns_forwarder::DnsForwarder::new(dead_addr));
    let policy = Arc::new(AllowList::new(["anything.test".into()].into()));
    let server = Arc::new(DnsServer::new(policy).with_upstream(forwarder));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    let server_clone = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        let _ = server_clone.run(socket).await;
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = make_query(0x7777, "anything.test", TYPE_A);
    client.send_to(&query, server_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.recv_from(&mut buf),
    )
    .await
    .expect("SERVFAIL response never arrived")
    .unwrap();

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    assert_eq!(flags & 0x000F, RCODE_SERVFAIL);
    let _ = len; // quiet the unused warning

    handle.abort();
}
