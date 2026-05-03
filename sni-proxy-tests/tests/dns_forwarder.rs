//! Tests for `sni_proxy::dns_forwarder`. `parse_answers`,
//! `ForwardedAnswer`, and `DnsForwarder` are public — no
//! `__test_internals` wrappers needed.

use sni_proxy::dns_forwarder::{parse_answers, DnsForwarder, ForwardedAnswer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Build a DNS response frame with `qname` in the question and a
/// single A-record answer of `ip` with TTL `ttl`.
fn response_with_a_record(qname: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: QR + RD + RA
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    // Question
    for label in qname.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    out.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    // Answer — use a name pointer back to the question.
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // type A
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    out.extend_from_slice(&ip.octets());
    out
}

#[test]
fn parse_a_record() {
    let buf = response_with_a_record("example.com", Ipv4Addr::new(203, 0, 113, 7), 42);
    let got: Vec<ForwardedAnswer> = parse_answers(&buf);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    assert_eq!(got[0].ttl, Duration::from_secs(42));
}

#[test]
fn parse_returns_empty_for_malformed() {
    // Two bytes — smaller than a header; must not panic, must
    // return an empty vec so the caller keeps forwarding the
    // (unparseable) response to the child unchanged.
    assert!(parse_answers(&[0, 0]).is_empty());
}

#[test]
fn parse_returns_every_a_record_for_multi_answer_response() {
    // Multi-A rrsets are common for load-balanced services.
    // The parser must surface every address so the DNS-cache
    // populates a reverse entry for each, and the bypass relay
    // can authorize a connection regardless of which IP the
    // child resolver happens to pick.
    let mut out = Vec::new();
    out.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&3u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for label in ["kdc", "example"] {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    out.extend_from_slice(&1u16.to_be_bytes()); // IN

    // Three A records for the same name, each a name pointer
    // to offset 12 (the question name).
    for octet in [1u8, 2, 3] {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // type A
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out.extend_from_slice(&300u32.to_be_bytes()); // ttl
        out.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        out.extend_from_slice(&[10, 0, 0, octet]);
    }

    let got = parse_answers(&out);
    let ips: Vec<IpAddr> = got.iter().map(|a| a.ip).collect();
    assert_eq!(
        ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ]
    );
}

#[test]
fn parse_tolerates_unknown_rrtype() {
    // Mix an A record with an unknown RR type (65535) and check
    // we only surface the A answer.
    let mut buf = response_with_a_record("ok.test", Ipv4Addr::new(1, 1, 1, 1), 60);
    buf[7] = 2; // bump ancount to 2
    // Append an unknown RR after the first answer. Name pointer
    // back to the question, type=0xFFFF, class=IN, ttl=10, rdlen=1, rdata=0xAA.
    buf.extend_from_slice(&0xC00Cu16.to_be_bytes());
    buf.extend_from_slice(&0xFFFFu16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&10u32.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.push(0xAA);

    let got = parse_answers(&buf);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
}

#[test]
fn parse_handles_aaaa_record() {
    // Build a minimal AAAA response manually.
    let mut out = Vec::new();
    out.extend_from_slice(&1u16.to_be_bytes()); // id
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    // Question: "v6.test"
    for label in ["v6", "test"] {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&28u16.to_be_bytes()); // qtype AAAA
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    // Answer
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name pointer
    out.extend_from_slice(&28u16.to_be_bytes()); // type AAAA
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&300u32.to_be_bytes()); // ttl
    out.extend_from_slice(&16u16.to_be_bytes()); // rdlen
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    out.extend_from_slice(&v6.octets());

    let got = parse_answers(&out);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].ip, IpAddr::V6(v6));
    assert_eq!(got[0].ttl, Duration::from_secs(300));
}

#[tokio::test]
async fn forwarder_roundtrips_through_mock_upstream() {
    // Stand up a mock "upstream resolver" that replies with a
    // canned answer to any query it receives.
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    let canned = response_with_a_record("example.com", Ipv4Addr::new(9, 9, 9, 9), 100);
    let canned_clone = canned.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_, src) = upstream.recv_from(&mut buf).await.unwrap();
        upstream.send_to(&canned_clone, src).await.unwrap();
    });

    let fwd = DnsForwarder::new(upstream_addr);
    let resp = fwd.forward(b"ignored: mock answers everything").await.unwrap();
    assert_eq!(resp, canned);
}
