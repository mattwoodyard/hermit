//! Forward DNS queries to a real upstream resolver.
//!
//! The parent-side hermit DNS server handles policy (allow/deny) but
//! doesn't invent answers — allowed queries are forwarded to a real
//! resolver so the child receives the same IPs everyone else on the
//! internet sees. Answers are parsed just enough to populate the
//! [`DnsCache`][crate::dns_cache::DnsCache] with A/AAAA records.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace};

/// Max time to wait for the upstream resolver's reply before giving
/// up. Each query gets its own timer — a slow upstream can't stall
/// the DNS server's recv loop because queries are dispatched to
/// spawned tasks.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Small UDP client that round-trips an already-encoded DNS query
/// through an upstream resolver and returns the response bytes
/// verbatim. Cloneable-cheap (just a socket addr) so callers usually
/// wrap a single instance in `Arc` and share it across tasks.
#[derive(Debug, Clone)]
pub struct DnsForwarder {
    upstream: SocketAddr,
}

impl DnsForwarder {
    pub fn new(upstream: SocketAddr) -> Self {
        Self { upstream }
    }

    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// Send `query` to the upstream resolver and return the response
    /// bytes. A fresh ephemeral UDP socket is used per query so a
    /// slow or faulty upstream can't influence concurrent lookups.
    pub async fn forward(&self, query: &[u8]) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let bind = match self.upstream {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        trace!(upstream = %self.upstream, query_bytes = query.len(), bind,
            "dns-forward: binding + sending");
        let sock = UdpSocket::bind(bind)
            .await
            .context("binding forwarder socket")?;
        sock.connect(self.upstream)
            .await
            .with_context(|| format!("connecting to upstream {}", self.upstream))?;
        sock.send(query).await.context("sending DNS query upstream")?;

        let mut buf = vec![0u8; 4096];
        let n = timeout(FORWARD_TIMEOUT, sock.recv(&mut buf))
            .await
            .context("upstream DNS query timed out")?
            .context("receiving DNS response from upstream")?;
        buf.truncate(n);
        let elapsed_us = start.elapsed().as_micros();
        debug!(upstream = %self.upstream, query_bytes = query.len(),
            response_bytes = buf.len(), elapsed_us,
            "dns-forward: round trip complete");
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// Minimal answer parser
// ---------------------------------------------------------------------------

/// One A or AAAA answer extracted from a DNS response.
#[derive(Debug, PartialEq, Eq)]
pub struct ForwardedAnswer {
    pub ip: IpAddr,
    pub ttl: Duration,
}

/// Walk a DNS response and pull out every A/AAAA answer record.
/// Unknown types, NS/additional sections, and compressed names are
/// all tolerated (we just step over them).
///
/// Returns an empty vec on any structural error — the caller will
/// treat that as "nothing cacheable" and still forward the response
/// to the child unchanged.
pub fn parse_answers(buf: &[u8]) -> Vec<ForwardedAnswer> {
    let answers = parse_answers_inner(buf).unwrap_or_default();
    trace!(response_bytes = buf.len(), answer_count = answers.len(),
        "dns-forward: parsed answers");
    answers
}

fn parse_answers_inner(buf: &[u8]) -> Option<Vec<ForwardedAnswer>> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    // Skip the question section: qdcount × (name, qtype, qclass).
    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_name(buf, offset)?;
        offset = offset.checked_add(4)?;
        if offset > buf.len() {
            return None;
        }
    }

    let mut out = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        offset = skip_name(buf, offset)?;
        if offset.checked_add(10)? > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        // class = buf[offset+2..+4], skipped
        let ttl_secs = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        let rdata_start = offset + 10;
        let rdata_end = rdata_start.checked_add(rdlen)?;
        if rdata_end > buf.len() {
            return None;
        }

        match rtype {
            1 if rdlen == 4 => {
                let octets: [u8; 4] = buf[rdata_start..rdata_end].try_into().ok()?;
                out.push(ForwardedAnswer {
                    ip: IpAddr::V4(Ipv4Addr::from(octets)),
                    ttl: Duration::from_secs(ttl_secs as u64),
                });
            }
            28 if rdlen == 16 => {
                let octets: [u8; 16] = buf[rdata_start..rdata_end].try_into().ok()?;
                out.push(ForwardedAnswer {
                    ip: IpAddr::V6(Ipv6Addr::from(octets)),
                    ttl: Duration::from_secs(ttl_secs as u64),
                });
            }
            _ => {} // CNAME, MX, TXT, ... — skipped
        }

        offset = rdata_end;
    }

    Some(out)
}

/// Step over an encoded DNS name (sequence of length-prefixed labels
/// terminated by a zero, or a 2-byte pointer). Returns the offset of
/// the first byte *after* the name, or `None` on a malformed input.
fn skip_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    // A hard upper bound prevents a pathological label chain from
    // turning this into a quadratic sink. 255 is the RFC 1035 limit.
    for _ in 0..256 {
        if offset >= buf.len() {
            return None;
        }
        let b = buf[offset];
        if b == 0 {
            return Some(offset + 1);
        }
        if b & 0xC0 == 0xC0 {
            // Pointer — the whole name is 2 bytes from our
            // perspective regardless of where the pointer aims.
            if offset + 2 > buf.len() {
                return None;
            }
            return Some(offset + 2);
        }
        if b & 0xC0 != 0 {
            // Reserved length encoding — treat as malformed.
            return None;
        }
        let len = b as usize;
        offset = offset.checked_add(1 + len)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let got = parse_answers(&buf);
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
}
