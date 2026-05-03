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
