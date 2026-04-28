//! Minimal fake DNS server for use inside an isolated network namespace.
//!
//! Resolves allowed hostnames to a configurable IP (typically 127.0.0.1),
//! returns REFUSED for denied names. Supports A and AAAA queries only.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::block_log::{BlockEvent, BlockKind, BlockLogger, now_unix_ms};
use crate::dns_cache::DnsCache;
use crate::dns_forwarder::{parse_answers, DnsForwarder};
use crate::policy::{ConnectionPolicy, Verdict};

// ---------------------------------------------------------------------------
// DNS wire format constants
// ---------------------------------------------------------------------------

const HEADER_LEN: usize = 12;
const FLAG_QR: u16 = 0x8000; // Response
const FLAG_AA: u16 = 0x0400; // Authoritative
const FLAG_RD: u16 = 0x0100; // Recursion Desired (echo back)
const RCODE_SERVFAIL: u16 = 2;
const RCODE_REFUSED: u16 = 5;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

const TTL: u32 = 1;

/// Max concurrent DNS send-to tasks. Bounds task-heap growth if UDP
/// send_to starts returning Pending under kernel buffer pressure.
/// Beyond this, we skip the send rather than queue further.
const MAX_CONCURRENT_DNS_SENDS: usize = 256;

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

/// A parsed DNS question.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// Transaction ID — must be echoed in the response.
    pub id: u16,
    /// Flags from the query (we preserve RD).
    pub flags: u16,
    /// The queried hostname (e.g. "example.com").
    pub name: String,
    /// Raw wire-format name bytes (for echoing in the response).
    pub name_wire: Vec<u8>,
    /// Query type (A=1, AAAA=28, etc.).
    pub qtype: u16,
    /// Query class (IN=1).
    pub qclass: u16,
}

/// Parse a DNS query from a UDP datagram.
///
/// Only handles a single question (qdcount=1), which covers all
/// real-world resolver behavior.
pub fn parse_query(buf: &[u8]) -> Result<DnsQuery, DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::TooShort);
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

    // Ignore responses (QR bit set)
    if flags & FLAG_QR != 0 {
        return Err(DnsError::NotAQuery);
    }

    if qdcount != 1 {
        return Err(DnsError::UnsupportedQdcount(qdcount));
    }

    // Parse the question name
    let (name, name_wire, offset) = parse_name(buf, HEADER_LEN)?;
    if offset + 4 > buf.len() {
        return Err(DnsError::TooShort);
    }

    let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);

    Ok(DnsQuery {
        id,
        flags,
        name,
        name_wire,
        qtype,
        qclass,
    })
}

/// Parse a DNS name starting at `offset`, returning (dotted string, wire bytes, new offset).
fn parse_name(buf: &[u8], mut offset: usize) -> Result<(String, Vec<u8>, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let wire_start = offset;

    loop {
        if offset >= buf.len() {
            return Err(DnsError::TooShort);
        }
        let len = buf[offset] as usize;
        if len == 0 {
            offset += 1; // skip the zero terminator
            break;
        }
        // Pointer compression — we don't support it in queries (resolvers don't use it)
        if len & 0xC0 != 0 {
            return Err(DnsError::UnsupportedCompression);
        }
        if offset + 1 + len > buf.len() {
            return Err(DnsError::TooShort);
        }
        let label = std::str::from_utf8(&buf[offset + 1..offset + 1 + len])
            .map_err(|_| DnsError::InvalidLabel)?;
        labels.push(label.to_ascii_lowercase());
        offset += 1 + len;
    }

    let name_wire = buf[wire_start..offset].to_vec();
    let name = labels.join(".");
    Ok((name, name_wire, offset))
}

// ---------------------------------------------------------------------------
// Response building
// ---------------------------------------------------------------------------

/// Build a DNS response with an A record pointing to `ipv4`.
pub fn build_a_response(query: &DnsQuery, ipv4: Ipv4Addr) -> Vec<u8> {
    build_response_with_rdata(query, TYPE_A, &ipv4.octets())
}

/// Build a DNS response with an AAAA record pointing to `ipv6`.
pub fn build_aaaa_response(query: &DnsQuery, ipv6: Ipv6Addr) -> Vec<u8> {
    build_response_with_rdata(query, TYPE_AAAA, &ipv6.octets())
}

/// Build a SERVFAIL response. Used when upstream forwarding fails —
/// the client sees the same signal they'd get from a broken resolver
/// rather than a lie.
pub fn build_servfail(query: &DnsQuery) -> Vec<u8> {
    build_rcode_response(query, RCODE_SERVFAIL)
}

/// Build a REFUSED response.
pub fn build_refused(query: &DnsQuery) -> Vec<u8> {
    build_rcode_response(query, RCODE_REFUSED)
}

fn build_rcode_response(query: &DnsQuery, rcode: u16) -> Vec<u8> {
    let flags = FLAG_QR | FLAG_AA | (query.flags & FLAG_RD) | rcode;
    let mut resp = Vec::with_capacity(HEADER_LEN + query.name_wire.len() + 4);
    // Header: id, flags, qdcount=1, ancount=0, nscount=0, arcount=0
    resp.extend_from_slice(&query.id.to_be_bytes());
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    resp.extend_from_slice(&0u16.to_be_bytes()); // ancount
    resp.extend_from_slice(&0u16.to_be_bytes()); // nscount
    resp.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // Question section (echo back)
    resp.extend_from_slice(&query.name_wire);
    resp.extend_from_slice(&query.qtype.to_be_bytes());
    resp.extend_from_slice(&query.qclass.to_be_bytes());
    resp
}

/// Build an empty (no records) success response — for unsupported qtypes.
pub fn build_empty(query: &DnsQuery) -> Vec<u8> {
    let flags = FLAG_QR | FLAG_AA | (query.flags & FLAG_RD);
    let mut resp = Vec::with_capacity(HEADER_LEN + query.name_wire.len() + 4);
    resp.extend_from_slice(&query.id.to_be_bytes());
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    resp.extend_from_slice(&0u16.to_be_bytes()); // ancount
    resp.extend_from_slice(&0u16.to_be_bytes()); // nscount
    resp.extend_from_slice(&0u16.to_be_bytes()); // arcount
    resp.extend_from_slice(&query.name_wire);
    resp.extend_from_slice(&query.qtype.to_be_bytes());
    resp.extend_from_slice(&query.qclass.to_be_bytes());
    resp
}

fn build_response_with_rdata(query: &DnsQuery, rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let flags = FLAG_QR | FLAG_AA | (query.flags & FLAG_RD);
    let mut resp = Vec::with_capacity(
        HEADER_LEN + query.name_wire.len() + 4 + query.name_wire.len() + 10 + rdata.len(),
    );

    // Header
    resp.extend_from_slice(&query.id.to_be_bytes());
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    resp.extend_from_slice(&1u16.to_be_bytes()); // ancount
    resp.extend_from_slice(&0u16.to_be_bytes()); // nscount
    resp.extend_from_slice(&0u16.to_be_bytes()); // arcount

    // Question section (echo back)
    resp.extend_from_slice(&query.name_wire);
    resp.extend_from_slice(&query.qtype.to_be_bytes());
    resp.extend_from_slice(&query.qclass.to_be_bytes());

    // Answer section
    resp.extend_from_slice(&query.name_wire); // name
    resp.extend_from_slice(&rtype.to_be_bytes()); // type
    resp.extend_from_slice(&CLASS_IN.to_be_bytes()); // class
    resp.extend_from_slice(&TTL.to_be_bytes()); // ttl
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // rdlength
    resp.extend_from_slice(rdata); // rdata

    resp
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Configuration for the hermit DNS server.
///
/// Two modes: with an [`DnsForwarder`] attached (the production mode)
/// allowed queries are forwarded to a real resolver and the real
/// answer is relayed back to the child; without a forwarder the
/// server falls back to answering with fixed loopback IPs, which is
/// what the unit tests use and matches legacy behavior.
pub struct DnsServer<P> {
    policy: Arc<P>,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    block_log: BlockLogger,
    /// Where to record *allowed* queries (learn-mode trace).
    /// Disabled outside of `hermit learn`.
    access_log: BlockLogger,
    upstream: Option<Arc<DnsForwarder>>,
    cache: Option<Arc<DnsCache>>,
}

impl<P: ConnectionPolicy + Send + Sync + 'static> DnsServer<P> {
    pub fn new(policy: Arc<P>) -> Self {
        Self {
            policy,
            ipv4: Ipv4Addr::LOCALHOST,
            ipv6: Ipv6Addr::LOCALHOST,
            block_log: BlockLogger::disabled(),
            access_log: BlockLogger::disabled(),
            upstream: None,
            cache: None,
        }
    }

    /// Attach an access logger. Allowed queries will be recorded —
    /// used by `hermit learn` to trace what the child resolved.
    pub fn with_access_log(mut self, access_log: BlockLogger) -> Self {
        self.access_log = access_log;
        self
    }

    /// Override the IPv4 address returned in A responses. Only
    /// meaningful in fallback mode (no forwarder).
    pub fn with_ipv4(mut self, ipv4: Ipv4Addr) -> Self {
        self.ipv4 = ipv4;
        self
    }

    /// Override the IPv6 address returned in AAAA responses. Only
    /// meaningful in fallback mode.
    pub fn with_ipv6(mut self, ipv6: Ipv6Addr) -> Self {
        self.ipv6 = ipv6;
        self
    }

    /// Attach a block logger. Denied queries will be emitted to it in
    /// addition to the `warn!` line.
    pub fn with_block_log(mut self, block_log: BlockLogger) -> Self {
        self.block_log = block_log;
        self
    }

    /// Attach a real upstream resolver. When set, allowed queries are
    /// forwarded to the upstream instead of being answered locally.
    pub fn with_upstream(mut self, upstream: Arc<DnsForwarder>) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Attach a shared [`DnsCache`] that will be populated with
    /// A/AAAA answers forwarded through this server. Relays consult
    /// the same cache to reverse-map a dst IP back to a hostname.
    pub fn with_cache(mut self, cache: Arc<DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Run the DNS server on the given socket until cancelled.
    ///
    /// Takes `self: Arc<Self>` so each packet's response work can be
    /// spawned off the recv loop — forwarding to upstream is a
    /// round-trip, so it must never stall reception. A semaphore
    /// caps outstanding worker tasks so a clogged kernel buffer
    /// can't grow the task heap without bound.
    pub async fn run(self: Arc<Self>, socket: UdpSocket) -> std::io::Result<()> {
        let local_addr = socket.local_addr()?;
        info!(%local_addr, "dns server listening");

        let socket = Arc::new(socket);
        let send_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_SENDS));
        let mut buf = [0u8; 512];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let packet = buf[..len].to_vec();

            let Ok(permit) = Arc::clone(&send_limit).try_acquire_owned() else {
                debug!(%src, "dns: send limit reached, dropping packet");
                continue;
            };
            let server = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(resp) = server.handle_packet(&packet, src).await {
                    if let Err(e) = socket.send_to(&resp, src).await {
                        warn!(%src, error = %e, "dns: send_to failed");
                    }
                }
            });
        }
    }

    /// Process a single DNS packet, returning the response bytes (or
    /// `None` to drop silently). When a real upstream is configured,
    /// allowed queries are forwarded verbatim and the upstream's
    /// answer is relayed back (with A/AAAA records tapped into the
    /// shared [`DnsCache`]).
    async fn handle_packet(&self, buf: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
        let query = match parse_query(buf) {
            Ok(q) => q,
            Err(e) => {
                debug!(%src, error = %e, "dropping malformed DNS query");
                return None;
            }
        };

        debug!(
            %src,
            name = %query.name,
            qtype = query.qtype,
            "dns query"
        );

        match self.policy.check(&query.name) {
            Verdict::Allow => {
                // Record the allowed query for learn-mode trace.
                // Done here (not inside answer_allowed) so it
                // fires for both the upstream-forward path and
                // the legacy fixed-IP fallback.
                self.access_log.log(BlockEvent {
                    time_unix_ms: now_unix_ms(),
                    kind: BlockKind::Dns,
                    client: Some(src.to_string()),
                    hostname: Some(query.name.clone()),
                    method: None,
                    path: None,
                    reason: None,
                });
                self.answer_allowed(&query, buf, src).await
            }
            Verdict::Deny => {
                debug!(%src, name = %query.name,
                    "hermit blocked: DNS query for {} (not in allowlist)", query.name);
                self.block_log.log(BlockEvent {
                    time_unix_ms: now_unix_ms(),
                    kind: BlockKind::Dns,
                    client: Some(src.to_string()),
                    hostname: Some(query.name.clone()),
                    method: None,
                    path: None,
                    reason: Some("name not in allowlist".to_string()),
                });
                Some(build_refused(&query))
            }
        }
    }

    /// Build an allowed-query response. Either forwards to the
    /// configured upstream (production path) or, for tests/legacy,
    /// synthesises a fixed-IP answer.
    async fn answer_allowed(
        &self,
        query: &DnsQuery,
        raw: &[u8],
        src: SocketAddr,
    ) -> Option<Vec<u8>> {
        if let Some(upstream) = &self.upstream {
            debug!(%src, name = %query.name, qtype = query.qtype,
                upstream = %upstream.upstream(), "dns: forwarding allowed query upstream");
            match upstream.forward(raw).await {
                Ok(resp) => {
                    // Populate the shared cache from whatever A/AAAA
                    // records we can extract. Best-effort — even if
                    // parsing fails the client still gets the real
                    // answer and later relay reverse-lookups simply
                    // deny the (uncached) IP.
                    if let Some(cache) = &self.cache {
                        let answers = parse_answers(&resp);
                        let count = answers.len();
                        for ans in answers {
                            debug!(name = %query.name, ip = %ans.ip,
                                ttl_secs = ans.ttl.as_secs(),
                                "dns: caching answer");
                            cache.insert(&query.name, ans.ip, ans.ttl);
                        }
                        if count == 0 {
                            debug!(%src, name = %query.name,
                                "dns: forwarded response had no A/AAAA records to cache");
                        }
                    }
                    info!(%src, name = %query.name, qtype = query.qtype,
                        response_bytes = resp.len(),
                        "dns: forwarded allowed query");
                    Some(resp)
                }
                Err(e) => {
                    warn!(%src, name = %query.name, error = %e,
                        "dns: upstream forward failed; answering SERVFAIL");
                    Some(build_servfail(query))
                }
            }
        } else {
            let resp = match query.qtype {
                TYPE_A => {
                    info!(%src, name = %query.name, ip = %self.ipv4, "dns: A -> allowed (fallback)");
                    build_a_response(query, self.ipv4)
                }
                TYPE_AAAA => {
                    info!(%src, name = %query.name, ip = %self.ipv6, "dns: AAAA -> allowed (fallback)");
                    build_aaaa_response(query, self.ipv6)
                }
                _ => {
                    debug!(%src, name = %query.name, qtype = query.qtype,
                        "dns: unsupported qtype, empty response");
                    build_empty(query)
                }
            };
            Some(resp)
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("packet too short")]
    TooShort,
    #[error("not a query (QR bit set)")]
    NotAQuery,
    #[error("unsupported qdcount: {0}")]
    UnsupportedQdcount(u16),
    #[error("pointer compression not supported")]
    UnsupportedCompression,
    #[error("invalid label encoding")]
    InvalidLabel,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AllowAll, AllowList};
    use std::collections::HashSet;
    use std::net::IpAddr;

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

        let cache = Arc::new(crate::dns_cache::DnsCache::new());
        let forwarder = Arc::new(crate::dns_forwarder::DnsForwarder::new(upstream_addr));
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

        // Also shrink the timeout path by using a resolver we know
        // won't answer. Patch-via-ICMP-unreachable is flakey in CI
        // sandboxes, so we rely on the 5s timeout instead — test is
        // tagged to tolerate the wait.
        let forwarder = Arc::new(crate::dns_forwarder::DnsForwarder::new(dead_addr));
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
}
