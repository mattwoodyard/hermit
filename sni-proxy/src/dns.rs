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
    pub async fn handle_packet(&self, buf: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
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
                    port: None,
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
                    port: None,
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

#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    pub const HEADER_LEN: usize = super::HEADER_LEN;
    pub const FLAG_QR: u16 = super::FLAG_QR;
    pub const FLAG_AA: u16 = super::FLAG_AA;
    pub const FLAG_RD: u16 = super::FLAG_RD;
    pub const RCODE_SERVFAIL: u16 = super::RCODE_SERVFAIL;
    pub const RCODE_REFUSED: u16 = super::RCODE_REFUSED;
    pub const TYPE_A: u16 = super::TYPE_A;
    pub const TYPE_AAAA: u16 = super::TYPE_AAAA;
    pub const CLASS_IN: u16 = super::CLASS_IN;
}
