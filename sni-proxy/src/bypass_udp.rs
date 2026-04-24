//! Transparent UDP relay for `Mechanism::Bypass` rules.
//!
//! Mirror image of [`crate::bypass_tcp`] for UDP — Kerberos KDC is
//! the motivating use case but anything UDP works.
//!
//! The listener socket is bound *inside the child netns* on
//! `127.0.0.1:<relay_port>` (nft DNAT redirects the real UDP port to
//! it) and the fd is sent to the parent. The parent:
//!
//! 1. Enables `IP_RECVORIGDSTADDR` on the fd so each `recvmsg` yields
//!    the pre-DNAT destination as a control message. Without this
//!    we'd lose the information we need to authorize the packet.
//! 2. Tracks one session per source `(ip, port)` from the child. A
//!    session owns a dedicated outbound UDP socket bound on the
//!    host netns and a reader task that relays replies back.
//! 3. Idle sessions are evicted so a UDP chatter doesn't grow the
//!    table without bound.
//!
//! No payload inspection — same policy as TCP bypass.
//!
//! Each UDP bypass endpoint has two listeners — one bound in the
//! AF_INET family, one in AF_INET6 — because the nft DNAT rules
//! that feed them live in separate families (`ip` vs `ip6`) and the
//! cmsg used to recover the pre-DNAT destination differs
//! (`IP_ORIGDSTADDR` vs `IPV6_ORIGDSTADDR`). Sharing one dual-stack
//! socket would entangle those code paths; the cost of two sockets
//! per endpoint is trivial.

use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::dns_cache::DnsCache;
use crate::policy::{BypassProtocol, RuleSet};

use tracing::{info, trace};

/// Max bytes we'll pull out of the listener per `recvmsg`. 64 KiB is
/// the upper bound a single UDP datagram can carry; anything larger
/// is off-spec.
const DGRAM_MAX: usize = 65_536;

/// Idle timeout before a UDP session is reaped. DNS-style protocols
/// complete in under a second; Kerberos pre-auth can take a few.
/// 30s gives headroom for retries without leaking resources when a
/// client forgets to close.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard cap on simultaneous UDP sessions so a misbehaving client
/// can't pin unbounded memory. Same order of magnitude as
/// `MAX_CONCURRENT_CONNECTIONS` on the TCP side.
const MAX_SESSIONS: usize = 1024;

/// Per-listener configuration. Each bypass `(udp, port, family)`
/// gets its own `BypassUdpConfig` and its own recv loop.
pub struct BypassUdpConfig {
    /// The real port the child thinks it's talking to (e.g. 88 for
    /// Kerberos). Used for rule matching and log context.
    pub port: u16,
    /// Which IP family this listener covers. Drives the cmsg and
    /// sockaddr codec path at runtime — the v4 and v6 ABIs aren't
    /// interchangeable.
    pub family: IpFamily,
    pub rules: Arc<RuleSet>,
    pub cache: Arc<DnsCache>,
    pub block_log: BlockLogger,
}

/// Which IP family a UDP bypass listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

/// State we keep per child-source `(ip, port)`.
struct Session {
    outbound: Arc<UdpSocket>,
    last_activity: Instant,
}

/// Map keyed by the child's source address. Kept behind a tokio
/// `Mutex` because both the recv loop and per-session reader tasks
/// mutate `last_activity`, and we want async-safe locking (the
/// critical section is tiny).
type Sessions = Arc<Mutex<HashMap<SocketAddr, Session>>>;

/// Run the UDP bypass relay on a socket the child bound and handed
/// over via SCM_RIGHTS. The returned future never completes under
/// normal operation — it lives as long as the sandbox does.
pub async fn run(raw_fd: RawFd, config: Arc<BypassUdpConfig>) -> Result<()> {
    // Ownership: wrapping the raw fd in a std UdpSocket makes sure
    // the fd is closed on drop. AsyncFd will take ownership below.
    let listener = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
    listener
        .set_nonblocking(true)
        .context("setting bypass-udp listener non-blocking")?;
    enable_recv_orig_dst(listener.as_raw_fd(), config.family)
        .with_context(|| match config.family {
            IpFamily::V4 => "enabling IP_RECVORIGDSTADDR on bypass-udp listener",
            IpFamily::V6 => "enabling IPV6_RECVORIGDSTADDR on bypass-udp listener",
        })?;

    let listener_fd = listener.as_raw_fd();
    let family = config.family;
    info!(port = config.port, ?family, fd = listener_fd,
        "bypass-udp: relay starting");
    let async_fd = AsyncFd::new(listener)
        .context("wrapping bypass-udp fd with AsyncFd")?;

    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                warn!(error = %e, "bypass-udp: AsyncFd readable failed");
                continue;
            }
        };
        match recv_with_orig_dst(listener_fd, family) {
            Ok(Some(pkt)) => {
                trace!(port = config.port, ?family, src = ?pkt.src,
                    orig_dst = ?pkt.orig_dst, bytes = pkt.data.len(),
                    "bypass-udp: received datagram");
                handle_datagram(listener_fd, family, pkt,
                    Arc::clone(&config), Arc::clone(&sessions)).await;
            }
            Ok(None) => {
                trace!("bypass-udp: recvmsg would-block");
                guard.clear_ready();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
            Err(e) => {
                warn!(error = %e, "bypass-udp: recvmsg failed");
                guard.clear_ready();
            }
        }
    }
}

/// One datagram pulled off the listener.
struct RecvPacket {
    data: Vec<u8>,
    src: SocketAddr,
    /// Pre-DNAT destination recovered from the `IP_ORIGDSTADDR` cmsg.
    /// `None` if the cmsg was missing, which can happen if
    /// `IP_RECVORIGDSTADDR` isn't effective on this kernel — we deny
    /// the packet rather than guess.
    orig_dst: Option<SocketAddr>,
}

/// Dispatch a single datagram: look up or create a session, forward
/// upstream. Isolated from the `recvmsg` work so tests can exercise
/// the allow/deny logic without staging a real DNAT.
async fn handle_datagram(
    listener_fd: RawFd,
    family: IpFamily,
    pkt: RecvPacket,
    config: Arc<BypassUdpConfig>,
    sessions: Sessions,
) {
    let Some(orig_dst) = pkt.orig_dst else {
        debug!(?pkt.src, "bypass-udp: missing IP_ORIGDSTADDR cmsg; dropping");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(pkt.src.to_string()),
            hostname: None,
            method: None,
            path: None,
            reason: Some("bypass-udp: missing IP_ORIGDSTADDR cmsg".to_string()),
        });
        return;
    };

    // Fast path: already have a session for this (src) → just send.
    // Updating `last_activity` under the lock keeps eviction honest.
    {
        let mut table = sessions.lock().await;
        if let Some(sess) = table.get_mut(&pkt.src) {
            sess.last_activity = Instant::now();
            trace!(src = ?pkt.src, ?orig_dst, bytes = pkt.data.len(),
                "bypass-udp: session hit; forwarding on existing outbound");
            if let Err(e) = sess.outbound.send_to(&pkt.data, orig_dst).await {
                warn!(?pkt.src, ?orig_dst, error = %e,
                    "bypass-udp: upstream send on existing session failed");
            }
            return;
        }
    }
    debug!(src = ?pkt.src, ?orig_dst, port = config.port,
        "bypass-udp: session miss; authorizing new flow");

    // Miss: authorize this flow before spending a socket on it.
    if !authorize(&config, &pkt.src, orig_dst).await {
        return;
    }

    // Create a new outbound socket in the host netns (we're the
    // parent process, so a bind here runs there by default).
    let outbound = match UdpSocket::bind(match orig_dst {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .await
    {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(error = %e, "bypass-udp: failed to bind outbound socket");
            return;
        }
    };

    if let Err(e) = outbound.send_to(&pkt.data, orig_dst).await {
        warn!(?orig_dst, error = %e, "bypass-udp: initial upstream send failed");
        return;
    }

    // Register the session *before* spawning the reader so a rapid
    // second datagram from the same src uses the same outbound
    // socket. Enforces the session cap too.
    let outbound_local = outbound.local_addr().ok();
    {
        let mut table = sessions.lock().await;
        if table.len() >= MAX_SESSIONS {
            warn!(session_count = table.len(),
                "bypass-udp: session cap reached; dropping new flow");
            return;
        }
        table.insert(
            pkt.src,
            Session {
                outbound: Arc::clone(&outbound),
                last_activity: Instant::now(),
            },
        );
        debug!(src = ?pkt.src, ?orig_dst, ?outbound_local,
            total_sessions = table.len(),
            "bypass-udp: session created");
    }

    // Spawn the upstream-reader task. It lives until the session
    // idles out; on exit it removes its entry from the table.
    let sessions_for_reader = Arc::clone(&sessions);
    let client_src = pkt.src;
    let cfg_port = config.port;
    tokio::spawn(async move {
        reader_loop(listener_fd, family, outbound, client_src, cfg_port, sessions_for_reader).await;
    });
}

/// Relay-upstream→client loop for a single session. Runs until idle
/// timeout fires, the socket errors, or the session table eviction
/// kicks it out.
async fn reader_loop(
    listener_fd: RawFd,
    family: IpFamily,
    outbound: Arc<UdpSocket>,
    client_src: SocketAddr,
    port: u16,
    sessions: Sessions,
) {
    let mut buf = vec![0u8; DGRAM_MAX];
    let mut replies = 0u64;
    let mut reply_bytes = 0u64;
    let started = Instant::now();
    loop {
        let recv = tokio::time::timeout(SESSION_IDLE_TIMEOUT, outbound.recv(&mut buf)).await;
        match recv {
            Ok(Ok(n)) => {
                // Relay reply back to the child via the listener
                // fd. conntrack on the nft DNAT path rewrites our
                // src to look like (real_ip, real_port) so the
                // child's socket accepts it.
                trace!(?client_src, bytes = n, port,
                    "bypass-udp: relaying upstream reply to child");
                if let Err(e) = sendto_listener(listener_fd, family, &buf[..n], client_src) {
                    warn!(?client_src, error = %e,
                        "bypass-udp: reply sendto failed; tearing down session");
                    break;
                }
                replies += 1;
                reply_bytes += n as u64;
                // Touch last_activity so idle eviction doesn't
                // clobber an active flow.
                let mut table = sessions.lock().await;
                if let Some(sess) = table.get_mut(&client_src) {
                    sess.last_activity = Instant::now();
                }
            }
            Ok(Err(e)) => {
                debug!(?client_src, error = %e, port,
                    "bypass-udp: outbound recv errored; closing session");
                break;
            }
            Err(_) => {
                debug!(?client_src, port, "bypass-udp: session idle timeout");
                break;
            }
        }
    }
    let elapsed_ms = started.elapsed().as_millis();
    let total = {
        let mut table = sessions.lock().await;
        table.remove(&client_src);
        table.len()
    };
    debug!(?client_src, port, replies, reply_bytes, elapsed_ms,
        remaining_sessions = total,
        "bypass-udp: session closed");
}

/// Policy gate: is the child allowed to send UDP to this `orig_dst`
/// through the bypass relay on `config.port`?
///
/// Tries the hostname rule first (via DNS cache reverse-lookup);
/// falls through to the literal-IP rule for destinations the child
/// reached without a DNS query we saw.
async fn authorize(config: &BypassUdpConfig, src: &SocketAddr, orig_dst: SocketAddr) -> bool {
    let dst_ip = orig_dst.ip();
    let hostname_opt = config.cache.reverse(dst_ip);
    debug!(?src, %dst_ip, port = config.port, hostname = ?hostname_opt,
        "bypass-udp: policy check");
    let allowed = match &hostname_opt {
        Some(h) => config
            .rules
            .is_bypass_allowed(h, BypassProtocol::Udp, config.port),
        None => config
            .rules
            .is_bypass_allowed_by_ip(dst_ip, BypassProtocol::Udp, config.port),
    };
    debug!(?src, hostname = ?hostname_opt, allowed,
        "bypass-udp: policy decision");
    if !allowed {
        debug!(?src, ?hostname_opt, %dst_ip, port = config.port,
            "bypass-udp: no matching rule; denying");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(src.to_string()),
            hostname: hostname_opt.clone(),
            method: None,
            path: Some(orig_dst.to_string()),
            reason: Some(match hostname_opt.as_ref() {
                Some(_) => "bypass-udp: no matching host rule".to_string(),
                None => "bypass-udp: dst IP not in DNS cache and not allowed by ip rule".to_string(),
            }),
        });
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Raw socket plumbing (`recvmsg` + `sendto` + IP_RECVORIGDSTADDR)
// ---------------------------------------------------------------------------

/// Turn on `IP_RECVORIGDSTADDR` (v4) or `IPV6_RECVORIGDSTADDR`
/// (v6) so subsequent `recvmsg` calls include the pre-DNAT
/// destination as a control message. Without this flag we'd only
/// see our own listener address and couldn't tell which real host
/// the child was targeting.
fn enable_recv_orig_dst(fd: RawFd, family: IpFamily) -> io::Result<()> {
    let one: libc::c_int = 1;
    let (level, name) = match family {
        IpFamily::V4 => (libc::SOL_IP, libc::IP_RECVORIGDSTADDR),
        IpFamily::V6 => (libc::IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR),
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &one as *const _ as *const _,
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Non-blocking `recvmsg` that also pulls the `IP[V6]_ORIGDSTADDR`
/// control message for the given family. Returns `Ok(None)` if
/// there was nothing to read; only returns `Err` for non-
/// `WouldBlock` failures.
fn recv_with_orig_dst(fd: RawFd, family: IpFamily) -> io::Result<Option<RecvPacket>> {
    let mut data = vec![0u8; DGRAM_MAX];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut _,
        iov_len: data.len(),
    };

    // Both sockaddr and cmsg are sized to the family we know we
    // bound on. Using the wrong size truncates the kernel-filled
    // address silently.
    let (addr_size, cmsg_payload_size) = match family {
        IpFamily::V4 => (
            std::mem::size_of::<libc::sockaddr_in>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        ),
        IpFamily::V6 => (
            std::mem::size_of::<libc::sockaddr_in6>(),
            std::mem::size_of::<libc::sockaddr_in6>(),
        ),
    };

    let control_len = unsafe { libc::CMSG_SPACE(cmsg_payload_size as u32) } as usize;
    let mut control = vec![0u8; control_len];

    // Allocate the bigger sockaddr so a single code path can hold
    // either family. msg_namelen tells us which the kernel used.
    let mut src_buf: MaybeUninit<libc::sockaddr_in6> = MaybeUninit::zeroed();

    let mut msg = unsafe { std::mem::zeroed::<libc::msghdr>() };
    msg.msg_name = src_buf.as_mut_ptr() as *mut _;
    msg.msg_namelen = addr_size as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut _;
    msg.msg_controllen = control.len();

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(e);
    }
    let n = n as usize;
    data.truncate(n);

    let src = unsafe { sockaddr_to_socket_addr(src_buf.as_ptr() as *const libc::sockaddr, family)? };
    let orig_dst = extract_orig_dst(&msg, family);

    Ok(Some(RecvPacket { data, src, orig_dst }))
}

/// Decode a filled-in `sockaddr` of known family. Called on the
/// kernel-populated buffer from `recvmsg` so the buffer is
/// guaranteed initialized in the first `sizeof(sockaddr_{in,in6})`
/// bytes.
unsafe fn sockaddr_to_socket_addr(
    ptr: *const libc::sockaddr,
    family: IpFamily,
) -> io::Result<SocketAddr> {
    match family {
        IpFamily::V4 => {
            let sa = &*(ptr as *const libc::sockaddr_in);
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                u16::from_be(sa.sin_port),
            )))
        }
        IpFamily::V6 => {
            let sa = &*(ptr as *const libc::sockaddr_in6);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sa.sin6_addr.s6_addr),
                u16::from_be(sa.sin6_port),
                u32::from_be(sa.sin6_flowinfo),
                u32::from_be(sa.sin6_scope_id),
            )))
        }
    }
}

/// Walk the cmsg chain and pull out the pre-DNAT destination for
/// the given family. Tolerates unknown control messages — if the
/// requested ORIGDSTADDR variant isn't present we just return
/// `None` and the caller denies the packet.
fn extract_orig_dst(msg: &libc::msghdr, family: IpFamily) -> Option<SocketAddr> {
    let (wanted_level, wanted_type) = match family {
        IpFamily::V4 => (libc::SOL_IP, libc::IP_ORIGDSTADDR),
        IpFamily::V6 => (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR),
    };

    let mut cmsg_ptr = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg_ptr.is_null() {
        let cmsg = unsafe { &*cmsg_ptr };
        if cmsg.cmsg_level == wanted_level && cmsg.cmsg_type == wanted_type {
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg_ptr) };
            return Some(unsafe {
                match family {
                    IpFamily::V4 => {
                        let mut addr: libc::sockaddr_in = std::mem::zeroed();
                        std::ptr::copy_nonoverlapping(
                            data_ptr,
                            &mut addr as *mut _ as *mut u8,
                            std::mem::size_of::<libc::sockaddr_in>(),
                        );
                        SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                            u16::from_be(addr.sin_port),
                        ))
                    }
                    IpFamily::V6 => {
                        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
                        std::ptr::copy_nonoverlapping(
                            data_ptr,
                            &mut addr as *mut _ as *mut u8,
                            std::mem::size_of::<libc::sockaddr_in6>(),
                        );
                        SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(addr.sin6_addr.s6_addr),
                            u16::from_be(addr.sin6_port),
                            u32::from_be(addr.sin6_flowinfo),
                            u32::from_be(addr.sin6_scope_id),
                        ))
                    }
                }
            });
        }
        cmsg_ptr = unsafe { libc::CMSG_NXTHDR(msg, cmsg_ptr) };
    }
    None
}

/// Send a datagram out on the listener fd. We can't use the tokio
/// `UdpSocket` for this path because it lives inside an `AsyncFd`
/// wrapper dedicated to reads; a parallel tokio wrap would fight
/// over mio registration. A direct `sendto` is the simplest answer
/// and UDP writes to an unbound local socket are near-instant.
///
/// `family` must match the listener the fd is bound on — a v4
/// listener can't deliver to a v6 client and vice versa.
fn sendto_listener(fd: RawFd, family: IpFamily, buf: &[u8], dst: SocketAddr) -> io::Result<()> {
    match (family, dst) {
        (IpFamily::V4, SocketAddr::V4(v4)) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            raw_sendto(fd, buf, &sa as *const _ as *const _,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        (IpFamily::V6, SocketAddr::V6(v6)) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo().to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id().to_be(),
            };
            raw_sendto(fd, buf, &sa as *const _ as *const _,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
        // Family mismatch is a programming error (the listener and
        // its client should always agree), but we surface it as an
        // IO error rather than a panic so the relay keeps running.
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bypass-udp: sendto family mismatch: listener={family:?}, dst={dst:?}"),
        )),
    }
}

fn raw_sendto(fd: RawFd, buf: &[u8], sa: *const libc::sockaddr, sa_len: libc::socklen_t) -> io::Result<()> {
    let rc = unsafe { libc::sendto(fd, buf.as_ptr() as *const _, buf.len(), 0, sa, sa_len) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AccessRule, Mechanism};
    use std::net::{IpAddr, Ipv4Addr};

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
        use crate::policy::IpRule;
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
}
