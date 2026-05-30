//! Look up the pre-NAT (original) destination of a DNAT'd UDP flow
//! by querying the kernel's `nf_conntrack` table via the NFNETLINK
//! CTNETLINK subsystem.
//!
//! Why this exists. For TCP, `getsockopt(SO_ORIGINAL_DST)` is a
//! special path that asks conntrack for the pre-NAT tuple. UDP has
//! no equivalent sockopt (kernel returns `ENOPROTOOPT` — TCP/SCTP
//! only). `IP_RECVORIGDSTADDR` cmsg looked right by name but
//! returns the *post*-NAT destination — the kernel reads it from
//! the skb's IP header at delivery time, after netfilter rewrote
//! it. With DNAT in the path, both common sockopts hand back the
//! listener's own address, not the real server the child was
//! targeting.
//!
//! This module fills that gap. Given the four-tuple as the
//! listener sees it (post-NAT), send `IPCTNL_MSG_CT_GET` with that
//! as the conntrack **reply** tuple and read the **original**
//! tuple from the response — which holds the pre-NAT addresses.
//!
//! The netlink fd must be in the same netns as the conntrack table
//! we're querying. hermit opens the socket inside the child netns
//! during setup and passes the fd up to the parent via SCM_RIGHTS,
//! so the parent-side relay reads conntrack against the child's
//! tables.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::Mutex;

// CTNETLINK constants (from <linux/netfilter/nfnetlink_conntrack.h>).
// libc 0.2 doesn't expose CTA_*; we define them locally.

const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const NFNETLINK_V0: u8 = 0;

/// `nlmsg_type` for ctnetlink = (NFNL_SUBSYS_CTNETLINK << 8) | op.
const fn ct_msg_type(op: u16) -> u16 {
    ((libc::NFNL_SUBSYS_CTNETLINK as u16) << 8) | op
}

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;

const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | 0x4000); // strip NESTED + NET_BYTEORDER

const NLMSG_HDR_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;

const NLM_F_REQUEST: u16 = libc::NLM_F_REQUEST as u16;
const NLM_F_ACK: u16 = libc::NLM_F_ACK as u16;

/// Open an unbound `NETLINK_NETFILTER` socket. The caller is
/// responsible for being in the netns whose conntrack table they
/// want to query at the moment of `socket(2)` — the socket
/// inherits the calling thread's netns at creation time, and
/// stays bound to it for the fd's lifetime regardless of who
/// later holds the fd.
pub fn open_socket() -> io::Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const _,
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Shared handle around a `NETLINK_NETFILTER` fd. Holds a mutex so
/// concurrent lookups from multiple bypass-udp relay tasks don't
/// interleave send/recv on the same socket — netlink replies have
/// no correlator that would let us untangle them after the fact.
pub struct Conntrack {
    fd: RawFd,
    lock: Mutex<()>,
}

impl Conntrack {
    /// Take ownership of a fd previously returned by [`open_socket`]
    /// (typically opened in the child netns and inherited via
    /// SCM_RIGHTS).
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            lock: Mutex::new(()),
        }
    }

    /// Serialize through the per-handle mutex and run a UDP
    /// pre-NAT lookup. See [`lookup_udp_orig_dst`] for semantics.
    pub fn lookup_udp_orig_dst(
        &self,
        reply_src: SocketAddr,
        reply_dst: SocketAddr,
    ) -> io::Result<SocketAddr> {
        let _g = self.lock.lock().expect("conntrack mutex poisoned");
        lookup_udp_orig_dst(self.fd, reply_src, reply_dst)
    }
}

impl Drop for Conntrack {
    fn drop(&mut self) {
        // Best-effort close; nothing actionable on failure.
        unsafe { libc::close(self.fd) };
    }
}

/// Look up the pre-NAT destination for a UDP datagram the relay
/// just received. `(reply_src, reply_dst)` is the post-NAT view as
/// the listener sees it: `reply_src` is the listener's bound
/// address (e.g. `127.0.0.1:relay_port`), `reply_dst` is the
/// packet's source (the child's ephem). The kernel returns the
/// conntrack entry whose REPLY tuple matches that, and we extract
/// the ORIGINAL tuple's destination — the real server.
///
/// Blocking on `send`/`recv`; conntrack responses arrive in one
/// hop with no kernel-side wait, so this is fast in practice
/// (microseconds). Per-session, not per-packet.
///
/// Prefer [`Conntrack::lookup_udp_orig_dst`] in production — this
/// raw entry point has no concurrency control and is intended for
/// callers that already serialize access to the fd.
pub fn lookup_udp_orig_dst(
    fd: RawFd,
    reply_src: SocketAddr,
    reply_dst: SocketAddr,
) -> io::Result<SocketAddr> {
    let req = build_request(reply_src, reply_dst, libc::IPPROTO_UDP as u8)?;
    let sent = unsafe { libc::send(fd, req.as_ptr() as *const _, req.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = [0u8; 8192];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    parse_orig_dst(&buf[..n as usize])
}

/// Serialize an `IPCTNL_MSG_CT_GET` message that asks for the
/// conntrack entry whose REPLY tuple matches `(reply_src,
/// reply_dst, proto)`. Pure — split out so the wire layout has a
/// unit test that doesn't need the kernel.
pub(crate) fn build_request(
    reply_src: SocketAddr,
    reply_dst: SocketAddr,
    proto: u8,
) -> io::Result<Vec<u8>> {
    let family: u8 = match (&reply_src, &reply_dst) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => libc::AF_INET as u8,
        (SocketAddr::V6(_), SocketAddr::V6(_)) => libc::AF_INET6 as u8,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "conntrack tuple family mismatch",
            ))
        }
    };

    let mut out = Vec::with_capacity(128);
    // nlmsghdr (16); length and type backfilled at end.
    out.extend_from_slice(&[0u8; NLMSG_HDR_LEN]);
    // nfgenmsg.
    out.push(family);
    out.push(NFNETLINK_V0);
    out.extend_from_slice(&0u16.to_be_bytes()); // res_id (BE)

    // CTA_TUPLE_REPLY (nested).
    let tuple_start = out.len();
    out.extend_from_slice(&[0u8; 4]);
    write_tuple_payload(&mut out, reply_src, reply_dst, proto);
    let tuple_len = (out.len() - tuple_start) as u16;
    out[tuple_start..tuple_start + 2].copy_from_slice(&tuple_len.to_ne_bytes());
    out[tuple_start + 2..tuple_start + 4]
        .copy_from_slice(&(CTA_TUPLE_REPLY | NLA_F_NESTED).to_ne_bytes());

    // Backfill nlmsghdr.
    let total = out.len() as u32;
    out[0..4].copy_from_slice(&total.to_ne_bytes());
    out[4..6].copy_from_slice(&ct_msg_type(IPCTNL_MSG_CT_GET).to_ne_bytes());
    out[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    // seq + pid stay zero; kernel doesn't require them for non-dump.

    Ok(out)
}

fn write_tuple_payload(out: &mut Vec<u8>, src: SocketAddr, dst: SocketAddr, proto: u8) {
    // CTA_TUPLE_IP (nested).
    let ip_start = out.len();
    out.extend_from_slice(&[0u8; 4]);
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            write_nla(out, CTA_IP_V4_SRC, &s.ip().octets());
            write_nla(out, CTA_IP_V4_DST, &d.ip().octets());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            write_nla(out, CTA_IP_V6_SRC, &s.ip().octets());
            write_nla(out, CTA_IP_V6_DST, &d.ip().octets());
        }
        _ => unreachable!("family mismatch already rejected by build_request"),
    }
    let ip_len = (out.len() - ip_start) as u16;
    out[ip_start..ip_start + 2].copy_from_slice(&ip_len.to_ne_bytes());
    out[ip_start + 2..ip_start + 4]
        .copy_from_slice(&(CTA_TUPLE_IP | NLA_F_NESTED).to_ne_bytes());

    // CTA_TUPLE_PROTO (nested).
    let proto_start = out.len();
    out.extend_from_slice(&[0u8; 4]);
    write_nla(out, CTA_PROTO_NUM, &[proto]);
    write_nla(out, CTA_PROTO_SRC_PORT, &src.port().to_be_bytes());
    write_nla(out, CTA_PROTO_DST_PORT, &dst.port().to_be_bytes());
    let proto_len = (out.len() - proto_start) as u16;
    out[proto_start..proto_start + 2].copy_from_slice(&proto_len.to_ne_bytes());
    out[proto_start + 2..proto_start + 4]
        .copy_from_slice(&(CTA_TUPLE_PROTO | NLA_F_NESTED).to_ne_bytes());
}

/// Write one netlink attribute: `[u16 total_len][u16 type][data][pad
/// to 4]`. `total_len` is the size *including* the 4-byte header
/// but *excluding* the trailing pad bytes.
fn write_nla(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    let total_len = (4 + data.len()) as u16;
    out.extend_from_slice(&total_len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(data);
    // Pad to 4-byte alignment for the next attribute.
    let pad = (4 - (out.len() % 4)) % 4;
    for _ in 0..pad {
        out.push(0);
    }
}

/// Walk the response buffer, find the first `CT_NEW`-typed message
/// (the matched entry), pull `CTA_TUPLE_ORIG` out of it, return
/// the dst. Tolerates a trailing ACK; surfaces a netlink error code
/// (negative `errno`) as an `io::Error`. Pure — testable against a
/// hand-built byte buffer.
pub(crate) fn parse_orig_dst(buf: &[u8]) -> io::Result<SocketAddr> {
    let ct_new = ct_msg_type(IPCTNL_MSG_CT_NEW);

    let mut offset = 0;
    while offset + NLMSG_HDR_LEN <= buf.len() {
        let nlmsg_len =
            u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        let nlmsg_type =
            u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());

        if nlmsg_len < NLMSG_HDR_LEN || offset + nlmsg_len > buf.len() {
            break;
        }

        if nlmsg_type == ct_new {
            let payload_start = offset + NLMSG_HDR_LEN + NFGENMSG_LEN;
            let payload_end = offset + nlmsg_len;
            if payload_start > payload_end {
                break;
            }
            return parse_tuple_orig(&buf[payload_start..payload_end]);
        }

        if nlmsg_type == libc::NLMSG_ERROR as u16 {
            let err_offset = offset + NLMSG_HDR_LEN;
            if err_offset + 4 > buf.len() {
                break;
            }
            let err = i32::from_ne_bytes(
                buf[err_offset..err_offset + 4].try_into().unwrap(),
            );
            if err != 0 {
                return Err(io::Error::from_raw_os_error(-err));
            }
            // ACK with code 0 — the matched entry was in a prior
            // CT_NEW message that we already handled (or there
            // wasn't one; fall through to NotFound below).
        }

        offset += (nlmsg_len + 3) & !3;
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "conntrack entry not found for tuple",
    ))
}

fn parse_tuple_orig(payload: &[u8]) -> io::Result<SocketAddr> {
    for (ty, data) in walk_nlas(payload) {
        if ty & NLA_TYPE_MASK == CTA_TUPLE_ORIG {
            return parse_tuple(data);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "response missing CTA_TUPLE_ORIG",
    ))
}

fn parse_tuple(buf: &[u8]) -> io::Result<SocketAddr> {
    let mut dst_ip: Option<IpAddr> = None;
    let mut dport: Option<u16> = None;

    for (ty, data) in walk_nlas(buf) {
        let base = ty & NLA_TYPE_MASK;
        if base == CTA_TUPLE_IP {
            for (ty2, data2) in walk_nlas(data) {
                match (ty2 & NLA_TYPE_MASK, data2.len()) {
                    (CTA_IP_V4_DST, 4) => {
                        dst_ip = Some(IpAddr::V4(Ipv4Addr::new(
                            data2[0], data2[1], data2[2], data2[3],
                        )));
                    }
                    (CTA_IP_V6_DST, 16) => {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(data2);
                        dst_ip = Some(IpAddr::V6(Ipv6Addr::from(o)));
                    }
                    _ => {}
                }
            }
        } else if base == CTA_TUPLE_PROTO {
            for (ty2, data2) in walk_nlas(data) {
                if ty2 & NLA_TYPE_MASK == CTA_PROTO_DST_PORT && data2.len() == 2 {
                    dport = Some(u16::from_be_bytes([data2[0], data2[1]]));
                }
            }
        }
    }

    match (dst_ip, dport) {
        (Some(ip), Some(port)) => Ok(SocketAddr::new(ip, port)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "conntrack tuple missing dst ip / dst port",
        )),
    }
}

/// Yield `(raw_type, data)` for each netlink attribute in `buf`.
/// `raw_type` retains the NESTED / NET_BYTEORDER flag bits — callers
/// mask with `NLA_TYPE_MASK` for the underlying enum value.
fn walk_nlas(buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut offset = 0;
    std::iter::from_fn(move || {
        while offset + 4 <= buf.len() {
            let total_len =
                u16::from_ne_bytes([buf[offset], buf[offset + 1]]) as usize;
            let ty = u16::from_ne_bytes([buf[offset + 2], buf[offset + 3]]);
            if total_len < 4 || offset + total_len > buf.len() {
                return None;
            }
            let data_start = offset + 4;
            let data_end = offset + total_len;
            // Pad next offset to 4-byte alignment.
            offset += (total_len + 3) & !3;
            return Some((ty, &buf[data_start..data_end]));
        }
        None
    })
}

/// Test-only handles.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use super::*;

    pub fn build_request_for_test(
        reply_src: SocketAddr,
        reply_dst: SocketAddr,
        proto: u8,
    ) -> io::Result<Vec<u8>> {
        super::build_request(reply_src, reply_dst, proto)
    }

    pub fn parse_orig_dst_for_test(buf: &[u8]) -> io::Result<SocketAddr> {
        super::parse_orig_dst(buf)
    }

    /// Synthesise a minimal `CT_NEW` response that carries a
    /// `CTA_TUPLE_ORIG` with the given dst. Useful for testing the
    /// parser without rigging up real conntrack.
    pub fn synth_response_v4(orig_dst_ip: [u8; 4], orig_dst_port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        // nlmsghdr (backfill length).
        out.extend_from_slice(&[0u8; NLMSG_HDR_LEN]);
        // nfgenmsg.
        out.push(libc::AF_INET as u8);
        out.push(NFNETLINK_V0);
        out.extend_from_slice(&0u16.to_be_bytes());

        // CTA_TUPLE_ORIG (nested).
        let tup_start = out.len();
        out.extend_from_slice(&[0u8; 4]);
        // CTA_TUPLE_IP (nested) with dummy src + real dst.
        let ip_start = out.len();
        out.extend_from_slice(&[0u8; 4]);
        super::write_nla(&mut out, super::CTA_IP_V4_SRC, &[0, 0, 0, 0]);
        super::write_nla(&mut out, super::CTA_IP_V4_DST, &orig_dst_ip);
        let ip_len = (out.len() - ip_start) as u16;
        out[ip_start..ip_start + 2].copy_from_slice(&ip_len.to_ne_bytes());
        out[ip_start + 2..ip_start + 4]
            .copy_from_slice(&(super::CTA_TUPLE_IP | super::NLA_F_NESTED).to_ne_bytes());
        // CTA_TUPLE_PROTO (nested) with dummy sport + real dport.
        let proto_start = out.len();
        out.extend_from_slice(&[0u8; 4]);
        super::write_nla(&mut out, super::CTA_PROTO_NUM, &[libc::IPPROTO_UDP as u8]);
        super::write_nla(&mut out, super::CTA_PROTO_SRC_PORT, &0u16.to_be_bytes());
        super::write_nla(&mut out, super::CTA_PROTO_DST_PORT, &orig_dst_port.to_be_bytes());
        let proto_len = (out.len() - proto_start) as u16;
        out[proto_start..proto_start + 2].copy_from_slice(&proto_len.to_ne_bytes());
        out[proto_start + 2..proto_start + 4]
            .copy_from_slice(&(super::CTA_TUPLE_PROTO | super::NLA_F_NESTED).to_ne_bytes());
        let tup_len = (out.len() - tup_start) as u16;
        out[tup_start..tup_start + 2].copy_from_slice(&tup_len.to_ne_bytes());
        out[tup_start + 2..tup_start + 4]
            .copy_from_slice(&(super::CTA_TUPLE_ORIG | super::NLA_F_NESTED).to_ne_bytes());

        // Backfill nlmsghdr.
        let total = out.len() as u32;
        out[0..4].copy_from_slice(&total.to_ne_bytes());
        out[4..6].copy_from_slice(&super::ct_msg_type(super::IPCTNL_MSG_CT_NEW).to_ne_bytes());
        out
    }
}
