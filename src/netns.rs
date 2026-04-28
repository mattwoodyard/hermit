//! Composable functions for network namespace setup.
//!
//! These are designed to be called after `unshare(CLONE_NEWUSER | CLONE_NEWNET)`
//! when the process is uid 0 inside its own user+net namespace.
//!
//! nftables rules are programmed directly via netlink (the `rustables`
//! crate). There is no dependency on an external `nft` binary — hermit
//! talks to the kernel's netfilter subsystem itself.
//!
//! Each function does one thing and can be composed in the caller:
//!
//! ```no_run
//! # use hermit::netns;
//! netns::bring_up_loopback()?;
//! netns::add_nft_redirect(443, 1443)?;
//! netns::add_nft_redirect(80, 1080)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::{bail, Context, Result};
use log::{debug, info};
use rustables::{
    expr::{Immediate, Nat, NatType, Register},
    Batch, Chain, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule, Table,
};
use std::os::fd::AsRawFd;

// ---------------------------------------------------------------------------
// Loopback
// ---------------------------------------------------------------------------

/// Bring up the loopback interface inside the current network namespace.
///
/// Uses a raw `SIOCSIFFLAGS` ioctl to avoid depending on the `ip` binary.
/// This sets the IFF_UP flag on the "lo" interface.
pub fn bring_up_loopback() -> Result<()> {
    info!("netns: bringing up loopback interface");

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        bail!(
            "socket(AF_INET, SOCK_DGRAM) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let result = set_interface_up(sock, "lo");

    unsafe { libc::close(sock) };

    result.context("failed to bring up loopback")?;
    debug!("netns: loopback is up");
    Ok(())
}

/// Set the IFF_UP flag on a network interface via ioctl.
fn set_interface_up(sock: i32, ifname: &str) -> Result<()> {
    // struct ifreq: 16-byte name + union of at least 16 bytes
    #[repr(C)]
    struct Ifreq {
        ifr_name: [u8; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22], // padding to fill the union
    }

    if ifname.len() >= libc::IFNAMSIZ {
        bail!("interface name too long: {}", ifname);
    }

    let mut req: Ifreq = unsafe { std::mem::zeroed() };
    req.ifr_name[..ifname.len()].copy_from_slice(ifname.as_bytes());

    // SIOCGIFFLAGS to get current flags
    let ret = unsafe {
        libc::ioctl(
            sock,
            libc::SIOCGIFFLAGS as libc::c_ulong,
            &mut req as *mut Ifreq,
        )
    };
    if ret < 0 {
        bail!(
            "ioctl(SIOCGIFFLAGS, {}) failed: {}",
            ifname,
            std::io::Error::last_os_error()
        );
    }

    // Set IFF_UP
    req.ifr_flags |= libc::IFF_UP as libc::c_short;

    let ret = unsafe {
        libc::ioctl(
            sock,
            libc::SIOCSIFFLAGS as libc::c_ulong,
            &req as *const Ifreq,
        )
    };
    if ret < 0 {
        bail!(
            "ioctl(SIOCSIFFLAGS, {}) failed: {}",
            ifname,
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nftables rules — programmed via netlink (rustables), not the nft binary
// ---------------------------------------------------------------------------

/// Name of the nftables table hermit creates inside the child netns.
/// Single name (one place to change) and scoped so it can't collide with
/// host rules even if the netns ever leaked.
const TABLE_NAME: &str = "hermit_nat";
const TABLE_NAME_V6: &str = "hermit_nat_v6";

/// Build the IPv4 `Table` descriptor. Not a real kernel resource —
/// just the rustables handle that batch operations target.
fn hermit_table() -> Table {
    Table::new(ProtocolFamily::Ipv4).with_name(TABLE_NAME)
}

/// IPv6 counterpart. Lives in the `ip6` family because nftables
/// keeps v4 and v6 tables in disjoint namespaces; a rule that
/// matches v6 traffic must live in an `ip6` table or an `inet`
/// table, and we chose the former for clean separation.
fn hermit_table_v6() -> Table {
    Table::new(ProtocolFamily::Ipv6).with_name(TABLE_NAME_V6)
}

/// Send a rustables `Batch` to the kernel via netlink.
///
/// We avoid `Batch::send()` because rustables 0.8.7 has an I/O-safety bug
/// there — the netlink socket fd is both closed manually (via
/// `nix::unistd::close`) and then a second time by the `OwnedFd::Drop`
/// that wraps the same fd. In a forking program like hermit this triggers
/// `fatal runtime error: IO Safety violation: owned file descriptor
/// already closed, aborting`. We use `Batch::finalize()` to obtain the
/// serialized netlink bytes and ship them ourselves with proper fd
/// ownership.
fn send_batch(batch: Batch) -> Result<()> {
    use nix::sys::socket::{
        self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
    };

    let bytes = batch.finalize();

    let sock = socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::NetlinkNetFilter,
    )
    .context("opening netlink socket")?;

    socket::bind(sock.as_raw_fd(), &NetlinkAddr::new(0, 0))
        .context("binding netlink socket")?;

    // 5-second ceiling on the *first* blocking recv so a missing kernel
    // reply can't hang us forever. Subsequent recvs use MSG_DONTWAIT so
    // we don't burn this timeout per batch — see the drain loop below.
    let timeout = nix::sys::time::TimeVal::new(5, 0);
    socket::setsockopt(&sock, nix::sys::socket::sockopt::ReceiveTimeout, &timeout)
        .context("setting SO_RCVTIMEO on netlink socket")?;

    let mut sent = 0;
    while sent < bytes.len() {
        let n = socket::send(sock.as_raw_fd(), &bytes[sent..], MsgFlags::empty())
            .context("netlink send")?;
        if n == 0 {
            bail!("netlink send returned 0 bytes");
        }
        sent += n;
    }

    // Rustables sets NLM_F_ACK on every object message, so the kernel
    // replies with an `nlmsgerr` per message (error=0 = success). In
    // practice all ACKs for a small batch come back in a single datagram.
    //
    // Strategy: one blocking recv to catch the initial reply, then drain
    // anything else non-blocking. The drain returns EAGAIN immediately
    // once the socket queue is empty — no dead wait on SO_RCVTIMEO.
    let mut buf = vec![0u8; 32 * 1024];
    match socket::recv(sock.as_raw_fd(), &mut buf, MsgFlags::empty()) {
        Ok(0) => return Ok(()),
        Ok(n) => check_netlink_acks(&buf[..n])?,
        Err(e) => bail!("netlink recv (first ack): {e}"),
    }
    loop {
        match socket::recv(sock.as_raw_fd(), &mut buf, MsgFlags::MSG_DONTWAIT) {
            Ok(0) => break,
            Ok(n) => check_netlink_acks(&buf[..n])?,
            // EAGAIN and EWOULDBLOCK are the same errno on Linux, but we
            // write them separately for portability — `#[allow]` keeps
            // the duplicate arm from tripping unreachable_patterns.
            #[allow(unreachable_patterns)]
            Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EWOULDBLOCK) => break,
            Err(e) => bail!("netlink recv (drain): {e}"),
        }
    }

    // OwnedFd dropped here — closed exactly once.
    Ok(())
}

/// Walk a block of netlink messages looking for `nlmsgerr` entries.
/// Return `Err` on the first nonzero error code. Success ACKs (error=0)
/// are acceptable and silently consumed.
fn check_netlink_acks(buf: &[u8]) -> Result<()> {
    const NLMSG_HDR_LEN: usize = 16;
    let mut offset = 0;
    while offset + NLMSG_HDR_LEN <= buf.len() {
        let nlmsg_len = u32::from_ne_bytes(
            buf[offset..offset + 4].try_into().unwrap(),
        ) as usize;
        let nlmsg_type = u16::from_ne_bytes(
            buf[offset + 4..offset + 6].try_into().unwrap(),
        );
        if nlmsg_len < NLMSG_HDR_LEN || offset + nlmsg_len > buf.len() {
            break;
        }
        if nlmsg_type == libc::NLMSG_ERROR as u16 {
            if offset + NLMSG_HDR_LEN + 4 > buf.len() {
                break;
            }
            let err = i32::from_ne_bytes(
                buf[offset + NLMSG_HDR_LEN..offset + NLMSG_HDR_LEN + 4]
                    .try_into()
                    .unwrap(),
            );
            if err != 0 {
                // Kernel reports negative errno; flip the sign for the os_error.
                let errno = -err;
                bail!(
                    "nftables netlink error: {}",
                    std::io::Error::from_raw_os_error(errno)
                );
            }
        }
        // Netlink messages are aligned to 4 bytes.
        offset += (nlmsg_len + 3) & !3;
    }
    Ok(())
}

/// Build the output-hook nat chain descriptor on `table`.
fn output_chain(table: &Table) -> Chain {
    Chain::new(table)
        .with_name("output")
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_type(ChainType::Nat)
}

/// Create the IPv4 nftables nat table and output chain.
///
/// Must be called before `add_nft_redirect`. Safe to call multiple times:
/// `MsgType::Add` without `NLM_F_EXCL` is a no-op when the object already
/// exists, matching the semantics of `nft add table ...`.
pub fn ensure_nft_nat_table() -> Result<()> {
    info!("netns: ensuring nftables nat table exists (via netlink)");
    let table = hermit_table();
    let chain = output_chain(&table);

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&chain, MsgType::Add);
    send_batch(batch).context("creating nat table/chain")?;
    Ok(())
}

/// IPv6 counterpart. Called lazily (only when an IPv6 DNAT rule is
/// about to be inserted) so configs that don't use IPv6 bypass
/// don't pay for an empty table.
pub fn ensure_nft_nat_table_v6() -> Result<()> {
    info!("netns: ensuring nftables nat table (ip6) exists (via netlink)");
    let table = hermit_table_v6();
    let chain = output_chain(&table);

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&chain, MsgType::Add);
    send_batch(batch).context("creating ip6 nat table/chain")?;
    Ok(())
}

/// Add a TCP nat rule: `tcp dport <from_port>` → `127.0.0.1:<to_port>`.
/// See [`add_nft_redirect_proto`] for the shared implementation; this
/// preserves the original TCP-only signature that call sites expect.
pub fn add_nft_redirect(from_port: u16, to_port: u16) -> Result<()> {
    add_nft_redirect_proto(Protocol::TCP, from_port, to_port)
}

/// Add a UDP nat rule: `udp dport <from_port>` → `127.0.0.1:<to_port>`.
pub fn add_nft_redirect_udp(from_port: u16, to_port: u16) -> Result<()> {
    add_nft_redirect_proto(Protocol::UDP, from_port, to_port)
}

/// Catch-all TCP DNAT: `meta l4proto tcp` → `127.0.0.1:<to_port>`.
///
/// Used by `hermit learn` to install a wildcard observer at the
/// loopback `to_port` so connections on un-proxied ports don't
/// vanish into a "no route to host" error — instead the observer
/// records the (dst_ip, dst_port) for the trace.
///
/// **Ordering matters.** Install this *before* the port-specific
/// rules. nftables evaluates NAT rules in order on the first
/// packet of a flow, and a later `dnat` overwrites an earlier
/// one. So the conventional layout is:
///
/// ```text
/// add_nft_redirect_all_tcp(LEARN_OBSERVER_PORT) // catch-all, FIRST
/// add_nft_redirect(443, MITM_PORT)              // overwrites for :443
/// add_nft_redirect(80,  HTTP_PROXY_PORT)        // overwrites for :80
/// ```
///
/// With this order a packet for :443 hits the catch-all (DNAT to
/// observer) and then the specific rule (DNAT to MITM); the second
/// `dnat` wins. A packet for :22 hits only the catch-all, so it
/// goes to the observer.
pub fn add_nft_redirect_all_tcp(to_port: u16) -> Result<()> {
    info!(
        "netns: adding catch-all nat rule (tcp -> 127.0.0.1:{}) (via netlink)",
        to_port
    );
    let table = hermit_table();
    let chain = output_chain(&table);

    let dst_ip: [u8; 4] = [127, 0, 0, 1];
    let dst_port: [u8; 2] = to_port.to_be_bytes();

    // No `dport` predicate — `protocol(Protocol::TCP)` matches
    // every TCP packet. Same DNAT register layout as the
    // port-specific rules in `add_nft_redirect_proto`.
    let rule = Rule::new(&chain)
        .context("constructing catch-all nat rule")?
        .protocol(Protocol::TCP)
        .with_expr(Immediate::new_data(dst_ip.to_vec(), Register::Reg1))
        .with_expr(Immediate::new_data(dst_port.to_vec(), Register::Reg2))
        .with_expr(
            Nat::default()
                .with_nat_type(NatType::DNat)
                .with_family(ProtocolFamily::Ipv4)
                .with_ip_register(Register::Reg1)
                .with_port_register(Register::Reg2),
        );

    let mut batch = Batch::new();
    batch.add(&rule, MsgType::Add);
    send_batch(batch).with_context(|| {
        format!("adding catch-all rule tcp -> :{to_port}")
    })?;
    Ok(())
}

/// IPv6 UDP DNAT: `udp dport <from_port>` → `[::1]:<to_port>`. The
/// table family is `ip6`, so call [`ensure_nft_nat_table_v6`] first.
///
/// This is the UDP-v6 sibling of [`add_nft_redirect_proto`]. It
/// mirrors that function's structure but targets the `ip6` table and
/// installs an IPv6 loopback address in the NAT registers.
pub fn add_nft_redirect_udp_v6(from_port: u16, to_port: u16) -> Result<()> {
    info!(
        "netns: adding nat rule (ip6) udp dport {} -> [::1]:{} (via netlink)",
        from_port, to_port
    );
    let table = hermit_table_v6();
    let chain = output_chain(&table);

    // ::1 as 16 bytes in network byte order.
    let mut dst_ip = [0u8; 16];
    dst_ip[15] = 1;
    let dst_port: [u8; 2] = to_port.to_be_bytes();

    let rule = Rule::new(&chain)
        .context("constructing nat rule")?
        .dport(from_port, Protocol::UDP)
        .with_expr(Immediate::new_data(dst_ip.to_vec(), Register::Reg1))
        .with_expr(Immediate::new_data(dst_port.to_vec(), Register::Reg2))
        .with_expr(
            Nat::default()
                .with_nat_type(NatType::DNat)
                .with_family(ProtocolFamily::Ipv6)
                .with_ip_register(Register::Reg1)
                .with_port_register(Register::Reg2),
        );

    let mut batch = Batch::new();
    batch.add(&rule, MsgType::Add);
    send_batch(batch)
        .with_context(|| format!("adding rule udp6:{from_port} -> :{to_port}"))?;
    Ok(())
}

/// Shared implementation of [`add_nft_redirect`] + its UDP sibling.
///
/// Note: this is DNAT-to-loopback, not `REDIRECT`. For output-hook NAT
/// the two behave equivalently (REDIRECT is shorthand for DNAT to the
/// interface's primary address; here we target loopback explicitly).
/// rustables 0.8 does not expose the `redir` expression, so DNAT is the
/// supported path.
///
/// Call `ensure_nft_nat_table` first.
pub fn add_nft_redirect_proto(
    protocol: Protocol,
    from_port: u16,
    to_port: u16,
) -> Result<()> {
    let proto_name = match protocol {
        Protocol::TCP => "tcp",
        Protocol::UDP => "udp",
    };
    info!(
        "netns: adding nat rule {} dport {} -> 127.0.0.1:{} (via netlink)",
        proto_name, from_port, to_port
    );
    let table = hermit_table();
    let chain = output_chain(&table);

    // DNAT reads destination address from `Reg1` and destination port from
    // `Reg2`. `Immediate` expressions load each value (in network byte
    // order) into those registers before the `Nat` expression runs.
    let dst_ip: [u8; 4] = [127, 0, 0, 1];
    let dst_port: [u8; 2] = to_port.to_be_bytes();

    let rule = Rule::new(&chain)
        .context("constructing nat rule")?
        .dport(from_port, protocol)
        .with_expr(Immediate::new_data(dst_ip.to_vec(), Register::Reg1))
        .with_expr(Immediate::new_data(dst_port.to_vec(), Register::Reg2))
        .with_expr(
            Nat::default()
                .with_nat_type(NatType::DNat)
                .with_family(ProtocolFamily::Ipv4)
                .with_ip_register(Register::Reg1)
                .with_port_register(Register::Reg2),
        );

    let mut batch = Batch::new();
    batch.add(&rule, MsgType::Add);
    send_batch(batch).with_context(|| {
        format!("adding rule {proto_name}:{from_port} -> :{to_port}")
    })?;
    Ok(())
}

/// Remove the hermit nftables tables (v4 + v6) and everything in
/// them.
///
/// Uses the Add+Del idempotency pattern so this succeeds whether or
/// not the tables already exist, matching `nft delete table` which
/// errors on a missing table.
pub fn cleanup_nft() -> Result<()> {
    info!(
        "netns: removing nftables {} / {} tables (via netlink)",
        TABLE_NAME, TABLE_NAME_V6
    );
    let t4 = hermit_table();
    let t6 = hermit_table_v6();
    let mut batch = Batch::new();
    batch.add(&t4, MsgType::Add); // make Del succeed if table absent
    batch.add(&t4, MsgType::Del);
    batch.add(&t6, MsgType::Add);
    batch.add(&t6, MsgType::Del);
    send_batch(batch).context("deleting nat tables")?;
    Ok(())
}

// `list_nft_ruleset` was intentionally dropped along with the shell-out —
// the rustables `list_*` helpers share the same I/O-safety bug as
// `Batch::send`, and nothing in hermit's runtime path consumed it.
// Reintroduce with our own netlink list path if we ever need it for
// debugging.

// ---------------------------------------------------------------------------
// resolv.conf
// ---------------------------------------------------------------------------

/// Write a resolv.conf pointing at localhost and bind-mount it over /etc/resolv.conf.
///
/// This makes the sandboxed process's DNS queries go to our fake DNS server
/// running on 127.0.0.1:53 inside the network namespace.
///
/// Must be called after the mount namespace is set up (so the bind mount
/// doesn't leak to the host).
pub fn write_resolv_conf() -> Result<()> {
    use nix::mount::{mount, MsFlags};

    let tmp_resolv = format!("/tmp/.hermit-{}-resolv.conf", std::process::id());
    std::fs::write(&tmp_resolv, "nameserver 127.0.0.1\n")
        .context("failed to write temporary resolv.conf")?;

    info!("netns: bind-mounting resolv.conf => /etc/resolv.conf");
    mount(
        Some(tmp_resolv.as_str()),
        "/etc/resolv.conf",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("failed to bind-mount resolv.conf")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// High-level orchestration
// ---------------------------------------------------------------------------

/// Set up network namespace for proxied isolation.
///
/// 1. Brings up loopback
/// 2. Creates nftables nat table
/// 3. Adds REDIRECT rules for each (from_port, to_port) pair
///
/// The `redirects` slice contains `(original_port, proxy_port)` pairs.
/// Typically: `[(443, 1443)]` for HTTPS-only, or
/// `[(443, 1443), (80, 1080)]` for HTTPS + HTTP.
pub fn setup_proxied_netns(redirects: &[(u16, u16)]) -> Result<()> {
    bring_up_loopback()?;
    ensure_nft_nat_table()?;
    for &(from, to) in redirects {
        add_nft_redirect(from, to)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_descriptor_has_expected_name() {
        let t = hermit_table();
        assert_eq!(t.get_name().map(|s| s.as_str()), Some(TABLE_NAME));
    }

    #[test]
    fn output_chain_descriptor_is_nat_on_output_hook() {
        let t = hermit_table();
        let c = output_chain(&t);
        assert_eq!(c.get_name().map(|s| s.as_str()), Some("output"));
        assert_eq!(c.get_type(), Some(&ChainType::Nat));
        let hook = c.get_hook().expect("hook set");
        // get_class returns the raw NF_INET_LOCAL_OUT value, not the enum.
        assert_eq!(hook.get_class().copied(), Some(libc::NF_INET_LOCAL_OUT as u32));
    }

    #[test]
    fn redirect_rule_builds_without_error() {
        // We can construct the rule descriptor without touching the kernel.
        // Sending the batch would need CAP_NET_ADMIN; we don't do that here.
        let t = hermit_table();
        let c = output_chain(&t);
        let r = Rule::new(&c)
            .expect("rule constructor")
            .dport(443, Protocol::TCP)
            .with_expr(Immediate::new_data(vec![127, 0, 0, 1], Register::Reg1))
            .with_expr(Immediate::new_data(1443u16.to_be_bytes().to_vec(), Register::Reg2))
            .with_expr(
                Nat::default()
                    .with_nat_type(NatType::DNat)
                    .with_family(ProtocolFamily::Ipv4)
                    .with_ip_register(Register::Reg1)
                    .with_port_register(Register::Reg2),
            );
        // Non-empty expression list == builder succeeded.
        assert!(r.get_expressions().is_some());
    }

    #[test]
    fn set_interface_up_rejects_long_name() {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(sock >= 0);
        let long_name = "a".repeat(libc::IFNAMSIZ + 1);
        let result = set_interface_up(sock, &long_name);
        unsafe { libc::close(sock) };
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn set_interface_up_fails_on_nonexistent_interface() {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(sock >= 0);
        let result = set_interface_up(sock, "hermittest0");
        unsafe { libc::close(sock) };
        // Should fail — interface doesn't exist
        assert!(result.is_err());
    }
}
