//! Composable functions for network namespace setup.
//!
//! These are designed to be called after `unshare(CLONE_NEWUSER | CLONE_NEWNET)`
//! when the process is uid 0 inside its own user+net namespace.
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
use std::process::Command;

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
// nftables rules
// ---------------------------------------------------------------------------

/// Path to the nft binary. Resolved once at first use.
fn nft_path() -> Result<std::path::PathBuf> {
    which::which("nft").context(
        "nft not found in PATH; install nftables to use network isolation",
    )
}

/// Run an `nft` command with the given arguments.
fn run_nft(args: &[&str]) -> Result<()> {
    let nft = nft_path()?;
    debug!("netns: nft {}", args.join(" "));
    let output = Command::new(&nft)
        .args(args)
        .output()
        .with_context(|| format!("failed to run nft {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nft {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

/// Create the nftables nat table and output chain (idempotent).
///
/// Must be called before `add_nft_redirect`. Safe to call multiple times.
pub fn ensure_nft_nat_table() -> Result<()> {
    info!("netns: ensuring nftables nat table exists");
    run_nft(&["add", "table", "ip", "hermit_nat"])?;
    run_nft(&[
        "add",
        "chain",
        "ip",
        "hermit_nat",
        "output",
        "{ type nat hook output priority 0 ; }",
    ])?;
    Ok(())
}

/// Add an nftables REDIRECT rule: connections to `from_port` are redirected
/// to `to_port` on localhost where the SNI proxy listens.
///
/// Call `ensure_nft_nat_table` first.
pub fn add_nft_redirect(from_port: u16, to_port: u16) -> Result<()> {
    info!(
        "netns: adding nftables redirect tcp:{} -> :{}",
        from_port, to_port
    );
    let rule = format!("tcp dport {} redirect to :{}", from_port, to_port);
    run_nft(&[
        "add",
        "rule",
        "ip",
        "hermit_nat",
        "output",
        &rule,
    ])
}

/// Remove all hermit nftables rules (cleanup).
pub fn cleanup_nft() -> Result<()> {
    info!("netns: removing nftables hermit_nat table");
    // "delete table" removes the table and all chains/rules in it
    run_nft(&["delete", "table", "ip", "hermit_nat"])
}

/// List current nftables ruleset (for debugging).
pub fn list_nft_ruleset() -> Result<String> {
    let nft = nft_path()?;
    let output = Command::new(&nft)
        .args(["list", "ruleset"])
        .output()
        .context("failed to run nft list ruleset")?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

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
    fn nft_path_finds_binary_or_errors() {
        // Just verify it doesn't panic — result depends on system
        let _ = nft_path();
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
