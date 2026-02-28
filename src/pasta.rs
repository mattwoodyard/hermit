use anyhow::{bail, Context, Result};
use log::info;
use nix::unistd::Pid;
use std::path::PathBuf;
use std::process::Command;

const PASTA_PATH: &str = match option_env!("PASTA_BINARY") {
    Some(p) => p,
    None => "/usr/bin/pasta",
};
const SNI_PROXY_BIN: &str = "sni-proxy";

/// Default listen address for the SNI proxy.
pub const SNI_PROXY_LISTEN: &str = "127.0.0.1:1443";

/// Locate the pasta binary, returning its path or an error if not found.
pub fn find_pasta() -> Result<PathBuf> {
    let path = PathBuf::from(PASTA_PATH);
    if path.exists() {
        Ok(path)
    } else {
        bail!(
            "pasta not found at {}; install passt (https://passt.top)",
            PASTA_PATH
        )
    }
}

/// Launch pasta targeting the given child PID's network namespace.
///
/// Pasta runs in the host namespace, creates a tap device in the child's
/// network namespace, and translates L2 tap traffic to L4 host sockets.
/// It daemonizes once the tap device is ready, so this call blocks until
/// pasta is set up (or returns an error on failure).
pub fn launch_pasta(child_pid: Pid) -> Result<()> {
    let pasta_bin = find_pasta()?;

    info!("using pasta binary: {}", pasta_bin.display());
    info!("launching pasta for child PID {}", child_pid);
    let output = Command::new(&pasta_bin)
        .arg("--config-net")
        .arg(child_pid.to_string())
        .output()
        .with_context(|| format!("failed to execute {}", pasta_bin.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "pasta exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }

    info!("pasta daemonized successfully for PID {}", child_pid);
    Ok(())
}

/// Parse the default gateway from `ip route show default` output.
///
/// Expected format: `default via <gateway> dev <iface> ...`
fn parse_gateway(ip_route_output: &str) -> Result<String> {
    ip_route_output
        .split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1)
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no default gateway found in: {}",
                ip_route_output.trim()
            )
        })
}

/// Discover the default gateway inside the current network namespace.
fn discover_gateway() -> Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("failed to execute 'ip route show default'")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_gateway(&stdout)
}

/// Set up iptables DNAT inside the network namespace to redirect outbound
/// HTTPS traffic (port 443) to the SNI proxy via the namespace's default gateway.
///
/// Pasta's `--map-host-loopback` (default: gateway address) maps the gateway
/// to the host's loopback, so DNAT to gateway:proxy_port reaches the SNI proxy
/// running on the host.
pub fn setup_sni_redirect(proxy_port: u16) -> Result<()> {
    let gateway = discover_gateway()?;
    let dest = format!("{}:{}", gateway, proxy_port);
    info!("setting up iptables DNAT: tcp/443 -> {}", dest);

    let output = Command::new("iptables")
        .args([
            "-t", "nat",
            "-A", "OUTPUT",
            "-p", "tcp",
            "--dport", "443",
            "-j", "DNAT",
            "--to-destination", &dest,
        ])
        .output()
        .context("failed to execute iptables")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("iptables DNAT setup failed: {}", stderr.trim());
    }

    info!("iptables DNAT rule installed successfully");
    Ok(())
}

/// Locate the sni-proxy binary by searching `$PATH`.
pub fn find_sni_proxy() -> Result<PathBuf> {
    which::which(SNI_PROXY_BIN).map_err(|_| {
        anyhow::anyhow!(
            "{} not found in $PATH; install sni-proxy from platform/sni-proxy",
            SNI_PROXY_BIN
        )
    })
}

/// RAII wrapper around the sni-proxy child process.
/// Kills the process on drop.
pub struct SniProxyChild(std::process::Child);

impl SniProxyChild {
    /// Explicitly kill and reap the proxy process.
    pub fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for SniProxyChild {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Launch sni-proxy as a background process.
///
/// The proxy listens on `listen_addr` and only permits connections to
/// hostnames in `allowed_hosts`. Returns an RAII handle that kills the
/// process on drop.
pub fn launch_sni_proxy(
    listen_addr: &str,
    allowed_hosts: &[String],
) -> Result<SniProxyChild> {
    let bin = find_sni_proxy()?;
    let hosts = allowed_hosts.join(",");

    info!(
        "launching sni-proxy on {} for hosts: {}",
        listen_addr, hosts
    );

    let child = Command::new(&bin)
        .args(["--listen", listen_addr, "--allowed-hosts", &hosts])
        .stderr(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn {}", bin.display()))?;

    let mut wrapper = SniProxyChild(child);

    // Brief pause to detect early failures (e.g. bind errors)
    std::thread::sleep(std::time::Duration::from_millis(50));

    match wrapper.0.try_wait() {
        Ok(Some(status)) => {
            bail!("sni-proxy exited immediately with {}", status);
        }
        Ok(None) => {
            info!("sni-proxy running (pid {})", wrapper.0.id());
        }
        Err(e) => {
            bail!("failed to check sni-proxy status: {}", e);
        }
    }

    Ok(wrapper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_pasta_adapts_to_system() {
        // This test passes on any system — it just checks consistency.
        let result = find_pasta();
        if PathBuf::from(PASTA_PATH).exists() {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), PathBuf::from(PASTA_PATH));
        } else {
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("pasta not found"));
        }
    }

    #[test]
    fn test_launch_pasta_bogus_pid() {
        if find_pasta().is_err() {
            // pasta not installed, skip
            return;
        }
        // PID 0 is the kernel — pasta should fail to attach
        let result = launch_pasta(Pid::from_raw(999_999_999));
        assert!(result.is_err(), "expected error for bogus PID");
    }

    #[test]
    #[cfg(feature = "vendored-pasta")]
    fn test_pasta_path_not_default_when_vendored() {
        assert_ne!(
            PASTA_PATH, "/usr/bin/pasta",
            "vendored-pasta feature should set a non-default PASTA_PATH"
        );
    }

    #[test]
    fn test_parse_gateway_typical() {
        let output = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n";
        assert_eq!(parse_gateway(output).unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_parse_gateway_pasta_tap() {
        let output = "default via 10.0.2.2 dev tap0\n";
        assert_eq!(parse_gateway(output).unwrap(), "10.0.2.2");
    }

    #[test]
    fn test_parse_gateway_no_default() {
        let output = "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n";
        let err = parse_gateway(output).unwrap_err();
        assert!(
            err.to_string().contains("no default gateway"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_gateway_empty() {
        let err = parse_gateway("").unwrap_err();
        assert!(err.to_string().contains("no default gateway"));
    }

    #[test]
    fn test_find_sni_proxy_adapts_to_system() {
        let result = find_sni_proxy();
        if which::which(SNI_PROXY_BIN).is_ok() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("not found"), "unexpected error: {}", msg);
        }
    }

    #[test]
    fn test_sni_proxy_child_drop_kills() {
        // Wrap a `sleep` process in SniProxyChild, drop it, verify it's dead.
        let child = std::process::Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("failed to spawn sleep");
        let pid = child.id();
        let wrapper = SniProxyChild(child);
        drop(wrapper);
        // After drop, the process should be dead. kill(0) checks existence.
        let alive = unsafe { libc::kill(pid as i32, 0) };
        assert_ne!(alive, 0, "process {} should be dead after drop", pid);
    }
}
