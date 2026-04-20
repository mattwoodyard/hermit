use anyhow::{bail, Context, Result};
use log::{debug, error, info};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use sni_proxy::policy::RuleSet;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use crate::cli::NetMode;
use crate::fdpass;
use crate::home_files::HomeFileDirective;
use crate::landlock::apply_landlock;
use crate::namespace::setup_namespace;
use crate::netns;

/// PID of the child process, used by signal handlers.
/// 0 means no child yet (signals are no-ops).
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// Port the MITM proxy listens on inside the network namespace (HTTPS).
const PROXY_LISTEN_PORT: u16 = 1443;
/// Port the HTTP proxy listens on inside the network namespace.
const HTTP_PROXY_LISTEN_PORT: u16 = 1080;
/// Port to redirect (HTTPS) to the MITM proxy.
const HTTPS_PORT: u16 = 443;
/// Port to redirect (HTTP) to the HTTP proxy.
const HTTP_PORT: u16 = 80;

// --- Readiness pipe ---

/// Read end of the readiness pipe. Parent blocks on this until child signals.
pub struct ReadyReader(i32);

/// Write end of the readiness pipe. Child signals readiness then drops.
pub struct ReadyWriter(i32);

/// Create a readiness pipe pair. The child writes one byte after namespace
/// setup completes; the parent blocks until that byte arrives.
pub fn readiness_pipe() -> Result<(ReadyReader, ReadyWriter)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        bail!(
            "pipe2 failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok((ReadyReader(fds[0]), ReadyWriter(fds[1])))
}

impl ReadyReader {
    /// Block until the child signals readiness (writes 1 byte) or the pipe
    /// closes (child died before signaling).
    pub fn wait(&self) -> Result<()> {
        let mut buf = [0u8; 1];
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if n == 1 {
            Ok(())
        } else if n == 0 {
            bail!("child died before signaling readiness")
        } else {
            bail!(
                "readiness pipe read failed: {}",
                std::io::Error::last_os_error()
            )
        }
    }
}

impl Drop for ReadyReader {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl ReadyWriter {
    /// Signal readiness by writing 1 byte, then close (consumed by drop).
    pub fn signal(self) {
        let buf = [1u8; 1];
        unsafe { libc::write(self.0, buf.as_ptr() as *const libc::c_void, 1) };
        // fd closed by Drop
    }
}

impl Drop for ReadyWriter {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// --- Signal forwarding ---

/// Install signal handlers that forward SIGTERM, SIGINT, SIGHUP to the child.
fn install_signal_forwarding(child_pid: Pid) {
    CHILD_PID.store(child_pid.as_raw(), Ordering::SeqCst);

    let handler = SigHandler::Handler(forward_signal);
    let action = SigAction::new(handler, SaFlags::SA_RESTART, SigSet::empty());

    for sig in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP] {
        if let Err(e) = unsafe { sigaction(sig, &action) } {
            debug!("failed to install handler for {:?}: {}", sig, e);
        }
    }
}

/// Async-signal-safe handler: forward the signal to the child process.
extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

// --- Wait for child ---

/// Wait for the child process and return its exit code.
/// Uses shell convention: signal death → 128 + signal number.
fn wait_for_child(pid: Pid) -> Result<i32> {
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                info!("child exited with code {}", code);
                return Ok(code);
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                let code = 128 + sig as i32;
                info!("child killed by signal {:?} (exit code {})", sig, code);
                return Ok(code);
            }
            Ok(status) => {
                // Stopped/Continued — keep waiting
                debug!("child status: {:?}, continuing wait", status);
                continue;
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e).context("waitpid failed"),
        }
    }
}

// =========================================================================
// Plain isolated fork (no proxy)
// =========================================================================

/// Run a sandboxed command in a forked child with network namespace isolation.
///
/// The parent forks, the child sets up namespaces (including CLONE_NEWNET)
/// and landlock, signals readiness, then exec's the command. The parent
/// installs signal forwarding and waits for the child to exit.
pub fn run_forked(
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    rw_paths: &[&Path],
    command: &[String],
    _net: &NetMode,
) -> Result<i32> {
    let (ns_reader, ns_writer) = readiness_pipe()?;

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => {
            drop(ns_reader);
            child_main(ns_writer, home_path, project_dir, passthrough, home_files, rw_paths, command);
        }
        ForkResult::Parent { child } => {
            drop(ns_writer);
            parent_main(ns_reader, child)
        }
    }
}

/// Child side of the fork. Sets up namespaces + landlock, signals ready, execs.
/// This function never returns — it either execs or exits with 126.
fn child_main(
    ns_ready: ReadyWriter,
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    rw_paths: &[&Path],
    command: &[String],
) -> ! {
    // If the parent dies, kill us immediately
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };

    // Set up namespace isolation (user + mount + net)
    if let Err(e) = setup_namespace(home_path, project_dir, passthrough, home_files, true) {
        eprintln!("hermit: namespace setup failed: {:#}", e);
        std::process::exit(126);
    }

    // Apply landlock MAC policy
    if let Err(e) = apply_landlock(rw_paths) {
        eprintln!("hermit: landlock setup failed: {:#}", e);
        std::process::exit(126);
    }

    // Signal parent that namespace + landlock are ready
    ns_ready.signal();

    info!("child: exec {:?}", command);
    let err = Command::new(&command[0]).args(&command[1..]).exec();
    eprintln!("hermit: exec failed: {}", err);
    std::process::exit(126);
}

/// Parent side of the fork. Forwards signals and waits for child exit.
fn parent_main(
    ns_reader: ReadyReader,
    child: Pid,
) -> Result<i32> {
    install_signal_forwarding(child);

    // Wait for child to finish namespace + landlock setup
    ns_reader.wait()?;
    info!("parent: child namespace ready");

    info!("parent: waiting for child exit");
    wait_for_child(child)
}

// =========================================================================
// Proxied fork (SNI proxy + fake DNS in parent, nftables in child)
// =========================================================================

/// Run a sandboxed command with SNI proxy and fake DNS.
///
/// Architecture:
/// 1. Create socketpair for fd passing + readiness pipe
/// 2. Fork
/// 3. Child: unshare(user+mount+net), bring up loopback, create TCP/UDP
///    listener sockets, set up nftables REDIRECT, send socket fds to parent,
///    bind-mount resolv.conf, apply landlock, signal readiness, exec command
/// 4. Parent: receive socket fds, wait for readiness, start tokio runtime
///    with SNI proxy + DNS server, wait for child to exit, shut down
pub fn run_forked_proxied(
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    rw_paths: &[&Path],
    command: &[String],
    policy: Arc<RuleSet>,
    network_policy: Option<Arc<sni_proxy::network_policy::NetworkPolicy>>,
) -> Result<i32> {
    // Generate the ephemeral CA before fork so both parent and child can use it.
    let ca = Arc::new(
        sni_proxy::ca::CertificateAuthority::new()
            .context("failed to generate ephemeral CA")?,
    );
    let ca_pem = ca.ca_cert_pem().to_string();

    let (ns_reader, ns_writer) = readiness_pipe()?;
    let (parent_sock, child_sock) = fdpass::socketpair()?;

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => {
            drop(ns_reader);
            fdpass::close_fd(parent_sock);
            child_main_proxied(
                ns_writer,
                child_sock,
                &ca_pem,
                home_path,
                project_dir,
                passthrough,
                home_files,
                rw_paths,
                command,
            );
        }
        ForkResult::Parent { child } => {
            drop(ns_writer);
            fdpass::close_fd(child_sock);
            parent_main_proxied(ns_reader, child, parent_sock, policy, ca, network_policy)
        }
    }
}

/// Child side of the proxied fork.
///
/// Sets up the network namespace with loopback + nftables REDIRECT,
/// creates listener sockets, sends them to the parent, then execs the command.
fn child_main_proxied(
    ns_ready: ReadyWriter,
    sock_fd: i32,
    ca_pem: &str,
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    rw_paths: &[&Path],
    command: &[String],
) -> ! {
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };

    if let Err(e) = child_proxied_setup(
        sock_fd, ca_pem, home_path, project_dir, passthrough, home_files, rw_paths,
    ) {
        eprintln!("hermit: proxied namespace setup failed: {:#}", e);
        std::process::exit(126);
    }

    ns_ready.signal();

    info!("child: exec {:?}", command);
    let err = Command::new(&command[0]).args(&command[1..]).exec();
    eprintln!("hermit: exec failed: {}", err);
    std::process::exit(126);
}

/// All fallible setup for the proxied child, collected so errors propagate cleanly.
fn child_proxied_setup(
    sock_fd: i32,
    ca_pem: &str,
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    rw_paths: &[&Path],
) -> Result<()> {
    // Set up namespace isolation (user + mount + net)
    setup_namespace(home_path, project_dir, passthrough, home_files, true)?;

    // Network namespace setup
    netns::bring_up_loopback()?;
    netns::ensure_nft_nat_table()?;
    netns::add_nft_redirect(HTTPS_PORT, PROXY_LISTEN_PORT)?;
    netns::add_nft_redirect(HTTP_PORT, HTTP_PROXY_LISTEN_PORT)?;

    // Create listener sockets inside the new network namespace.
    // These will be transferred to the parent via SCM_RIGHTS.
    let https_listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", PROXY_LISTEN_PORT))
        .context("failed to bind MITM proxy listener")?;
    let http_listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", HTTP_PROXY_LISTEN_PORT))
        .context("failed to bind HTTP proxy listener")?;
    let udp_socket = std::net::UdpSocket::bind("127.0.0.1:53")
        .context("failed to bind DNS socket")?;

    info!(
        "child: created HTTPS proxy on :{}, HTTP proxy on :{}, DNS on :53",
        PROXY_LISTEN_PORT, HTTP_PROXY_LISTEN_PORT
    );

    // Send the fds to the parent (HTTPS, HTTP, DNS)
    fdpass::send_fds(
        sock_fd,
        &[https_listener.as_raw_fd(), http_listener.as_raw_fd(), udp_socket.as_raw_fd()],
    )
    .context("failed to send listener fds to parent")?;
    fdpass::close_fd(sock_fd);

    // Override /etc/resolv.conf to point at our fake DNS server
    netns::write_resolv_conf()?;

    // Install the ephemeral CA cert in the sandbox trust store
    crate::trust::install_ca_cert(ca_pem)
        .context("failed to install CA certificate")?;

    // Apply landlock MAC policy
    apply_landlock(rw_paths)?;

    Ok(())
}

/// Parent side of the proxied fork.
///
/// Receives listener fds from the child, starts the SNI proxy and DNS server
/// on a tokio runtime, then blocks waiting for the child to exit.
fn parent_main_proxied(
    ns_reader: ReadyReader,
    child: Pid,
    sock_fd: i32,
    policy: Arc<RuleSet>,
    ca: Arc<sni_proxy::ca::CertificateAuthority>,
    network_policy: Option<Arc<sni_proxy::network_policy::NetworkPolicy>>,
) -> Result<i32> {
    install_signal_forwarding(child);

    // Receive the listener fds from the child (HTTPS, HTTP, DNS)
    info!("parent: waiting for listener fds from child");
    let fds = fdpass::recv_fds(sock_fd, 3)
        .context("failed to receive listener fds from child")?;
    fdpass::close_fd(sock_fd);
    let https_raw_fd = fds[0];
    let http_raw_fd = fds[1];
    let udp_raw_fd = fds[2];

    // Wait for child to complete all setup (namespace, nftables, landlock)
    ns_reader.wait()?;
    info!("parent: child namespace ready, starting proxy services");

    // Build a tokio runtime for the proxy services
    let rt = tokio::runtime::Runtime::new()
        .context("failed to create tokio runtime")?;

    // Convert raw fds to tokio types
    let https_listener = fd_to_tokio_listener(https_raw_fd, &rt)
        .context("HTTPS listener setup")?;
    let http_listener = fd_to_tokio_listener(http_raw_fd, &rt)
        .context("HTTP listener setup")?;
    let udp_socket = fd_to_tokio_udp(udp_raw_fd, &rt)
        .context("DNS socket setup")?;

    // MITM proxy for HTTPS (port 443 -> 1443)
    let mitm_config = Arc::new(sni_proxy::mitm::MitmConfig {
        policy: Arc::clone(&policy),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        ca,
        upstream_port: HTTPS_PORT,
        network_policy: network_policy.clone(),
    });

    // HTTP proxy for port 80 -> 1080
    let http_config = Arc::new(sni_proxy::http_proxy::HttpProxyConfig {
        policy: Arc::clone(&policy),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        upstream_port: HTTP_PORT,
    });

    // DNS server
    let dns_server = sni_proxy::dns::DnsServer::new(Arc::clone(&policy));

    // Spawn all services
    rt.spawn(async move {
        if let Err(e) = sni_proxy::mitm::run(https_listener, mitm_config).await {
            error!("mitm proxy error: {}", e);
        }
    });

    rt.spawn(async move {
        if let Err(e) = sni_proxy::http_proxy::run(http_listener, http_config).await {
            error!("http proxy error: {}", e);
        }
    });

    rt.spawn(async move {
        if let Err(e) = dns_server.run(udp_socket).await {
            error!("dns server error: {}", e);
        }
    });

    info!("parent: proxy services running, waiting for child exit");
    let exit_code = wait_for_child(child)?;

    // Child exited — shut down the proxy services
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    info!("parent: proxy services stopped");

    Ok(exit_code)
}

// ---------------------------------------------------------------------------
// fd conversion helpers
// ---------------------------------------------------------------------------

/// Convert a raw fd to a tokio TcpListener.
fn fd_to_tokio_listener(
    fd: i32,
    rt: &tokio::runtime::Runtime,
) -> Result<tokio::net::TcpListener> {
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener
        .set_nonblocking(true)
        .context("failed to set listener non-blocking")?;
    rt.block_on(async { tokio::net::TcpListener::from_std(listener) })
        .context("failed to register listener with tokio")
}

/// Convert a raw fd to a tokio UdpSocket.
fn fd_to_tokio_udp(
    fd: i32,
    rt: &tokio::runtime::Runtime,
) -> Result<tokio::net::UdpSocket> {
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    socket
        .set_nonblocking(true)
        .context("failed to set UDP socket non-blocking")?;
    rt.block_on(async { tokio::net::UdpSocket::from_std(socket) })
        .context("failed to register UDP socket with tokio")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readiness_pipe_signal() {
        let (reader, writer) = readiness_pipe().unwrap();
        writer.signal();
        reader.wait().unwrap();
    }

    #[test]
    fn test_readiness_pipe_drop_without_signal() {
        let (reader, writer) = readiness_pipe().unwrap();
        drop(writer);
        let result = reader.wait();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("died before signaling"),
        );
    }

    #[test]
    fn test_child_pid_atomic_default() {
        // CHILD_PID starts at 0
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 0);
    }
}
