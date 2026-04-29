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
use crate::config::{PortForwardSpec, PortProtocol};
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
/// First loopback port used for TCP-bypass relay listeners. Each
/// distinct bypass `(tcp, port)` rule gets one consecutive port
/// starting here. Room for up to 256 endpoints before we'd collide
/// with anything interesting — more than enough for real-world
/// configs, and the allocation is deterministic so parent + child
/// agree without side-channel coordination.
const BYPASS_TCP_BASE_PORT: u16 = 1090;
/// First loopback port used for UDP-bypass relay listeners. Kept
/// disjoint from the TCP range so an operator reading `ss -tulnp`
/// can tell which listener is which at a glance, and we don't care
/// about UDP-TCP clashes (they don't share port space) but the
/// alignment is handy for logs.
const BYPASS_UDP_BASE_PORT: u16 = 1400;
/// Loopback port for the learn-mode catch-all TCP observer. Only
/// bound + DNAT'd to when `permit_all = true`; the rest of run
/// mode never opens this socket.
const LEARN_OBSERVER_PORT: u16 = 1500;

/// One TCP-bypass endpoint plus the loopback port where the relay
/// listens for it. Both sides of the fork compute the same
/// allocation from the shared `RuleSet` so we don't need to send
/// metadata alongside the SCM_RIGHTS fds.
#[derive(Debug, Clone, Copy)]
struct BypassTcpAllocation {
    /// The real port the child thinks it's connecting to (e.g. 389).
    real_port: u16,
    /// Loopback port where the relay listens (e.g. 1090).
    relay_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct BypassUdpAllocation {
    real_port: u16,
    relay_port: u16,
}

/// Snapshot of the nftables layout we install before exec, used
/// for a single human-readable summary log. Order in the vector
/// matches install order, which is also nftables evaluation order
/// (first-match-wins for `dnat`). The `from_port = None` form
/// represents a catch-all (no `dport` predicate).
#[derive(Debug, Default)]
struct NftPlan {
    rows: Vec<NftRow>,
}

#[derive(Debug, Clone, Copy)]
enum NftFamily {
    /// IPv4 TCP. Includes both port-specific rules and the
    /// learn-mode catch-all.
    TcpV4,
    UdpV4,
    UdpV6,
}

#[derive(Debug)]
struct NftRow {
    family: NftFamily,
    /// `Some(port)` for a `dport == port` rule, `None` for a
    /// catch-all (`meta l4proto tcp` without a port predicate).
    from_port: Option<u16>,
    /// Loopback port the rule DNATs to.
    to_port: u16,
    /// Short human-friendly description of what the rule routes.
    label: &'static str,
}

impl NftPlan {
    fn push_tcp(&mut self, from_port: Option<u16>, to_port: u16, label: &'static str) {
        self.rows.push(NftRow { family: NftFamily::TcpV4, from_port, to_port, label });
    }
    fn push_udp_v4(&mut self, from_port: u16, to_port: u16, label: &'static str) {
        self.rows.push(NftRow {
            family: NftFamily::UdpV4,
            from_port: Some(from_port),
            to_port,
            label,
        });
    }
    fn push_udp_v6(&mut self, from_port: u16, to_port: u16, label: &'static str) {
        self.rows.push(NftRow {
            family: NftFamily::UdpV6,
            from_port: Some(from_port),
            to_port,
            label,
        });
    }

    /// Render a fixed-width table. Columns: index, family, source
    /// port (or `*` for catch-all), arrow, dest, label. Index is
    /// the order packets see — rule 1 is consulted before rule 2.
    fn render(&self) -> String {
        use std::fmt::Write as _;
        if self.rows.is_empty() {
            return "  (no rules)".to_string();
        }
        // Compute the width of the source-port column so the
        // arrow lines up across rows.
        let from_w = self
            .rows
            .iter()
            .map(|r| {
                r.from_port
                    .map(|p| p.to_string().len())
                    .unwrap_or(1) // `*`
            })
            .max()
            .unwrap_or(1);
        let mut out = String::new();
        for (i, r) in self.rows.iter().enumerate() {
            let proto = match r.family {
                NftFamily::TcpV4 => "tcp ",
                NftFamily::UdpV4 => "udp4",
                NftFamily::UdpV6 => "udp6",
            };
            let from = match r.from_port {
                Some(p) => format!("{p:>from_w$}"),
                None => format!("{:>from_w$}", "*"),
            };
            let dst_addr = match r.family {
                NftFamily::UdpV6 => "[::1]",
                _ => "127.0.0.1",
            };
            let _ = writeln!(
                out,
                "  [{:>2}] {proto} :{from} -> {dst_addr}:{:<5}  ({})",
                i + 1,
                r.to_port,
                r.label,
            );
        }
        // Trim the trailing newline so callers get a clean
        // single-block log line.
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }
}

fn compute_bypass_tcp_allocations(rules: &RuleSet) -> Vec<BypassTcpAllocation> {
    rules
        .bypass_endpoints()
        .into_iter()
        .filter(|(p, _)| *p == sni_proxy::policy::BypassProtocol::Tcp)
        .enumerate()
        .map(|(i, (_, port))| BypassTcpAllocation {
            real_port: port,
            relay_port: BYPASS_TCP_BASE_PORT + i as u16,
        })
        .collect()
}

fn compute_bypass_udp_allocations(rules: &RuleSet) -> Vec<BypassUdpAllocation> {
    rules
        .bypass_endpoints()
        .into_iter()
        .filter(|(p, _)| *p == sni_proxy::policy::BypassProtocol::Udp)
        .enumerate()
        .map(|(i, (_, port))| BypassUdpAllocation {
            real_port: port,
            relay_port: BYPASS_UDP_BASE_PORT + i as u16,
        })
        .collect()
}

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
    port_forwards: &[PortForwardSpec],
    block_log_path: Option<&Path>,
    dns_upstream: std::net::SocketAddr,
    // `hermit learn` writes a JSONL trace of every *allowed*
    // access here. `None` outside learn mode (the access logger
    // is disabled and the field is unused).
    access_log_path: Option<&Path>,
) -> Result<i32> {
    // Generate the ephemeral CA before fork so both parent and child can use it.
    let ca = Arc::new(
        sni_proxy::ca::CertificateAuthority::new()
            .context("failed to generate ephemeral CA")?,
    );
    let ca_pem = ca.ca_cert_pem().to_string();

    let (ns_reader, ns_writer) = readiness_pipe()?;
    let (parent_sock, child_sock) = fdpass::socketpair()?;

    // Computed before the fork so parent + child agree on the
    // relay-port layout without having to pass it through the
    // SCM_RIGHTS channel.
    let bypass_tcp = compute_bypass_tcp_allocations(&policy);
    let bypass_udp = compute_bypass_udp_allocations(&policy);
    // `permit_all` is set only by `hermit learn`. When it's on,
    // the child binds an extra catch-all observer listener and
    // installs a wildcard nft DNAT so connections on un-proxied
    // ports get logged for `hermit learn-convert` to consume
    // instead of failing with "no route to host".
    let learn_mode = policy.is_permit_all();

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
                port_forwards,
                &bypass_tcp,
                &bypass_udp,
                learn_mode,
            );
        }
        ForkResult::Parent { child } => {
            drop(ns_writer);
            fdpass::close_fd(child_sock);
            parent_main_proxied(
                ns_reader,
                child,
                parent_sock,
                policy,
                ca,
                network_policy,
                block_log_path.map(|p| p.to_path_buf()),
                access_log_path.map(|p| p.to_path_buf()),
                dns_upstream,
                bypass_tcp,
                bypass_udp,
                port_forwards.to_vec(),
                learn_mode,
            )
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
    port_forwards: &[PortForwardSpec],
    bypass_tcp: &[BypassTcpAllocation],
    bypass_udp: &[BypassUdpAllocation],
    learn_mode: bool,
) -> ! {
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };

    if let Err(e) = child_proxied_setup(
        sock_fd, ca_pem, home_path, project_dir, passthrough, home_files, rw_paths,
        port_forwards, bypass_tcp, bypass_udp, learn_mode,
    ) {
        eprintln!("hermit: proxied namespace setup failed: {:#}", e);
        std::process::exit(126);
    }

    ns_ready.signal();

    info!("child: exec {:?}", command);
    let err = Command::new(&command[0])
        .args(&command[1..])
        .envs(proxy_env_vars())
        .exec();
    eprintln!("hermit: exec failed: {}", err);
    std::process::exit(126);
}

/// Environment variables set on the sandboxed command so that
/// proxy-aware clients (curl, python-requests, cargo, npm, go, ...)
/// route HTTP and HTTPS through the hermit proxies explicitly rather
/// than relying only on the transparent nftables DNAT redirect.
///
/// Both casings are set because ecosystems disagree on which one is
/// canonical — curl reads lowercase, most others accept both. The
/// HTTP proxy on [`HTTP_PROXY_LISTEN_PORT`] handles origin-form
/// requests, absolute-form requests (what `HTTP_PROXY` clients send),
/// and `CONNECT` tunnels (what `HTTPS_PROXY` clients send); that's
/// why the same URL is used for all four.
///
/// `NO_PROXY` excludes loopback so tools hitting a local service
/// inside the sandbox don't tunnel through the proxy back to
/// themselves.
fn proxy_env_vars() -> Vec<(&'static str, String)> {
    let url = format!("http://127.0.0.1:{}", HTTP_PROXY_LISTEN_PORT);
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    vec![
        ("HTTP_PROXY", url.clone()),
        ("http_proxy", url.clone()),
        ("HTTPS_PROXY", url.clone()),
        ("https_proxy", url),
        ("NO_PROXY", no_proxy.clone()),
        ("no_proxy", no_proxy),
    ]
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
    port_forwards: &[PortForwardSpec],
    bypass_tcp: &[BypassTcpAllocation],
    bypass_udp: &[BypassUdpAllocation],
    learn_mode: bool,
) -> Result<()> {
    // Set up namespace isolation (user + mount + net)
    setup_namespace(home_path, project_dir, passthrough, home_files, true)?;

    // Network namespace setup. Install nft rules in
    // first-match-wins order: specific port rules first, then any
    // bypass rules, then the learn-mode catch-all LAST. nftables
    // NAT terminates chain processing on the first matching `dnat`
    // (NF_ACCEPT verdict from nft_nat), so a catch-all installed
    // ahead of the specific rules would gobble all TCP traffic
    // before the MITM/HTTP/bypass rules ever fire. See
    // `netns::add_nft_redirect_all_tcp` for the full reasoning.
    netns::bring_up_loopback()?;
    netns::ensure_nft_nat_table()?;
    let mut nft_plan = NftPlan::default();
    netns::add_nft_redirect(HTTPS_PORT, PROXY_LISTEN_PORT)?;
    nft_plan.push_tcp(Some(HTTPS_PORT), PROXY_LISTEN_PORT, "MITM proxy");
    netns::add_nft_redirect(HTTP_PORT, HTTP_PROXY_LISTEN_PORT)?;
    nft_plan.push_tcp(Some(HTTP_PORT), HTTP_PROXY_LISTEN_PORT, "HTTP proxy");
    for pf in port_forwards {
        let (dest, label) = match pf.protocol {
            PortProtocol::Https => (PROXY_LISTEN_PORT, "port_forward https → MITM"),
            PortProtocol::Http => (HTTP_PROXY_LISTEN_PORT, "port_forward http → HTTP proxy"),
        };
        netns::add_nft_redirect(pf.port, dest)?;
        nft_plan.push_tcp(Some(pf.port), dest, label);
    }
    for alloc in bypass_tcp {
        netns::add_nft_redirect(alloc.real_port, alloc.relay_port)?;
        nft_plan.push_tcp(Some(alloc.real_port), alloc.relay_port, "bypass-tcp");
    }
    // UDP bypass: install both v4 and v6 DNAT rules. Each rule
    // retargets the real port onto our loopback relay port in the
    // matching family (127.0.0.1 / ::1). The v6 table is created
    // lazily so configs without IPv6 bypass don't pay for an empty
    // `ip6 hermit_nat_v6`.
    if !bypass_udp.is_empty() {
        netns::ensure_nft_nat_table_v6()?;
    }
    for alloc in bypass_udp {
        netns::add_nft_redirect_udp(alloc.real_port, alloc.relay_port)?;
        nft_plan.push_udp_v4(alloc.real_port, alloc.relay_port, "bypass-udp v4");
        netns::add_nft_redirect_udp_v6(alloc.real_port, alloc.relay_port)?;
        nft_plan.push_udp_v6(alloc.real_port, alloc.relay_port, "bypass-udp v6");
    }
    // Learn-mode catch-all is the FALLBACK rule — installed last
    // so it only fires for TCP that didn't match anything above.
    if learn_mode {
        netns::add_nft_redirect_all_tcp(LEARN_OBSERVER_PORT)?;
        nft_plan.push_tcp(None, LEARN_OBSERVER_PORT, "learn-mode observer (catch-all)");
    }
    info!("nft layout (first-match-wins):\n{}", nft_plan.render());

    // Create listener sockets inside the new network namespace.
    // These will be transferred to the parent via SCM_RIGHTS.
    let https_listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", PROXY_LISTEN_PORT))
        .context("failed to bind MITM proxy listener")?;
    let http_listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", HTTP_PROXY_LISTEN_PORT))
        .context("failed to bind HTTP proxy listener")?;
    let udp_socket = std::net::UdpSocket::bind("127.0.0.1:53")
        .context("failed to bind DNS socket")?;
    // Learn-mode catch-all observer listener. Bound before the
    // bypass sockets so the fd-order in the SCM_RIGHTS payload is
    // stable for run mode (which doesn't include this fd at all).
    let learn_observer_listener: Option<std::net::TcpListener> = if learn_mode {
        Some(
            std::net::TcpListener::bind(format!("127.0.0.1:{}", LEARN_OBSERVER_PORT))
                .context("failed to bind learn-mode observer listener")?,
        )
    } else {
        None
    };

    // Bind one listener per bypass-tcp allocation. Order matches the
    // allocation order (which is deterministic), so the parent can
    // pair each received fd with its config entry by index.
    let mut bypass_tcp_listeners: Vec<std::net::TcpListener> =
        Vec::with_capacity(bypass_tcp.len());
    for alloc in bypass_tcp {
        let l = std::net::TcpListener::bind(format!("127.0.0.1:{}", alloc.relay_port))
            .with_context(|| {
                format!(
                    "failed to bind bypass-tcp relay listener on 127.0.0.1:{}",
                    alloc.relay_port
                )
            })?;
        bypass_tcp_listeners.push(l);
    }

    // UDP bypass: bind *two* sockets per allocation — one v4, one
    // v6 — matching the two DNAT rules installed above. Each
    // relay instance (spawned on the parent side) consumes one
    // fd, so the v4 + v6 sockets for the same `real_port`
    // become sibling relays that authorize independently.
    let mut bypass_udp_v4: Vec<std::net::UdpSocket> = Vec::with_capacity(bypass_udp.len());
    let mut bypass_udp_v6: Vec<std::net::UdpSocket> = Vec::with_capacity(bypass_udp.len());
    for alloc in bypass_udp {
        let s4 = std::net::UdpSocket::bind(format!("127.0.0.1:{}", alloc.relay_port))
            .with_context(|| {
                format!(
                    "failed to bind bypass-udp v4 relay socket on 127.0.0.1:{}",
                    alloc.relay_port
                )
            })?;
        let s6 = std::net::UdpSocket::bind(format!("[::1]:{}", alloc.relay_port))
            .with_context(|| {
                format!(
                    "failed to bind bypass-udp v6 relay socket on [::1]:{}",
                    alloc.relay_port
                )
            })?;
        bypass_udp_v4.push(s4);
        bypass_udp_v6.push(s6);
    }

    info!(
        "child: created HTTPS proxy on :{}, HTTP proxy on :{}, DNS on :53, \
         {} bypass-tcp listener(s), {} bypass-udp listener(s) (v4+v6 each)",
        PROXY_LISTEN_PORT,
        HTTP_PROXY_LISTEN_PORT,
        bypass_tcp_listeners.len(),
        bypass_udp_v4.len(),
    );

    // Send the fds to the parent. Order: HTTPS, HTTP, DNS, then
    // bypass-tcp fds (in allocation order), then bypass-udp-v4
    // fds, then bypass-udp-v6 fds, then (learn mode only) the
    // observer fd. The parent recomputes the same allocation
    // order and splits the received vector by index — it knows
    // whether to expect the observer fd from the same `learn_mode`
    // flag that drove the binding here.
    let mut fds: Vec<i32> = vec![
        https_listener.as_raw_fd(),
        http_listener.as_raw_fd(),
        udp_socket.as_raw_fd(),
    ];
    for l in &bypass_tcp_listeners {
        fds.push(l.as_raw_fd());
    }
    for s in &bypass_udp_v4 {
        fds.push(s.as_raw_fd());
    }
    for s in &bypass_udp_v6 {
        fds.push(s.as_raw_fd());
    }
    if let Some(l) = &learn_observer_listener {
        fds.push(l.as_raw_fd());
    }
    fdpass::send_fds(sock_fd, &fds)
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
    block_log_path: Option<PathBuf>,
    access_log_path: Option<PathBuf>,
    dns_upstream: std::net::SocketAddr,
    bypass_tcp: Vec<BypassTcpAllocation>,
    bypass_udp: Vec<BypassUdpAllocation>,
    port_forwards: Vec<PortForwardSpec>,
    learn_mode: bool,
) -> Result<i32> {
    install_signal_forwarding(child);

    // Receive the listener fds from the child. Layout (must match
    // `child_proxied_setup`'s send order): HTTPS, HTTP, DNS, then
    // TCP-bypass fds, then UDP-bypass v4 fds, then UDP-bypass v6
    // fds, then (only when `learn_mode`) the catch-all observer fd.
    // Each UDP allocation contributes two fds (one per family) so
    // the split is `2 × bypass_udp.len()`.
    let fixed_count = 3usize;
    let tcp_count = bypass_tcp.len();
    let udp_count = bypass_udp.len();
    let observer_count = if learn_mode { 1 } else { 0 };
    let total = fixed_count + tcp_count + 2 * udp_count + observer_count;
    info!(
        "parent: waiting for {} listener fds from child ({} bypass-tcp, {} bypass-udp × v4+v6{})",
        total, tcp_count, udp_count,
        if learn_mode { ", +1 learn observer" } else { "" }
    );
    let fds = fdpass::recv_fds(sock_fd, total)
        .context("failed to receive listener fds from child")?;
    fdpass::close_fd(sock_fd);
    let https_raw_fd = fds[0];
    let http_raw_fd = fds[1];
    let udp_raw_fd = fds[2];
    let tcp_start = fixed_count;
    let udp_v4_start = fixed_count + tcp_count;
    let udp_v6_start = udp_v4_start + udp_count;
    let observer_start = udp_v6_start + udp_count;
    let bypass_tcp_raw_fds: Vec<i32> = fds[tcp_start..udp_v4_start].to_vec();
    let bypass_udp_v4_raw_fds: Vec<i32> = fds[udp_v4_start..udp_v6_start].to_vec();
    let bypass_udp_v6_raw_fds: Vec<i32> = fds[udp_v6_start..observer_start].to_vec();
    let learn_observer_raw_fd: Option<i32> = if learn_mode {
        Some(fds[observer_start])
    } else {
        None
    };

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
    let bypass_tcp_listeners: Vec<_> = bypass_tcp_raw_fds
        .into_iter()
        .enumerate()
        .map(|(i, fd)| {
            fd_to_tokio_listener(fd, &rt)
                .with_context(|| format!("bypass-tcp listener {i} setup"))
        })
        .collect::<Result<_>>()?;

    // Block logger must be constructed on the runtime because it opens
    // an async file and spawns a writer task. The access logger
    // shares the same machinery; it points at a different file
    // when `hermit learn` is in use, otherwise it's disabled.
    let block_log = match block_log_path {
        Some(p) => rt
            .block_on(async { sni_proxy::block_log::BlockLogger::to_file(&p).await })
            .context("opening block log")?,
        None => sni_proxy::block_log::BlockLogger::disabled(),
    };
    let access_log = match access_log_path {
        Some(p) => {
            info!("access log: {}", p.display());
            rt.block_on(async { sni_proxy::block_log::BlockLogger::to_file(&p).await })
                .context("opening access log")?
        }
        None => sni_proxy::block_log::BlockLogger::disabled(),
    };

    // MITM proxy for HTTPS (port 443 -> 1443)
    let mitm_config = Arc::new(sni_proxy::mitm::MitmConfig {
        policy: Arc::clone(&policy),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        ca,
        upstream_port: HTTPS_PORT,
        network_policy: network_policy.clone(),
        block_log: block_log.clone(),
        access_log: access_log.clone(),
    });

    // HTTP proxy for port 80 -> 1080. The CONNECT-tunnel port
    // allowlist is the union of the standard HTTPS port and any
    // `[[port_forward]]` entries the config marked as `https` —
    // those are the ports the build's tools may legitimately
    // tunnel through `HTTPS_PROXY`.
    let mut allowed_connect_ports: std::collections::BTreeSet<u16> =
        std::collections::BTreeSet::new();
    allowed_connect_ports.insert(HTTPS_PORT);
    for pf in port_forwards {
        if matches!(pf.protocol, PortProtocol::Https) {
            allowed_connect_ports.insert(pf.port);
        }
    }
    let http_config = Arc::new(sni_proxy::http_proxy::HttpProxyConfig {
        policy: Arc::clone(&policy),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        upstream_port: HTTP_PORT,
        allowed_connect_ports,
        block_log: block_log.clone(),
        access_log: access_log.clone(),
    });

    // DNS server — wrapped in Arc so `run` can spawn per-response
    // tasks that share the socket. A real upstream resolver is
    // plumbed in here so allowed queries get real answers; the
    // shared DnsCache lets future relays reverse-map a dst IP
    // (from SO_ORIGINAL_DST) back to the hostname that was
    // originally asked for.
    let dns_cache = Arc::new(sni_proxy::dns_cache::DnsCache::new());
    let dns_forwarder = Arc::new(sni_proxy::dns_forwarder::DnsForwarder::new(dns_upstream));
    info!("dns: forwarding allowed queries to {}", dns_upstream);
    let dns_server = Arc::new(
        sni_proxy::dns::DnsServer::new(Arc::clone(&policy))
            .with_block_log(block_log.clone())
            .with_access_log(access_log.clone())
            .with_upstream(dns_forwarder)
            .with_cache(Arc::clone(&dns_cache)),
    );

    // Spawn all services. Keep the JoinHandles so the supervisor can
    // observe an early exit and escalate — without this, a panicking
    // proxy task would silently disable egress filtering while the child
    // kept running against the dead proxy.
    let mitm_handle = rt.spawn(async move {
        if let Err(e) = sni_proxy::mitm::run(https_listener, mitm_config).await {
            error!("mitm proxy error: {}", e);
        }
    });

    let http_handle = rt.spawn(async move {
        if let Err(e) = sni_proxy::http_proxy::run(http_listener, http_config).await {
            error!("http proxy error: {}", e);
        }
    });

    let dns_handle = rt.spawn(async move {
        if let Err(e) = dns_server.run(udp_socket).await {
            error!("dns server error: {}", e);
        }
    });

    // Spawn one TCP-bypass relay per allocation. Each gets its own
    // BypassTcpConfig (port is load-bearing for rule matching).
    // We collect the handles so a relay death triggers the same
    // supervisor teardown as any other proxy task — the child
    // running against a dead relay would experience a hard-to-
    // diagnose hang rather than a clean deny.
    let mut bypass_tcp_handles = Vec::with_capacity(bypass_tcp_listeners.len());
    for (alloc, listener) in bypass_tcp.iter().zip(bypass_tcp_listeners.into_iter()) {
        let cfg = Arc::new(sni_proxy::bypass_tcp::BypassTcpConfig {
            port: alloc.real_port,
            rules: Arc::clone(&policy),
            cache: Arc::clone(&dns_cache),
            connector: Arc::new(sni_proxy::connector::DirectConnector),
            block_log: block_log.clone(),
        });
        let real_port = alloc.real_port;
        let handle = rt.spawn(async move {
            if let Err(e) = sni_proxy::bypass_tcp::run(listener, cfg).await {
                error!("bypass-tcp relay (port {}) error: {}", real_port, e);
            }
        });
        bypass_tcp_handles.push((real_port, handle));
    }

    // Learn-mode catch-all observer. Bound to its own listener
    // fd received from the child. When run mode is in effect this
    // branch is skipped entirely — no fd was sent, no listener
    // was bound.
    let learn_observer_handle = match learn_observer_raw_fd {
        Some(raw_fd) => {
            let listener = fd_to_tokio_listener(raw_fd, &rt)
                .context("learn-mode observer listener setup")?;
            let cfg = Arc::new(sni_proxy::learn_observer::LearnObserverConfig {
                dns_cache: Arc::clone(&dns_cache),
                access_log: access_log.clone(),
            });
            let handle = rt.spawn(async move {
                if let Err(e) = sni_proxy::learn_observer::run(listener, cfg).await {
                    error!("learn-observer error: {}", e);
                }
            });
            Some(handle)
        }
        None => None,
    };

    // Spawn one UDP-bypass relay per (allocation, family). The UDP
    // module takes a raw fd because it does its own
    // `IP[V6]_RECVORIGDSTADDR` setup and cmsg-aware `recvmsg` —
    // plain tokio `UdpSocket` can't give us the pre-DNAT dst.
    let mut bypass_udp_handles = Vec::with_capacity(2 * bypass_udp.len());
    let udp_families = [
        (bypass_udp_v4_raw_fds, sni_proxy::bypass_udp::IpFamily::V4, "v4"),
        (bypass_udp_v6_raw_fds, sni_proxy::bypass_udp::IpFamily::V6, "v6"),
    ];
    for (fds, family, label) in udp_families {
        for (alloc, raw_fd) in bypass_udp.iter().zip(fds.into_iter()) {
            let cfg = Arc::new(sni_proxy::bypass_udp::BypassUdpConfig {
                port: alloc.real_port,
                family,
                rules: Arc::clone(&policy),
                cache: Arc::clone(&dns_cache),
                block_log: block_log.clone(),
            });
            let real_port = alloc.real_port;
            let label = label.to_string();
            let label_for_task = label.clone();
            let handle = rt.spawn(async move {
                if let Err(e) = sni_proxy::bypass_udp::run(raw_fd, cfg).await {
                    error!("bypass-udp relay ({} port {}) error: {}", label_for_task, real_port, e);
                }
            });
            bypass_udp_handles.push((alloc.real_port, label, handle));
        }
    }

    // Supervisor: if any proxy task exits (clean return, error, or
    // panic) before the child does, SIGTERM the child. The child
    // running with a dead proxy means egress policy isn't being
    // enforced, which is worse than tearing the whole sandbox down.
    let child_pid_raw = child.as_raw();
    rt.spawn(async move {
        // `select` over the fixed proxies + every bypass relay.
        // `futures::select_all` would be cleaner but adds a dep;
        // spawn a watcher per handle instead.
        let (name_tx, mut name_rx) = tokio::sync::mpsc::channel::<(String, _)>(16);
        {
            let tx = name_tx.clone();
            tokio::spawn(async move {
                let r = mitm_handle.await;
                let _ = tx.send(("mitm".to_string(), r)).await;
            });
        }
        {
            let tx = name_tx.clone();
            tokio::spawn(async move {
                let r = http_handle.await;
                let _ = tx.send(("http".to_string(), r)).await;
            });
        }
        {
            let tx = name_tx.clone();
            tokio::spawn(async move {
                let r = dns_handle.await;
                let _ = tx.send(("dns".to_string(), r)).await;
            });
        }
        for (real_port, handle) in bypass_tcp_handles {
            let tx = name_tx.clone();
            tokio::spawn(async move {
                let r = handle.await;
                let _ = tx.send((format!("bypass-tcp:{real_port}"), r)).await;
            });
        }
        for (real_port, label, handle) in bypass_udp_handles {
            let tx = name_tx.clone();
            tokio::spawn(async move {
                let r = handle.await;
                let _ = tx.send((format!("bypass-udp/{label}:{real_port}"), r)).await;
            });
        }
        if let Some(handle) = learn_observer_handle {
            let tx = name_tx.clone();
            tokio::spawn(async move {
                let r = handle.await;
                let _ = tx.send(("learn-observer".to_string(), r)).await;
            });
        }
        drop(name_tx);

        let Some((name, result)) = name_rx.recv().await else {
            return; // all senders dropped without a message — nothing to do
        };
        match result {
            Ok(()) => error!(
                "proxy task {} exited unexpectedly (no error); tearing down sandbox child",
                name
            ),
            Err(e) if e.is_panic() => error!(
                "proxy task {} panicked; tearing down sandbox child: {}",
                name, e
            ),
            Err(e) => error!(
                "proxy task {} ended abnormally; tearing down sandbox child: {}",
                name, e
            ),
        }
        // SIGTERM is forwarded by `forward_signal` only when installed
        // for the parent's handled signals — here we signal the child
        // directly to ensure it exits even if the user isn't pressing
        // Ctrl-C. `wait_for_child` in the main thread then returns.
        unsafe { libc::kill(child_pid_raw, libc::SIGTERM) };
    });

    info!("parent: proxy services running, waiting for child exit");
    let exit_code = wait_for_child(child)?;

    // Child exited — shut down the proxy services. The block-log
    // writer task flushes on each event, so a 1-second window is
    // enough for in-flight events to land.
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

    #[test]
    fn bypass_tcp_allocations_give_distinct_relay_ports() {
        use sni_proxy::policy::{AccessRule, BypassProtocol, Mechanism};
        let rules = RuleSet::new(vec![
            AccessRule {
                hostname: "a.example".into(),
                path_prefix: None,
                methods: None,
                mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 389 },
            },
            AccessRule {
                hostname: "b.example".into(),
                path_prefix: None,
                methods: None,
                mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 22 },
            },
            // UDP rule must not appear in the TCP allocation list.
            AccessRule {
                hostname: "c.example".into(),
                path_prefix: None,
                methods: None,
                mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
            },
        ]);
        let allocs = compute_bypass_tcp_allocations(&rules);
        assert_eq!(allocs.len(), 2);
        // All relay ports distinct, all at or above the base.
        let relay_ports: std::collections::HashSet<_> =
            allocs.iter().map(|a| a.relay_port).collect();
        assert_eq!(relay_ports.len(), 2);
        for a in &allocs {
            assert!(a.relay_port >= BYPASS_TCP_BASE_PORT);
        }
    }

    #[test]
    fn bypass_udp_allocations_coexist_with_tcp_on_same_port() {
        // Kerberos ships UDP/88 and TCP/88 — both should allocate
        // listeners independently and land in disjoint loopback
        // port ranges so neither steps on the other.
        use sni_proxy::policy::{AccessRule, BypassProtocol, Mechanism};
        let rules = RuleSet::new(vec![
            AccessRule {
                hostname: "kdc.example".into(),
                path_prefix: None,
                methods: None,
                mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
            },
            AccessRule {
                hostname: "kdc.example".into(),
                path_prefix: None,
                methods: None,
                mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 88 },
            },
        ]);
        let tcp_allocs = compute_bypass_tcp_allocations(&rules);
        let udp_allocs = compute_bypass_udp_allocations(&rules);
        assert_eq!(tcp_allocs.len(), 1);
        assert_eq!(udp_allocs.len(), 1);
        // They're in separate port ranges so we can tell TCP vs UDP
        // from the loopback port alone.
        assert!(tcp_allocs[0].relay_port >= BYPASS_TCP_BASE_PORT);
        assert!(tcp_allocs[0].relay_port < BYPASS_UDP_BASE_PORT);
        assert!(udp_allocs[0].relay_port >= BYPASS_UDP_BASE_PORT);
    }

    #[test]
    fn bypass_tcp_allocations_deduplicate_same_port_different_hosts() {
        // Two different hosts both bypassing TCP port 22 — the
        // relay serves both via a single listener on the same
        // loopback port, and the port 22 DNAT redirects to it.
        use sni_proxy::policy::{AccessRule, BypassProtocol, Mechanism};
        let rules = RuleSet::new(vec![
            AccessRule {
                hostname: "a.example".into(),
                path_prefix: None,
                methods: None,
                mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 22 },
            },
            AccessRule {
                hostname: "b.example".into(),
                path_prefix: None,
                methods: None,
                mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 22 },
            },
        ]);
        let allocs = compute_bypass_tcp_allocations(&rules);
        assert_eq!(allocs.len(), 1, "same port must share one relay listener");
    }

    #[test]
    fn proxy_env_vars_cover_both_casings_and_no_proxy() {
        let vars: std::collections::HashMap<_, _> = proxy_env_vars().into_iter().collect();
        let expected_url = format!("http://127.0.0.1:{}", HTTP_PROXY_LISTEN_PORT);
        for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
            assert_eq!(vars.get(k).map(|s| s.as_str()), Some(expected_url.as_str()),
                "missing or wrong value for {k}");
        }
        for k in ["NO_PROXY", "no_proxy"] {
            let v = vars.get(k).expect("missing NO_PROXY casing");
            // Loopback must be excluded — otherwise local services
            // tunnel back through the proxy to themselves.
            assert!(v.contains("127.0.0.1"), "NO_PROXY missing 127.0.0.1: {v}");
            assert!(v.contains("localhost"), "NO_PROXY missing localhost: {v}");
        }
    }

    #[test]
    fn nft_plan_render_lists_rules_in_install_order() {
        // The summary lists rules in nft-evaluation order
        // (first-match-wins) so a reader can scan top-to-bottom
        // and predict which rule a packet hits.
        let mut plan = NftPlan::default();
        plan.push_tcp(Some(443), 1443, "MITM proxy");
        plan.push_tcp(Some(80), 1080, "HTTP proxy");
        plan.push_tcp(Some(8443), 1443, "port_forward https → MITM");
        plan.push_tcp(Some(389), 1090, "bypass-tcp");
        plan.push_udp_v4(88, 1400, "bypass-udp v4");
        plan.push_udp_v6(88, 1400, "bypass-udp v6");
        plan.push_tcp(None, 1500, "learn-mode observer (catch-all)");

        let out = plan.render();
        // Every label appears.
        for label in [
            "MITM proxy", "HTTP proxy", "port_forward https",
            "bypass-tcp", "bypass-udp v4", "bypass-udp v6",
            "learn-mode observer",
        ] {
            assert!(out.contains(label), "missing {label} in: {out}");
        }
        // Catch-all renders with `*` instead of a specific port.
        // (The exact padding depends on the widest source port
        // in the plan; here 8443 dictates a 4-char column.)
        assert!(out.contains(":   * ->"),
            "catch-all must render with `*` source port: {out}");
        // Indices are 1-based and ordered.
        let i_443 = out.find("[ 1]").expect("rule [ 1] missing");
        let i_obs = out.find("[ 7]").expect("rule [ 7] missing");
        assert!(i_443 < i_obs, "rule order must be preserved");
        // IPv6 UDP renders with `[::1]` (not 127.0.0.1).
        assert!(out.contains("[::1]:1400"), "udp v6 must use [::1]: {out}");
    }

    #[test]
    fn nft_plan_render_handles_no_rules() {
        let plan = NftPlan::default();
        assert!(plan.render().contains("(no rules)"));
    }

    #[test]
    fn nft_plan_aligns_source_port_column() {
        // Width-aligned source-port column means a one-line
        // `grep` for `:443 ->` keeps working regardless of how
        // many other rules are above/below.
        let mut plan = NftPlan::default();
        plan.push_tcp(Some(443), 1443, "MITM");
        plan.push_tcp(Some(80), 1080, "HTTP");
        plan.push_tcp(Some(50000), 1090, "bypass");
        let out = plan.render();
        // Each `:<port>` column should be the same width — the
        // narrowest port (80) gets padded out to match 50000 (5).
        assert!(out.contains(":   80 ->"), "80 should be right-padded: {out}");
        assert!(out.contains(":50000 ->"), "{out}");
    }
}
