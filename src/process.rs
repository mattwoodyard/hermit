use anyhow::{bail, Context, Result};
use log::{debug, info};
use nix::sys::signal::{kill, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::cli::NetMode;
use crate::home_files::HomeFileDirective;
use crate::landlock::apply_landlock;
use crate::namespace::setup_namespace;
use crate::pasta;

/// PID of the child process, used by signal handlers.
/// 0 means no child yet (signals are no-ops).
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

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

// --- Forked sandbox entry point ---

/// Run a sandboxed command in a forked child with network namespace isolation.
///
/// The parent forks, the child sets up namespaces (including CLONE_NEWNET)
/// and landlock, signals readiness, then exec's the command. The parent
/// installs signal forwarding and waits for the child to exit.
///
/// When `net == Pasta`, a second "pasta-ready" pipe is used:
///   Child: namespace setup → landlock → signal ns-ready → **wait pasta-ready** → exec
///   Parent: wait ns-ready → launch_pasta(child_pid) → signal pasta-ready → wait exit
pub fn run_forked(
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    rw_paths: &[&Path],
    command: &[String],
    net: &NetMode,
    allowed_hosts: &[String],
) -> Result<i32> {
    let (ns_reader, ns_writer) = readiness_pipe()?;

    // Second pipe for Pasta mode: child waits on this after namespace setup,
    // parent signals it after pasta has configured the tap device.
    let (pasta_reader, pasta_writer) = if *net == NetMode::Pasta {
        let (r, w) = readiness_pipe()?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };

    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => {
            drop(ns_reader);
            drop(pasta_writer); // child doesn't write to pasta pipe
            child_main(ns_writer, pasta_reader, home_path, project_dir, passthrough, home_files, rw_paths, command, allowed_hosts);
        }
        ForkResult::Parent { child } => {
            drop(ns_writer);
            drop(pasta_reader); // parent doesn't read from pasta pipe
            parent_main(ns_reader, pasta_writer, child, allowed_hosts)
        }
    }
}

/// Child side of the fork. Sets up namespaces + landlock, signals ready, execs.
/// This function never returns — it either execs or exits with 126.
///
/// When `pasta_ready` is Some, the child waits for the parent to signal that
/// pasta has configured the tap device before exec'ing.
fn child_main(
    ns_ready: ReadyWriter,
    pasta_ready: Option<ReadyReader>,
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    rw_paths: &[&Path],
    command: &[String],
    allowed_hosts: &[String],
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

    // If pasta mode: wait for parent to finish launching pasta
    if let Some(reader) = pasta_ready {
        if let Err(e) = reader.wait() {
            eprintln!("hermit: waiting for pasta setup failed: {:#}", e);
            std::process::exit(126);
        }
        info!("child: pasta tap device ready");

        // Redirect outbound HTTPS to the SNI proxy on the host via iptables DNAT.
        // Pasta's --map-host-loopback maps the gateway to host loopback, so
        // DNAT to gateway:proxy_port reaches the SNI proxy on the host.
        if !allowed_hosts.is_empty() {
            let proxy_port: u16 = pasta::SNI_PROXY_LISTEN
                .rsplit(':')
                .next()
                .and_then(|s| s.parse().ok())
                .expect("invalid SNI_PROXY_LISTEN port");
            if let Err(e) = pasta::setup_sni_redirect(proxy_port) {
                eprintln!("hermit: SNI redirect setup failed: {:#}", e);
                std::process::exit(126);
            }
        }
    }

    info!("child: exec {:?}", command);
    let err = Command::new(&command[0]).args(&command[1..]).exec();
    eprintln!("hermit: exec failed: {}", err);
    std::process::exit(126);
}

/// Parent side of the fork. Forwards signals and waits for child exit.
///
/// When `pasta_writer` is Some (pasta mode):
///   1. Wait for ns-ready (child has namespace + landlock set up)
///   2. Launch pasta against child PID (creates tap device)
///   3. Signal pasta-ready so child can exec
///
/// If pasta fails, the pasta_writer is dropped without signaling (child sees
/// EOF and exits 126), then the child is killed and reaped.
fn parent_main(
    ns_reader: ReadyReader,
    pasta_writer: Option<ReadyWriter>,
    child: Pid,
    allowed_hosts: &[String],
) -> Result<i32> {
    install_signal_forwarding(child);

    // Wait for child to finish namespace + landlock setup
    ns_reader.wait()?;
    info!("parent: child namespace ready");

    // RAII handle — dropped at end of scope, killing the proxy
    let mut _sni_proxy_handle: Option<pasta::SniProxyChild> = None;

    // If pasta mode, launch pasta now and signal the child
    if let Some(writer) = pasta_writer {
        match pasta::launch_pasta(child) {
            Ok(()) => {
                info!("parent: pasta ready");
            }
            Err(e) => {
                drop(writer);
                info!("parent: pasta failed, killing child");
                let _ = kill(child, Signal::SIGKILL);
                let _ = waitpid(child, None);
                return Err(e).context("pasta setup failed");
            }
        }

        // Launch sni-proxy if allowed_hosts is non-empty
        if !allowed_hosts.is_empty() {
            match pasta::launch_sni_proxy(pasta::SNI_PROXY_LISTEN, allowed_hosts) {
                Ok(handle) => {
                    info!("parent: sni-proxy running");
                    _sni_proxy_handle = Some(handle);
                }
                Err(e) => {
                    drop(writer);
                    info!("parent: sni-proxy failed, killing child");
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    return Err(e).context("sni-proxy setup failed");
                }
            }
        }

        writer.signal();
        info!("parent: signaled child to proceed");
    }

    info!("parent: waiting for child exit");
    let exit_code = wait_for_child(child);
    // _sni_proxy_handle dropped here → proxy killed
    exit_code
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
    fn test_two_phase_pipe_round_trip() {
        // Simulate the two-phase protocol: ns-ready then pasta-ready
        let (ns_reader, ns_writer) = readiness_pipe().unwrap();
        let (pasta_reader, pasta_writer) = readiness_pipe().unwrap();

        // "Child" signals ns-ready
        ns_writer.signal();
        // "Parent" waits for ns-ready
        ns_reader.wait().unwrap();
        // "Parent" signals pasta-ready
        pasta_writer.signal();
        // "Child" waits for pasta-ready
        pasta_reader.wait().unwrap();
    }

    #[test]
    fn test_two_phase_pipe_dropped_writer_produces_error() {
        // Simulate pasta failure: parent drops pasta_writer without signaling
        let (ns_reader, ns_writer) = readiness_pipe().unwrap();
        let (pasta_reader, pasta_writer) = readiness_pipe().unwrap();

        ns_writer.signal();
        ns_reader.wait().unwrap();

        // Parent drops pasta writer without signaling (pasta failed)
        drop(pasta_writer);

        // Child should see an error
        let result = pasta_reader.wait();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("died before signaling"),
        );
    }
}
