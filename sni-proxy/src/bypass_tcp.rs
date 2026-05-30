//! Transparent TCP relay for `Mechanism::Bypass` rules.
//!
//! The listener sits on a dedicated loopback port inside the child
//! netns; nft DNATs the real target port (e.g. `389` for LDAP) to it.
//! For each accepted connection we:
//!
//! 1. Pull the pre-DNAT destination out of `SO_ORIGINAL_DST`.
//! 2. Reverse-map that dst IP to a hostname via the shared
//!    [`DnsCache`] — the child's own DNS lookup populated it moments
//!    ago. IPs not in the cache are denied (the child is attempting
//!    to reach a literal IP we never handed out).
//! 3. Check the bypass policy: was this hostname declared with a
//!    matching `(protocol, port)`?
//! 4. If allowed, dial the real destination from the host netns and
//!    splice bytes both ways until one side closes.
//!
//! No payload inspection. No protocol awareness. That's the point —
//! Kerberos, SSH, raw LDAP, etc. all work as long as their hostnames
//! were resolved through hermit DNS.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use crate::connector::UpstreamConnector;
use crate::dns_cache::DnsCache;
use crate::policy::{BypassProtocol, RuleSet};
use crate::proxy::{get_original_dst, MAX_CONCURRENT_CONNECTIONS};
use crate::timeouts::{BYPASS_TCP_IDLE_TIMEOUT, UPSTREAM_CONNECT_TIMEOUT};

/// Per-listener configuration. Each bypass `(protocol=tcp, port=N)`
/// gets its own `BypassTcpConfig` and its own accept loop.
pub struct BypassTcpConfig<C> {
    /// The port this relay is authoritative for. Used both to
    /// evaluate the policy match and to log a meaningful entry.
    pub port: u16,
    pub rules: Arc<RuleSet>,
    pub cache: Arc<DnsCache>,
    pub connector: Arc<C>,
    pub block_log: BlockLogger,
}

/// Run the TCP bypass accept loop until the listener is closed.
pub async fn run<C>(listener: TcpListener, config: Arc<BypassTcpConfig<C>>) -> Result<()>
where
    C: UpstreamConnector + 'static,
{
    let local = listener.local_addr().ok();
    tracing::info!(port = config.port, ?local, "bypass-tcp: accept loop starting");
    let conn_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    // Exponential backoff on accept failure: 10ms → 20ms → … →
    // capped at 1s. Reset on success. Constant-10ms-forever spins
    // CPU and floods logs when the listener is in a hot-broken
    // state (e.g. fd closed under us).
    let mut accept_backoff_ms = 10u64;
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => {
                accept_backoff_ms = 10;
                v
            }
            Err(e) => {
                warn!(error = %e, backoff_ms = accept_backoff_ms,
                    "bypass-tcp: accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(accept_backoff_ms)).await;
                accept_backoff_ms = (accept_backoff_ms.saturating_mul(2)).min(1000);
                continue;
            }
        };
        debug!(%addr, port = config.port, "bypass-tcp: accepted connection");
        let Ok(permit) = Arc::clone(&conn_limit).acquire_owned().await else {
            warn!(%addr, "bypass-tcp: connection semaphore closed; dropping");
            continue;
        };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(stream, addr, &config).await {
                debug!(%addr, error = %e, "bypass-tcp: connection ended");
            }
        });
    }
}

/// Accept-side wrapper: reads `SO_ORIGINAL_DST`, then delegates to
/// [`handle_connection_at`] which holds the real logic (and is what
/// unit tests target since they can supply their own fake dst).
async fn handle_connection<C>(
    client: TcpStream,
    client_addr: SocketAddr,
    config: &BypassTcpConfig<C>,
) -> Result<()>
where
    C: UpstreamConnector,
{
    let Some(orig) = get_original_dst(&client) else {
        // Only ever happens on a direct connect to the bypass port
        // from inside the sandbox (no DNAT applied). Treat as a
        // block-worthy anomaly so it's visible in the log, but
        // don't escalate — closing the socket is enough.
        debug!(%client_addr, port = config.port,
            "bypass-tcp: no SO_ORIGINAL_DST, closing (direct-to-relay connect?)");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(client_addr.to_string()),
            hostname: None,
            method: None,
            path: None,
            port: None,
            reason: Some("bypass-tcp: missing SO_ORIGINAL_DST".to_string()),
        });
        return Ok(());
    };
    debug!(%client_addr, dst_ip = %orig.ip(), dst_port = orig.port(),
        "bypass-tcp: SO_ORIGINAL_DST recovered");
    handle_connection_at(client, client_addr, orig.ip(), orig.port(), config).await
}

/// Core per-connection logic with an injected destination. Kept
/// separate from [`handle_connection`] so tests don't need to stage
/// a real DNAT. A deny path closes the client socket with no data
/// (bypass is transparent — there's no HTTP status we could return).
pub async fn handle_connection_at<C>(
    mut client: TcpStream,
    client_addr: SocketAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    config: &BypassTcpConfig<C>,
) -> Result<()>
where
    C: UpstreamConnector,
{
    // Reverse-lookup: the child's DNS query populated `cache`, so a
    // dst IP that we just handed out resolves back to the hostname
    // asked for. If it doesn't, fall through to the literal-IP rule
    // path — the child may have been given a raw IP that was
    // pre-authorized via `ip = "…"` in config.
    let hostname_opt = config.cache.reverse(dst_ip);
    debug!(%client_addr, %dst_ip, dst_port, port = config.port,
        hostname = ?hostname_opt,
        "bypass-tcp: policy check");
    let allowed = match &hostname_opt {
        Some(h) => config
            .rules
            .is_bypass_allowed(h, BypassProtocol::Tcp, config.port),
        None => config
            .rules
            .is_bypass_allowed_by_ip(dst_ip, BypassProtocol::Tcp, config.port),
    };
    debug!(%client_addr, hostname = ?hostname_opt, allowed,
        "bypass-tcp: policy decision");
    if !allowed {
        // Visible at the default log level (warn) so a denied flow
        // doesn't require -vv to diagnose. The block-log entry below
        // still carries the structured payload for offline analysis;
        // this warn! is for "the user is staring at stderr asking
        // why their connection just hung".
        warn!(%client_addr, ?hostname_opt, %dst_ip, port = config.port,
            "bypass-tcp: deny (no matching rule)");
        config.block_log.log(BlockEvent {
            time_unix_ms: now_unix_ms(),
            kind: BlockKind::Http,
            client: Some(client_addr.to_string()),
            hostname: hostname_opt.clone(),
            method: None,
            path: Some(format!("{dst_ip}:{dst_port}")),
            port: None,
            reason: Some(match hostname_opt.as_ref() {
                Some(_) => "bypass-tcp: no matching host rule".to_string(),
                None => "bypass-tcp: dst IP not in DNS cache and not allowed by ip rule".to_string(),
            }),
        });
        return Ok(());
    }

    // Dial: prefer the hostname (so TLS SNI / cert verification
    // further downstream sees the real name), otherwise fall back
    // to the IP literal for IP-only rules.
    let dial_target: String = hostname_opt
        .clone()
        .unwrap_or_else(|| dst_ip.to_string());
    debug!(%client_addr, dial_target = %dial_target, %dst_ip, port = dst_port,
        "bypass-tcp: dialing upstream");

    let upstream = match timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        config.connector.connect(&dial_target, dst_port, None),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(%dial_target, port = dst_port, error = %e,
                "bypass-tcp: upstream connect failed");
            let _ = client.shutdown().await;
            return Ok(());
        }
        Err(_) => {
            warn!(%dial_target, port = dst_port, "bypass-tcp: upstream connect timed out");
            let _ = client.shutdown().await;
            return Ok(());
        }
    };

    // Bidirectional splice. We intentionally use `copy_bidirectional`
    // rather than the raw `splice(2)` syscall for v1: it's already
    // non-blocking and driven by tokio's reactor, and the extra
    // zero-copy gains of splice-via-pipe are only measurable on bulk
    // data transfer — not the request/response pattern typical of
    // LDAP/SSH/Kerberos. Swap to a splice-based implementation if
    // throughput ever shows up in a profile.
    //
    // The streams are wrapped in `WriteCounter` so we can log how
    // many bytes flowed in each direction *even when the splice
    // returns Err* — `copy_bidirectional` discards its partial
    // counts on error, which is exactly when knowing "did anything
    // flow before the RST?" matters most for debugging.
    let c2u_counter = Arc::new(AtomicU64::new(0));
    let u2c_counter = Arc::new(AtomicU64::new(0));
    // Snapshot raw fds *before* the move into WriteCounter. We need
    // them at splice end for getsockopt(TCP_INFO); the underlying
    // sockets live until the wrappers drop, which happens after the
    // log lines below, so the fds stay valid.
    let client_fd = client.as_raw_fd();
    let upstream_fd = upstream.as_raw_fd();
    let mut client_wrapped = WriteCounter::new(client, Arc::clone(&u2c_counter));
    let mut upstream_wrapped = WriteCounter::new(upstream, Arc::clone(&c2u_counter));

    let splice_start = std::time::Instant::now();
    debug!(%client_addr, %dial_target, port = dst_port,
        "bypass-tcp: splice begin");
    // Race the splice against an idle watchdog: poll the existing
    // direction counters; if neither has advanced for
    // BYPASS_TCP_IDLE_TIMEOUT we abort the splice. Without this a
    // well-behaved-but-silent peer (or a NAT-eaten ESTABLISHED
    // entry) holds a relay slot indefinitely.
    let watchdog = watch_idle_splice(
        Arc::clone(&c2u_counter),
        Arc::clone(&u2c_counter),
        BYPASS_TCP_IDLE_TIMEOUT,
        Duration::from_secs(1),
    );
    let splice = tokio::select! {
        r = tokio::io::copy_bidirectional(
            &mut client_wrapped, &mut upstream_wrapped,
        ) => r,
        e = watchdog => Err(e),
    };
    let elapsed_ms = splice_start.elapsed().as_millis();
    let c2u = c2u_counter.load(Ordering::Relaxed);
    let u2c = u2c_counter.load(Ordering::Relaxed);
    // Per-side TCP_INFO at splice end so the debug log explains
    // "30s silent then RST"-style stalls without needing tcpdump or
    // root: kernel-reported state (CLOSE_WAIT / FIN_WAIT_2 /
    // LAST_ACK / ESTABLISHED…) plus per-side last-data ages and
    // retransmit counters tell us *which* side stopped talking and
    // whether the kernel saw a FIN, an RST, or just silence.
    let ci = tcp_info_snapshot(client_fd);
    let ui = tcp_info_snapshot(upstream_fd);
    let cs = tcp_info_state_name(&ci);
    let us = tcp_info_state_name(&ui);
    match splice {
        Ok(_) => debug!(%client_addr, %dial_target, port = dst_port,
            client_to_upstream_bytes = c2u, upstream_to_client_bytes = u2c,
            elapsed_ms,
            client_state = cs, upstream_state = us,
            client_last_recv_ms = tcp_info_field(&ci, |i| i.tcpi_last_data_recv),
            upstream_last_recv_ms = tcp_info_field(&ui, |i| i.tcpi_last_data_recv),
            client_last_send_ms = tcp_info_field(&ci, |i| i.tcpi_last_data_sent),
            upstream_last_send_ms = tcp_info_field(&ui, |i| i.tcpi_last_data_sent),
            client_retrans = tcp_info_field(&ci, |i| i.tcpi_total_retrans),
            upstream_retrans = tcp_info_field(&ui, |i| i.tcpi_total_retrans),
            "bypass-tcp: splice end"),
        Err(ref e) => debug!(%client_addr, %dial_target, port = dst_port,
            client_to_upstream_bytes = c2u, upstream_to_client_bytes = u2c,
            elapsed_ms,
            error = %e, errno = e.raw_os_error().unwrap_or(0),
            client_state = cs, upstream_state = us,
            client_last_recv_ms = tcp_info_field(&ci, |i| i.tcpi_last_data_recv),
            upstream_last_recv_ms = tcp_info_field(&ui, |i| i.tcpi_last_data_recv),
            client_last_send_ms = tcp_info_field(&ci, |i| i.tcpi_last_data_sent),
            upstream_last_send_ms = tcp_info_field(&ui, |i| i.tcpi_last_data_sent),
            client_retrans = tcp_info_field(&ci, |i| i.tcpi_total_retrans),
            upstream_retrans = tcp_info_field(&ui, |i| i.tcpi_total_retrans),
            "bypass-tcp: splice error"),
    }

    // Belt-and-suspenders close. `copy_bidirectional` only calls
    // shutdown(SHUT_WR) on a side when the *other* side returned a
    // clean EOF; on the error path (upstream RST mid-stream, etc.)
    // it propagates the first failing direction's Err and skips
    // the unrelated side entirely. The peer that wasn't told then
    // sits in CLOSE_WAIT until handle_connection_at returns and
    // Drop closes the fd — and if any unread bytes remain in the
    // recv buffer at that moment, the kernel's close path emits
    // RST instead of FIN. The child app sees "connection reset by
    // peer" instead of a clean EOF.
    //
    // shutdown(SHUT_RDWR) cleanly resolves both: it emits FIN if
    // not already sent, and discards the recv buffer so the later
    // close() on drop has nothing to RST about. Idempotent /
    // harmless on a side that's already fully closed; we ignore
    // the return code on purpose (EBADF / ENOTCONN are both fine).
    unsafe {
        libc::shutdown(client_fd, libc::SHUT_RDWR);
        libc::shutdown(upstream_fd, libc::SHUT_RDWR);
    }
    Ok(())
}

/// Splice-idle watchdog. Polls both direction counters every
/// `poll_interval`; returns when the *sum* hasn't advanced for
/// `idle_timeout`. Always returns an error (the future is meant
/// to be raced against the real splice via `tokio::select!`; if
/// the splice wins this future is dropped).
///
/// Reads the existing `AtomicU64` counters maintained by the two
/// `WriteCounter` wrappers, so there's no extra accounting on the
/// hot data path. Counter sum is enough — a direction-specific
/// stall (e.g. half-close) doesn't trip the watchdog as long as
/// the *other* direction is still moving bytes, which matches the
/// semantics we want.
pub(crate) async fn watch_idle_splice(
    c2u: Arc<AtomicU64>,
    u2c: Arc<AtomicU64>,
    idle_timeout: Duration,
    poll_interval: Duration,
) -> std::io::Error {
    let mut last_total = 0u64;
    let mut last_progress = std::time::Instant::now();
    loop {
        tokio::time::sleep(poll_interval).await;
        let now_total = c2u.load(Ordering::Relaxed) + u2c.load(Ordering::Relaxed);
        if now_total != last_total {
            last_total = now_total;
            last_progress = std::time::Instant::now();
        } else if last_progress.elapsed() >= idle_timeout {
            return std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "bypass-tcp splice idle timeout",
            );
        }
    }
}

/// `getsockopt(TCP_INFO)` on `fd`. Returns `None` if the call fails
/// (socket closed, not TCP, etc.) — caller logs "unavailable" rather
/// than guessing. Unprivileged: works for any user that owns the fd.
fn tcp_info_snapshot(fd: i32) -> Option<libc::tcp_info> {
    let mut info: std::mem::MaybeUninit<libc::tcp_info> = std::mem::MaybeUninit::zeroed();
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr() as *mut _,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(unsafe { info.assume_init() })
}

/// Human label for `tcpi_state` so the splice-end log is readable
/// without a `tcp_states.h` reference. Returns the literal "?" when
/// the snapshot is missing so the log field width stays predictable.
fn tcp_info_state_name(info: &Option<libc::tcp_info>) -> &'static str {
    let Some(i) = info else { return "?" };
    match i.tcpi_state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "unknown",
    }
}

/// Project a single `u32` field out of an optional snapshot.
/// `u32::MAX` is a sentinel for "no snapshot" — chosen because
/// real `tcpi_*_ms` fields cap out much lower (milliseconds since
/// a recent event) and any reader can spot the marker immediately.
fn tcp_info_field(info: &Option<libc::tcp_info>, f: impl Fn(&libc::tcp_info) -> u32) -> u32 {
    info.as_ref().map(f).unwrap_or(u32::MAX)
}

/// `AsyncRead + AsyncWrite` adapter that ticks a shared counter on
/// every successful `poll_write`. Reads pass through untouched.
///
/// Used to surface partial byte counts on the bypass-tcp splice
/// error path — `tokio::io::copy_bidirectional` only returns counts
/// on success, but the symptom we most often want to diagnose
/// ("relay started, then RST mid-stream") happens on the error
/// branch. Wrapping both sides of the splice with a `WriteCounter`
/// pointed at the *other* side's accounting variable gives us
/// per-direction byte totals regardless of how the splice ended.
struct WriteCounter<S> {
    inner: S,
    bytes_written: Arc<AtomicU64>,
}

impl<S> WriteCounter<S> {
    fn new(inner: S, bytes_written: Arc<AtomicU64>) -> Self {
        Self { inner, bytes_written }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteCounter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteCounter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.bytes_written.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Test-only wrappers around `bypass_tcp`'s private items.
/// Off by default; `sni-proxy-tests` flips on `__test_internals`.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncWrite};

    /// Construct the private `WriteCounter` wrapper for tests. Returns
    /// it as an opaque `AsyncRead + AsyncWrite` so the struct itself
    /// stays unexported — tests exercise it through the trait surface,
    /// which is what real callers use too.
    pub fn write_counter<S>(
        inner: S,
        bytes: Arc<AtomicU64>,
    ) -> impl AsyncRead + AsyncWrite + Unpin
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        super::WriteCounter::new(inner, bytes)
    }

    /// `(state_name, last_data_recv_ms)` projected from
    /// `getsockopt(TCP_INFO)` on `fd`. `None` if the call failed.
    /// Test-only: exposes just enough of the snapshot to verify the
    /// diagnostic plumbing without re-exporting `libc::tcp_info`.
    pub fn tcp_info_for_test(fd: i32) -> Option<(&'static str, u32)> {
        let info = super::tcp_info_snapshot(fd)?;
        Some((super::tcp_info_state_name(&Some(info)), info.tcpi_last_data_recv))
    }

    /// Run the splice-idle watchdog with caller-supplied poll
    /// interval (production uses 1s; tests use ~10ms so the
    /// `idle_timeout` can also be small and the test runs fast).
    /// Returns the `io::Error` the watchdog would have surfaced.
    pub async fn watch_idle_splice(
        c2u: Arc<AtomicU64>,
        u2c: Arc<AtomicU64>,
        idle_timeout: std::time::Duration,
        poll_interval: std::time::Duration,
    ) -> std::io::Error {
        super::watch_idle_splice(c2u, u2c, idle_timeout, poll_interval).await
    }
}
