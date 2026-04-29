use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{info, warn};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;

use hermit::cli::{
    Cli, Command, EditConfigAction, EditConfigArgs, KeygenArgs, LearnArgs, LearnConvertArgs,
    ProxyArgs, RunArgs, SignArgs, VerifyArgs,
};
use hermit::config_loader::TrustPolicy;
use hermit::sandbox::default_access_log_path;
use hermit::{config_loader, edit_config, landlock, learn_convert, sandbox::run_sandboxed, signature};

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hermit: {:#}", e);
            1
        }
    };
    process::exit(exit_code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => run_subcommand(args),
        Command::Sign(args) => sign_subcommand(args),
        Command::Verify(args) => verify_subcommand(args),
        Command::Keygen(args) => keygen_subcommand(args),
        Command::EditConfig(args) => edit_config_subcommand(args),
        Command::Learn(args) => learn_subcommand(args),
        Command::LearnConvert(args) => learn_convert_subcommand(args),
        Command::Proxy(args) => proxy_subcommand(args),
    }
}

fn learn_convert_subcommand(args: LearnConvertArgs) -> Result<i32> {
    learn_convert::convert(&args)?;
    Ok(0)
}

fn learn_subcommand(args: LearnArgs) -> Result<i32> {
    init_logging(args.verbose, args.log_file.as_deref())?;
    if let Some(p) = &args.log_file {
        info!("log file: {}", p.display());
    }

    landlock::ensure_available()?;

    let project_dir = args
        .project_dir
        .canonicalize()
        .with_context(|| format!("--project-dir '{}' does not exist", args.project_dir.display()))?;

    // Learn mode skips signature verification by default — the
    // workflow is "I'm authoring rules from scratch, take whatever
    // I have right now". An operator who explicitly wants the
    // signed path should use `hermit run` with their wip rules.
    let trust = TrustPolicy::AllowUnsigned;
    if !args.allow_unsigned {
        warn!(
            "learn mode: signature verification is always skipped \
             (this is observation only; no enforcement happens)"
        );
    }

    let config = match &args.config {
        Some(url) => config_loader::assemble(url, &trust)
            .with_context(|| format!("loading config from {}", url))?,
        None => {
            info!(
                "learn mode: no --config provided, synthesizing a passthrough \
                 config (passthrough = [\"/\"])"
            );
            default_learn_config()?
        }
    };

    // Resolve the access-log path, defaulting to XDG and creating
    // the parent directory so the BlockLogger writer's `open(...)`
    // succeeds on a fresh machine.
    let access_log_path = args
        .access_log
        .clone()
        .unwrap_or_else(default_access_log_path);
    if let Some(parent) = access_log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating access-log directory {}", parent.display()))?;
    }
    info!("learn mode: trace -> {}", access_log_path.display());

    info!("command: {}", args.command.join(" "));
    run_sandboxed(
        &project_dir,
        &args.command,
        &config,
        None,  // block log: irrelevant in learn mode (nothing is blocked)
        true,  // no_block_log: skip the block log entirely
        Some(&access_log_path),
        true, // permit_all
    )
}

/// Build the synthetic config used when `hermit learn` is invoked
/// without `--config`. Carries `passthrough = ["/"]` so the build
/// runs against the host filesystem (Landlock allows everything),
/// while learn-mode's `permit_all` + forced `net = isolate` keep
/// the proxies observing network access.
fn default_learn_config() -> Result<hermit::config::Config> {
    hermit::config::Config::parse(
        r#"
[sandbox]
passthrough = ["/"]
"#,
    )
    .context("building default learn-mode config")
}

/// Run the proxy services in the foreground without forking a
/// sandboxed child or installing nft DNAT. Useful for testing the
/// proxy code path against an external client driven through
/// `HTTP_PROXY` / `HTTPS_PROXY`, or for capturing what an
/// unsandboxed app does.
fn proxy_subcommand(args: ProxyArgs) -> Result<i32> {
    use std::sync::Arc;
    use sni_proxy::policy::RuleSet;

    init_logging(args.verbose, args.log_file.as_deref())?;
    if let Some(p) = &args.log_file {
        info!("log file: {}", p.display());
    }

    // Config loading mirrors `hermit run`: signed by default,
    // unsigned only when explicitly requested. Trust dir
    // resolution falls back to ~/.hermit/keys / HERMIT_TRUST_DIR.
    let trust_dir_buf = if args.allow_unsigned {
        warn!(
            "--allow-unsigned: skipping signature verification for {} \
             and any included files",
            args.config
        );
        None
    } else {
        Some(default_trust_dir()?)
    };
    let trust = match &trust_dir_buf {
        Some(dir) => TrustPolicy::RequireSigned { trust_dir: dir },
        None => TrustPolicy::AllowUnsigned,
    };
    let config = config_loader::assemble(&args.config, &trust)
        .with_context(|| format!("loading config from {}", args.config))?;

    let access_rules = config.access_rules()?;
    let ip_rules = config.ip_rules()?;
    if !config.port_forwards.is_empty() {
        warn!(
            "proxy mode: ignoring {} [[port_forward]] entries — they require \
             nft DNAT, which proxy mode does not install",
            config.port_forwards.len()
        );
    }
    let bypass_count = access_rules
        .iter()
        .filter(|r| matches!(r.mechanism, sni_proxy::policy::Mechanism::Bypass { .. }))
        .count()
        + ip_rules.len();
    if bypass_count > 0 {
        warn!(
            "proxy mode: ignoring {} bypass rule(s) — they need nft DNAT + \
             SO_ORIGINAL_DST and are unreachable through HTTP_PROXY",
            bypass_count
        );
    }

    let policy = Arc::new(
        RuleSet::new(access_rules)
            .with_ip_rules(ip_rules)
            .with_permit_all(args.permit_all),
    );
    if args.permit_all {
        info!("proxy mode: --permit-all — every host is allowed and recorded");
    }
    let network_policy = config.network_policy()?.map(Arc::new);

    // Generate the ephemeral CA. Same shape as the sandbox path,
    // but the cert must be made available to the *external*
    // client (we can't bind-mount into its trust store).
    let ca = Arc::new(
        sni_proxy::ca::CertificateAuthority::new()
            .context("failed to generate ephemeral CA")?,
    );
    let ca_pem = ca.ca_cert_pem().to_string();
    if let Some(path) = &args.ca_cert {
        std::fs::write(path, ca_pem.as_bytes())
            .with_context(|| format!("writing CA cert to {}", path.display()))?;
        info!("ca cert: {}", path.display());
    } else {
        // No path provided — print to stdout so a caller can pipe
        // it (`hermit proxy ... | ca-trust install`-style) without
        // having to scrape a temp file.
        println!("{}", ca_pem);
    }

    let dns_upstream = config.dns().upstream_addr()?;

    // Build a tokio runtime and spawn the proxy services.
    let rt = tokio::runtime::Runtime::new()
        .context("creating tokio runtime")?;

    let block_log = build_block_log(&rt, &args)?;
    let access_log = match &args.access_log {
        Some(p) => {
            info!("access log: {}", p.display());
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            rt.block_on(async { sni_proxy::block_log::BlockLogger::to_file(p).await })
                .context("opening access log")?
        }
        None => sni_proxy::block_log::BlockLogger::disabled(),
    };

    // Bind listeners on the *host* network — no namespace switch.
    // We use `tokio::net::TcpListener::bind` directly; the address
    // strings are validated by clap-default + here at runtime.
    let https_listener = rt
        .block_on(tokio::net::TcpListener::bind(&args.listen_https))
        .with_context(|| format!("binding HTTPS listener on {}", args.listen_https))?;
    let http_listener = rt
        .block_on(tokio::net::TcpListener::bind(&args.listen_http))
        .with_context(|| format!("binding HTTP listener on {}", args.listen_http))?;
    let https_addr = https_listener.local_addr().ok();
    let http_addr = http_listener.local_addr().ok();

    let dns_socket: Option<tokio::net::UdpSocket> = match &args.listen_dns {
        Some(addr) => Some(
            rt.block_on(tokio::net::UdpSocket::bind(addr))
                .with_context(|| format!("binding DNS socket on {addr}"))?,
        ),
        None => None,
    };
    let dns_addr = dns_socket.as_ref().and_then(|s| s.local_addr().ok());

    // Configs identical to the sandbox path, minus the netns-bound
    // upstream_port quirks. `upstream_port` is the *default* port
    // the connector dials when the original-dst lookup yields
    // nothing — for proxy mode there's no DNAT and SO_ORIGINAL_DST
    // is always None, so the default carries every CONNECT.
    let mitm_config = Arc::new(sni_proxy::mitm::MitmConfig {
        policy: Arc::clone(&policy),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        ca,
        upstream_port: 443,
        network_policy,
        block_log: block_log.clone(),
        access_log: access_log.clone(),
    });

    let mut allowed_connect_ports: std::collections::BTreeSet<u16> =
        std::collections::BTreeSet::new();
    allowed_connect_ports.insert(443);
    for pf in &config.port_forwards {
        if matches!(pf.protocol, hermit::config::PortProtocol::Https) {
            allowed_connect_ports.insert(pf.port);
        }
    }
    let http_config = Arc::new(sni_proxy::http_proxy::HttpProxyConfig {
        policy: Arc::clone(&policy),
        connector: Arc::new(sni_proxy::connector::DirectConnector),
        upstream_port: 80,
        allowed_connect_ports,
        block_log: block_log.clone(),
        access_log: access_log.clone(),
    });

    let dns_cache = Arc::new(sni_proxy::dns_cache::DnsCache::new());
    let dns_server = if dns_socket.is_some() {
        let forwarder =
            Arc::new(sni_proxy::dns_forwarder::DnsForwarder::new(dns_upstream));
        Some(Arc::new(
            sni_proxy::dns::DnsServer::new(Arc::clone(&policy))
                .with_block_log(block_log.clone())
                .with_access_log(access_log.clone())
                .with_upstream(forwarder)
                .with_cache(Arc::clone(&dns_cache)),
        ))
    } else {
        None
    };

    print_ready_banner(https_addr, http_addr, dns_addr, args.ca_cert.as_deref());

    rt.block_on(async move {
        let mitm = tokio::spawn(async move {
            if let Err(e) = sni_proxy::mitm::run(https_listener, mitm_config).await {
                eprintln!("hermit: mitm proxy error: {e}");
            }
        });
        let http = tokio::spawn(async move {
            if let Err(e) = sni_proxy::http_proxy::run(http_listener, http_config).await {
                eprintln!("hermit: http proxy error: {e}");
            }
        });
        let dns = match (dns_server, dns_socket) {
            (Some(server), Some(socket)) => Some(tokio::spawn(async move {
                if let Err(e) = server.run(socket).await {
                    eprintln!("hermit: dns server error: {e}");
                }
            })),
            _ => None,
        };

        // Block until the operator interrupts. SIGINT covers
        // Ctrl-C; SIGTERM covers `kill <pid>` and supervisord-
        // style stop signals. Either fires → we drop the
        // listener tasks and the runtime tears them down.
        wait_for_signal().await;
        eprintln!("hermit: shutting down");
        mitm.abort();
        http.abort();
        if let Some(h) = dns {
            h.abort();
        }
    });

    Ok(0)
}

fn build_block_log(
    rt: &tokio::runtime::Runtime,
    args: &ProxyArgs,
) -> Result<sni_proxy::block_log::BlockLogger> {
    if args.no_block_log {
        return Ok(sni_proxy::block_log::BlockLogger::disabled());
    }
    let path = args
        .block_log
        .clone()
        .unwrap_or_else(hermit::sandbox::default_block_log_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    info!("block log: {}", path.display());
    rt.block_on(async { sni_proxy::block_log::BlockLogger::to_file(&path).await })
        .context("opening block log")
}

/// Print the listen addresses + a CA hint so the user knows how
/// to configure their client. Goes to stderr so an operator who
/// piped stdout to capture the CA PEM still sees it.
fn print_ready_banner(
    https: Option<std::net::SocketAddr>,
    http: Option<std::net::SocketAddr>,
    dns: Option<std::net::SocketAddr>,
    ca_path: Option<&Path>,
) {
    eprintln!("hermit proxy: listening");
    if let Some(a) = https {
        eprintln!("  HTTPS  {a}  (MITM)");
    }
    if let Some(a) = http {
        eprintln!("  HTTP   {a}  (HTTP_PROXY/HTTPS_PROXY entry point)");
    }
    if let Some(a) = dns {
        eprintln!("  DNS    {a}  (UDP)");
    }
    match ca_path {
        Some(p) => eprintln!("  CA cert -> {}", p.display()),
        None => eprintln!("  CA cert printed above on stdout"),
    }
    let http_url = http.map(|a| format!("http://{a}"));
    if let Some(u) = http_url {
        eprintln!();
        eprintln!("Example client setup:");
        eprintln!("  HTTP_PROXY={u} HTTPS_PROXY={u} <your-command>");
        eprintln!();
    }
    eprintln!("Press Ctrl+C to stop.");
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hermit: failed to install SIGTERM handler: {e}");
            // Falling back to SIGINT-only is still useful.
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

fn edit_config_subcommand(args: EditConfigArgs) -> Result<i32> {
    match args.action {
        EditConfigAction::AddRule(a) => edit_config::add_rule(&a)?,
        EditConfigAction::RemoveRule(a) => edit_config::remove_rule(&a)?,
        EditConfigAction::Show(a) => edit_config::show(&a)?,
    }
    Ok(0)
}

fn init_logging(verbose: u8, log_file: Option<&Path>) -> Result<()> {
    let level = match verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    // Open the log file up front (once) so both logging frameworks write
    // into the same sink. POSIX O_APPEND writes are atomic for the small
    // records emitted here, so two handles on the same file don't tear
    // each other's lines.
    let file_handle = match log_file {
        Some(p) => Some(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .with_context(|| format!("opening log file {}", p.display()))?,
        ),
        None => None,
    };

    let env_target = match &file_handle {
        Some(f) => env_logger::Target::Pipe(Box::new(
            f.try_clone().context("cloning log file handle for env_logger")?,
        )),
        None => env_logger::Target::Stderr,
    };
    env_logger::Builder::new()
        .filter_level(level)
        .format_target(false)
        .format_timestamp(None)
        .target(env_target)
        .init();

    // sni-proxy uses the `tracing` facade (not `log`), so env_logger alone
    // would drop proxy events — including the `warn!` lines emitted when the
    // MITM, HTTP proxy, or DNS layer blocks a request. Install a tracing
    // subscriber at the same verbosity so those events reach the same sink.
    let tracing_level = match verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(tracing_level.to_string()));
    // `try_init` returns Err if a subscriber is already installed (e.g. from
    // a test harness reusing the process) — we silently swallow that because
    // a duplicate-install error isn't actionable at runtime.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time();
    match file_handle {
        Some(f) => {
            // `Mutex<File>` directly satisfies tracing-subscriber's
            // `MakeWriter` via its specialised impl, and the subscriber
            // takes ownership — no Arc needed (and in fact `Arc<Mutex<F>>`
            // does NOT satisfy MakeWriter: the blanket impl for Arc
            // requires `&W: io::Write`, which `&Mutex<File>` doesn't
            // provide).
            let writer = Mutex::new(f);
            let _ = builder.with_writer(writer).try_init();
        }
        None => {
            let _ = builder.with_writer(std::io::stderr).try_init();
        }
    }

    Ok(())
}

fn run_subcommand(args: RunArgs) -> Result<i32> {
    init_logging(args.verbose, args.log_file.as_deref())?;
    if let Some(p) = &args.log_file {
        info!("log file: {}", p.display());
    }

    // Refuse to start if the kernel can't enforce Landlock — the whole
    // filesystem-isolation story depends on it.
    landlock::ensure_available()?;

    let project_dir = args
        .project_dir
        .canonicalize()
        .with_context(|| format!("--project-dir '{}' does not exist", args.project_dir.display()))?;
    info!("project dir: {}", project_dir.display());
    info!("config URL: {}", args.config);

    // `trust_dir_buf` owns the PathBuf; `trust` borrows it. Both must
    // outlive the `assemble` call, which is why we bind the owner first.
    let trust_dir_buf = if args.allow_unsigned {
        warn!(
            "--allow-unsigned: skipping signature verification for {} \
             and any included files \
             (this bypasses the trust anchor in ~/.hermit/keys)",
            args.config
        );
        None
    } else {
        Some(default_trust_dir()?)
    };
    let trust = match &trust_dir_buf {
        Some(dir) => TrustPolicy::RequireSigned { trust_dir: dir },
        None => TrustPolicy::AllowUnsigned,
    };

    let config = config_loader::assemble(&args.config, &trust)
        .with_context(|| format!("loading config from {}", args.config))?;

    info!("command: {}", args.command.join(" "));
    run_sandboxed(
        &project_dir,
        &args.command,
        &config,
        args.block_log.as_deref(),
        args.no_block_log,
        None,  // access log only used by `hermit learn`
        false, // permit_all only set by `hermit learn`
    )
}

fn sign_subcommand(args: SignArgs) -> Result<i32> {
    init_logging(0, None)?;
    let cert_path = match args.cert {
        Some(p) => p,
        None => default_signer_cert_path()?,
    };
    let key_path = match args.key {
        Some(p) => p,
        None => default_signer_key_path()?,
    };
    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("reading cert {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("reading key {}", key_path.display()))?;
    let unsigned = std::fs::read(&args.config)
        .with_context(|| format!("reading config {}", args.config.display()))?;
    let signed = signature::sign(&unsigned, &cert_pem, &key_pem)?;
    let output = args.output.as_ref().unwrap_or(&args.config);
    std::fs::write(output, &signed)
        .with_context(|| format!("writing signed config {}", output.display()))?;
    println!("signed -> {}", output.display());
    Ok(0)
}

fn verify_subcommand(args: VerifyArgs) -> Result<i32> {
    init_logging(0, None)?;
    let trust_dir = match args.trust_dir {
        Some(p) => p,
        None => default_trust_dir()?,
    };
    // Verify the root directly so we can report which trusted key signed
    // it. Then walk any includes via `assemble` so we don't green-light a
    // config whose transitively-included files are unsigned.
    let bytes = config_loader::fetch(&args.config)?;
    let trusted = signature::verify(&bytes, &trust_dir)
        .with_context(|| format!("verifying {}", args.config))?;
    config_loader::assemble(
        &args.config,
        &TrustPolicy::RequireSigned { trust_dir: &trust_dir },
    )
    .with_context(|| format!("verifying {} and its includes", args.config))?;
    println!("OK: verified by {}", trusted.path.display());
    Ok(0)
}

/// Resolve the trust directory. `HERMIT_TRUST_DIR` wins over the
/// default `~/.hermit/keys` so tests can point hermit at a scoped trust
/// anchor without relying on a host `~/.hermit`.
fn keygen_subcommand(args: KeygenArgs) -> Result<i32> {
    init_logging(0, None)?;

    let cert_path = match args.cert {
        Some(p) => p,
        None => default_signer_cert_path()?,
    };
    let key_path = match args.key {
        Some(p) => p,
        None => default_signer_key_path()?,
    };

    // The default `~/.hermit/signer.{cert,key}.pem` paths put the
    // output in a directory the user may not have created yet. Make
    // it on demand so the very first `hermit keygen` run works
    // out of the box. For an explicit --cert/--key the user has
    // already chosen a parent — still create it for symmetry; if it
    // already exists `create_dir_all` is a no-op.
    for p in [&cert_path, &key_path] {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
    }

    // Up-front existence check uses `symlink_metadata` so a
    // pre-planted symlink at the target path is also detected
    // (`Path::exists` would silently follow it). The actual write
    // below is guarded by `O_EXCL | O_NOFOLLOW`; this branch is
    // about producing a friendly error before we get there.
    if !args.force {
        for p in [&cert_path, &key_path] {
            match std::fs::symlink_metadata(p) {
                Ok(_) => bail!(
                    "{} already exists (use --force to overwrite)",
                    p.display()
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::Error::from(e))
                        .with_context(|| format!("stat {}", p.display()));
                }
            }
        }
    } else {
        // `--force` must remove any existing entry up front so the
        // O_EXCL open below can succeed. `remove_file` unlinks
        // both regular files and symlinks (it never follows the
        // link), so a pre-planted symlink is dispatched cleanly.
        for p in [&cert_path, &key_path] {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::Error::from(e))
                        .with_context(|| format!("removing existing {}", p.display()));
                }
            }
        }
    }

    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generating ed25519 keypair")?;
    let cert = rcgen::CertificateParams::new(vec![args.subject.clone()])
        .context("building cert params")?
        .self_signed(&kp)
        .context("self-signing certificate")?;

    write_new_file_excl(&cert_path, cert.pem().as_bytes(), 0o644)?;
    write_new_file_excl(&key_path, kp.serialize_pem().as_bytes(), 0o600)?;

    println!("cert  -> {}", cert_path.display());
    println!("key   -> {} (mode 0600)", key_path.display());
    println!(
        "note: to trust configs signed by this key, copy {} into ~/.hermit/keys/",
        cert_path.display()
    );
    Ok(0)
}

/// Create `path` with the given mode bits and write `bytes` to it.
///
/// Open is `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`:
/// * `O_EXCL` rejects pre-existing files, so we never silently
///   overwrite a file the user (or an attacker) planted at this
///   path. Callers handle `--force` by `unlink`-ing first.
/// * `O_NOFOLLOW` rejects a symlink at the target — combined with
///   `O_EXCL` this means the file we're about to write definitely
///   wasn't there a moment ago and isn't aliasing anything else.
/// * `mode` is set from creation, not via a chmod race.
///
/// On non-unix platforms falls back to `std::fs::write` — the
/// restrictive flags don't have direct equivalents.
fn write_new_file_excl(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, bytes)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// Default location for the signer's PEM cert when `hermit sign` /
/// `hermit keygen` is invoked without `--cert`. Lives next to the
/// trust dir so a user who runs keygen → moves the cert into
/// `keys/` → re-runs sign has a single home directory to think about.
fn default_signer_cert_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .context("cannot locate signer cert: $HOME is not set")?;
    Ok(Path::new(&home).join(".hermit/signer.cert.pem"))
}

/// Companion to [`default_signer_cert_path`] for the private key.
fn default_signer_key_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .context("cannot locate signer key: $HOME is not set")?;
    Ok(Path::new(&home).join(".hermit/signer.key.pem"))
}

fn default_trust_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("HERMIT_TRUST_DIR") {
        let dir = PathBuf::from(p);
        if !dir.exists() {
            bail!(
                "HERMIT_TRUST_DIR={} does not exist",
                dir.display()
            );
        }
        return Ok(dir);
    }
    let home = std::env::var("HOME")
        .context("cannot locate trust directory: $HOME is not set")?;
    let dir = Path::new(&home).join(".hermit/keys");
    if !dir.exists() {
        bail!(
            "trust directory {} does not exist; create it and add trusted ed25519 cert .pem files",
            dir.display()
        );
    }
    Ok(dir)
}
