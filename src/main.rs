use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{info, warn};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Mutex;

use hermit::cli::{
    Cli, Command, EditConfigAction, EditConfigArgs, KeygenArgs, LearnArgs, LearnConvertArgs,
    RunArgs, SignArgs, VerifyArgs,
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
