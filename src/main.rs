use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{info, warn};
use std::path::{Path, PathBuf};
use std::process;

use hermit::cli::{Cli, Command, KeygenArgs, RunArgs, SignArgs, VerifyArgs};
use hermit::{config::Config, config_loader, landlock, sandbox::run_sandboxed, signature};

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
    }
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(level)
        .format_target(false)
        .format_timestamp(None)
        .init();

    // sni-proxy uses the `tracing` facade (not `log`), so env_logger alone
    // would drop proxy events — including the `warn!` lines emitted when the
    // MITM, HTTP proxy, or DNS layer blocks a request. Install a tracing
    // subscriber at the same verbosity so those block events reach stderr.
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .try_init();
}

fn run_subcommand(args: RunArgs) -> Result<i32> {
    init_logging(args.verbose);

    // Refuse to start if the kernel can't enforce Landlock — the whole
    // filesystem-isolation story depends on it.
    landlock::ensure_available()?;

    let project_dir = args
        .project_dir
        .canonicalize()
        .with_context(|| format!("--project-dir '{}' does not exist", args.project_dir.display()))?;
    info!("project dir: {}", project_dir.display());
    info!("config URL: {}", args.config);

    let bytes = config_loader::fetch(&args.config)?;
    if args.allow_unsigned {
        warn!(
            "--allow-unsigned: skipping signature verification for {} \
             (this bypasses the trust anchor in ~/.hermit/keys)",
            args.config
        );
    } else {
        let trust_dir = default_trust_dir()?;
        let trusted = signature::verify(&bytes, &trust_dir)
            .with_context(|| format!("verifying {}", args.config))?;
        info!("config verified by trusted key: {}", trusted.path.display());
    }

    let text = std::str::from_utf8(&bytes).context("config is not valid UTF-8")?;
    let config = Config::parse(text)?;

    info!("command: {}", args.command.join(" "));
    run_sandboxed(&project_dir, &args.command, &config)
}

fn sign_subcommand(args: SignArgs) -> Result<i32> {
    init_logging(0);
    let cert_pem = std::fs::read_to_string(&args.cert)
        .with_context(|| format!("reading cert {}", args.cert.display()))?;
    let key_pem = std::fs::read_to_string(&args.key)
        .with_context(|| format!("reading key {}", args.key.display()))?;
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
    init_logging(0);
    let trust_dir = match args.trust_dir {
        Some(p) => p,
        None => default_trust_dir()?,
    };
    let bytes = config_loader::fetch(&args.config)?;
    let trusted = signature::verify(&bytes, &trust_dir)
        .with_context(|| format!("verifying {}", args.config))?;
    println!("OK: verified by {}", trusted.path.display());
    Ok(0)
}

/// Resolve the trust directory. `HERMIT_TRUST_DIR` wins over the
/// default `~/.hermit/keys` so tests can point hermit at a scoped trust
/// anchor without relying on a host `~/.hermit`.
fn keygen_subcommand(args: KeygenArgs) -> Result<i32> {
    init_logging(0);

    if !args.force {
        if args.cert.exists() {
            bail!(
                "{} already exists (use --force to overwrite)",
                args.cert.display()
            );
        }
        if args.key.exists() {
            bail!(
                "{} already exists (use --force to overwrite)",
                args.key.display()
            );
        }
    }

    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generating ed25519 keypair")?;
    let cert = rcgen::CertificateParams::new(vec![args.subject.clone()])
        .context("building cert params")?
        .self_signed(&kp)
        .context("self-signing certificate")?;

    std::fs::write(&args.cert, cert.pem())
        .with_context(|| format!("writing cert {}", args.cert.display()))?;
    write_private_key(&args.key, &kp.serialize_pem())?;

    println!("cert  -> {}", args.cert.display());
    println!("key   -> {} (mode 0600)", args.key.display());
    println!(
        "note: to trust configs signed by this key, copy {} into ~/.hermit/keys/",
        args.cert.display()
    );
    Ok(0)
}

/// Write a private key file with restrictive permissions (0600 on unix).
/// Uses `OpenOptions` so the permission bits apply from creation, not as
/// a follow-up chmod race.
fn write_private_key(path: &Path, pem: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(pem.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, pem)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
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
