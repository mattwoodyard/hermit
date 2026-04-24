use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Network isolation mode for the sandbox.
///
/// Kept as an enum here (rather than derived from the TOML) because
/// internal code paths (sandbox.rs, process.rs) need to branch on it.
/// `config::NetMode::to_cli` lowers the TOML form into this one.
#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum NetMode {
    /// Share the host network namespace (no isolation).
    #[default]
    Host,
    /// Empty network namespace with zero connectivity except through
    /// the hermit proxy.
    Isolate,
}

impl std::fmt::Display for NetMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetMode::Host => write!(f, "host"),
            NetMode::Isolate => write!(f, "isolate"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "hermit", about = "Lightweight container/sandbox for build commands")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a command inside the sandbox, using the signed config at URL.
    Run(RunArgs),
    /// Append a `[signature]` section to a config TOML, signing with an
    /// ed25519 x509 cert + matching PKCS8 private key (both PEM).
    Sign(SignArgs),
    /// Verify a signed config URL against trusted keys in `~/.hermit/keys`.
    Verify(VerifyArgs),
    /// Generate a fresh ed25519 signer keypair + self-signed x509 cert.
    Keygen(KeygenArgs),
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// URL of the signed config. `file://...` or `https://...`.
    #[arg(long)]
    pub config: String,

    /// Skip signature verification and accept a config without a
    /// `[signature]` section. Intended for local development — a
    /// loud warning is logged when this is used.
    #[arg(long)]
    pub allow_unsigned: bool,

    /// Verbose output. `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Project directory (read-write inside the sandbox).
    #[arg(long, default_value = ".")]
    pub project_dir: PathBuf,

    /// Append JSON-lines block events (blocked DNS queries, blocked
    /// TLS/HTTP requests) to this file. Defaults to
    /// `$XDG_STATE_HOME/hermit/blocks.jsonl` (fallback
    /// `~/.local/state/hermit/blocks.jsonl`) when omitted — the parent
    /// directory is created if it doesn't already exist. Pass
    /// `--no-block-log` to disable entirely.
    #[arg(long, conflicts_with = "no_block_log")]
    pub block_log: Option<PathBuf>,

    /// Disable block-event logging entirely. By default hermit records
    /// blocked DNS/TLS/HTTP events to
    /// `$XDG_STATE_HOME/hermit/blocks.jsonl`.
    #[arg(long)]
    pub no_block_log: bool,

    /// Write hermit's own info/warn/debug output to this file instead of
    /// stderr. Useful when running an interactive command inside the
    /// sandbox where interleaved warnings (stalled connects, retries,
    /// ...) would otherwise distract from the command's own output. The
    /// sandboxed command's stdout/stderr are unaffected.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Command and arguments to run inside the sandbox.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct SignArgs {
    /// Path to the signer's x509 certificate in PEM form.
    #[arg(long)]
    pub cert: PathBuf,

    /// Path to the signer's PKCS8 ed25519 private key in PEM form.
    #[arg(long)]
    pub key: PathBuf,

    /// Config file to sign (must not already have a `[signature]` section).
    pub config: PathBuf,

    /// Write the signed output here. If omitted, overwrite `config` in place.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct VerifyArgs {
    /// URL of the signed config to verify.
    pub config: String,

    /// Override the trust directory. Defaults to `~/.hermit/keys`.
    #[arg(long)]
    pub trust_dir: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct KeygenArgs {
    /// Write the self-signed x509 certificate here (PEM).
    #[arg(long)]
    pub cert: PathBuf,

    /// Write the PKCS8 ed25519 private key here (PEM).
    /// The file is created with mode 0600.
    #[arg(long)]
    pub key: PathBuf,

    /// Subject common name for the generated cert.
    #[arg(long, default_value = "hermit-signer")]
    pub subject: String,

    /// Overwrite `--cert` / `--key` if they already exist.
    #[arg(long)]
    pub force: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_run_minimal() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///tmp/hermit.toml",
            "--",
            "make",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.config, "file:///tmp/hermit.toml");
                assert_eq!(args.project_dir, PathBuf::from("."));
                assert_eq!(args.command, vec!["make"]);
                assert_eq!(args.verbose, 0);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_with_all_flags() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "https://example.com/h.toml",
            "-vv",
            "--project-dir",
            "/tmp/proj",
            "--",
            "cargo",
            "build",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.config, "https://example.com/h.toml");
                assert_eq!(args.project_dir, PathBuf::from("/tmp/proj"));
                assert_eq!(args.command, vec!["cargo", "build"]);
                assert_eq!(args.verbose, 2);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn run_requires_config_url() {
        assert!(Cli::try_parse_from(["hermit", "run", "--", "make"]).is_err());
    }

    #[test]
    fn run_requires_command() {
        assert!(Cli::try_parse_from([
            "hermit", "run", "--config", "file:///x",
        ])
        .is_err());
    }

    #[test]
    fn parse_sign() {
        let cli = Cli::parse_from([
            "hermit",
            "sign",
            "--cert",
            "/tmp/cert.pem",
            "--key",
            "/tmp/key.pem",
            "config.toml",
        ]);
        match cli.command {
            Command::Sign(args) => {
                assert_eq!(args.cert, PathBuf::from("/tmp/cert.pem"));
                assert_eq!(args.key, PathBuf::from("/tmp/key.pem"));
                assert_eq!(args.config, PathBuf::from("config.toml"));
                assert!(args.output.is_none());
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_sign_with_output() {
        let cli = Cli::parse_from([
            "hermit",
            "sign",
            "--cert",
            "/tmp/c.pem",
            "--key",
            "/tmp/k.pem",
            "--output",
            "/tmp/out.toml",
            "in.toml",
        ]);
        match cli.command {
            Command::Sign(args) => {
                assert_eq!(args.output, Some(PathBuf::from("/tmp/out.toml")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_verify() {
        let cli = Cli::parse_from(["hermit", "verify", "file:///tmp/h.toml"]);
        match cli.command {
            Command::Verify(args) => {
                assert_eq!(args.config, "file:///tmp/h.toml");
                assert!(args.trust_dir.is_none());
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_verify_with_trust_dir() {
        let cli = Cli::parse_from([
            "hermit",
            "verify",
            "--trust-dir",
            "/etc/hermit-keys",
            "file:///t/c.toml",
        ]);
        match cli.command {
            Command::Verify(args) => {
                assert_eq!(args.trust_dir, Some(PathBuf::from("/etc/hermit-keys")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn no_subcommand_is_error() {
        assert!(Cli::try_parse_from(["hermit"]).is_err());
    }

    #[test]
    fn parse_run_allow_unsigned() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--allow-unsigned",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert!(args.allow_unsigned);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_with_block_log() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--block-log",
            "/tmp/hermit-blocks.jsonl",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.block_log, Some(PathBuf::from("/tmp/hermit-blocks.jsonl")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_with_log_file() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--log-file",
            "/tmp/hermit.log",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.log_file, Some(PathBuf::from("/tmp/hermit.log")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_log_file_defaults_to_none() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => assert!(args.log_file.is_none()),
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_log_file_and_block_log_independent() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--block-log",
            "/tmp/blocks.jsonl",
            "--log-file",
            "/tmp/hermit.log",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert_eq!(args.log_file, Some(PathBuf::from("/tmp/hermit.log")));
                assert_eq!(args.block_log, Some(PathBuf::from("/tmp/blocks.jsonl")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_block_log_defaults_to_none() {
        // `block_log` holds only the user's explicit override — when the
        // flag is omitted it is None, and the sandbox layer substitutes
        // `$XDG_STATE_HOME/hermit/blocks.jsonl`. `no_block_log` defaults
        // to false, i.e. logging is on by default.
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert!(args.block_log.is_none());
                assert!(!args.no_block_log);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_no_block_log_sets_flag() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--no-block-log",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => {
                assert!(args.no_block_log);
                assert!(args.block_log.is_none());
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_run_block_log_and_no_block_log_conflict() {
        // Passing both is ambiguous — clap should reject it. Without
        // this guard, the opt-out flag would silently win over the
        // explicit path (or vice versa) depending on ordering.
        let err = Cli::try_parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--block-log",
            "/tmp/b.jsonl",
            "--no-block-log",
            "--",
            "true",
        ])
        .expect_err("clap must reject --block-log with --no-block-log");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be used with") || msg.contains("conflict"),
            "expected a conflict error, got: {msg}"
        );
    }

    #[test]
    fn parse_run_defaults_to_signed() {
        let cli = Cli::parse_from([
            "hermit",
            "run",
            "--config",
            "file:///x.toml",
            "--",
            "true",
        ]);
        match cli.command {
            Command::Run(args) => assert!(!args.allow_unsigned),
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_keygen_required_args() {
        let cli = Cli::parse_from([
            "hermit",
            "keygen",
            "--cert",
            "/tmp/c.pem",
            "--key",
            "/tmp/k.pem",
        ]);
        match cli.command {
            Command::Keygen(args) => {
                assert_eq!(args.cert, PathBuf::from("/tmp/c.pem"));
                assert_eq!(args.key, PathBuf::from("/tmp/k.pem"));
                assert_eq!(args.subject, "hermit-signer");
                assert!(!args.force);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_keygen_with_all_flags() {
        let cli = Cli::parse_from([
            "hermit", "keygen",
            "--cert", "/t/c.pem",
            "--key", "/t/k.pem",
            "--subject", "ci-bot",
            "--force",
        ]);
        match cli.command {
            Command::Keygen(args) => {
                assert_eq!(args.subject, "ci-bot");
                assert!(args.force);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn keygen_requires_cert_and_key() {
        assert!(Cli::try_parse_from(["hermit", "keygen"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "keygen", "--cert", "/x"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "keygen", "--key", "/x"]).is_err());
    }

    #[test]
    fn legacy_flags_are_gone() {
        // The old positional mode (`hermit -- cmd`) and flags like
        // --net, --allow must no longer parse at top level.
        assert!(Cli::try_parse_from(["hermit", "--net", "isolate", "--", "make"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "--allow", "x", "--", "make"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "--", "make"]).is_err());
    }
}
