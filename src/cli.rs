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
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// URL of the signed config. `file://...` or `https://...`.
    #[arg(long)]
    pub config: String,

    /// Verbose output. `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Project directory (read-write inside the sandbox).
    #[arg(long, default_value = ".")]
    pub project_dir: PathBuf,

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
    fn legacy_flags_are_gone() {
        // The old positional mode (`hermit -- cmd`) and flags like
        // --net, --allow must no longer parse at top level.
        assert!(Cli::try_parse_from(["hermit", "--net", "isolate", "--", "make"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "--allow", "x", "--", "make"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "--", "make"]).is_err());
    }
}
