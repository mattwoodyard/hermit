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
    /// Edit an unsigned config TOML — add or remove `[[access_rule]]`
    /// entries. Any existing `[signature]` section is dropped on
    /// write because an edit invalidates the signature; re-sign with
    /// `hermit sign` afterwards.
    EditConfig(EditConfigArgs),
    /// Run a command in the sandbox in *learn* mode: nothing is
    /// blocked, every DNS query / TLS hostname / HTTP request is
    /// recorded to a JSONL trace file. Use the trace to author
    /// `[[access_rule]]` entries that match what the build
    /// actually does.
    Learn(LearnArgs),
    /// Convert a `hermit learn` JSONL trace into a hermit.toml
    /// scaffold — one `[[access_rule]]` per unique hostname,
    /// with a best-effort mechanism guess (`sni` if the host's TLS
    /// handshake never produced an HTTPS request, suggesting a
    /// cert-pinning client; `mitm` otherwise).
    LearnConvert(LearnConvertArgs),
    /// Run the proxy services (MITM, HTTP, optional DNS) in the
    /// foreground without forking a sandboxed child. Reads the
    /// same config as `hermit run` — every `[[access_rule]]` is
    /// honored — but binds the listeners on the host network
    /// directly so a client process anywhere on the host can be
    /// pointed at them via `HTTP_PROXY`/`HTTPS_PROXY`. Useful
    /// for testing the proxy in isolation, capturing traffic from
    /// an unsandboxed app, or running the proxy as a service.
    /// Bypass relays and `[[port_forward]]` entries are skipped
    /// because they require nft DNAT, which proxy mode doesn't
    /// install.
    Proxy(ProxyArgs),
}

#[derive(Parser, Debug)]
pub struct LearnConvertArgs {
    /// Path to the JSONL trace produced by `hermit learn`. Defaults
    /// to `$XDG_STATE_HOME/hermit/access.jsonl`.
    #[arg(long)]
    pub input: Option<PathBuf>,

    /// Where to write the generated TOML. Stdout when omitted, so
    /// the output can be piped through `tee` / `>>` to combine with
    /// an existing config.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// For each MITM rule, narrow with `methods = […]` listing every
    /// HTTP method observed for that host. Off by default — the
    /// resulting allowlist is broader but more forgiving.
    #[arg(long)]
    pub with_methods: bool,
}

#[derive(Parser, Debug)]
pub struct LearnArgs {
    /// URL of the config to load. Same shape as `hermit run --config`.
    /// Hostname/path/method rules in this config are *ignored*; the
    /// runtime builds an allow-all policy from it. Other sections
    /// (`[sandbox]`, `[dns]`, includes, etc.) still apply.
    ///
    /// Optional in learn mode. When omitted, hermit synthesizes a
    /// minimal config with `passthrough = ["/"]`, so the build can
    /// touch the host filesystem freely while the proxies observe
    /// network access. The intended workflow is "I have no rules
    /// yet — let me see what my build does."
    #[arg(long)]
    pub config: Option<String>,

    /// Skip signature verification on the loaded config(s).
    #[arg(long)]
    pub allow_unsigned: bool,

    /// Verbose output. `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Project directory (read-write inside the sandbox).
    #[arg(long, default_value = ".")]
    pub project_dir: PathBuf,

    /// Where to write the JSONL access trace. One line per allowed
    /// DNS query / TLS connection / HTTP request. Defaults to
    /// `$XDG_STATE_HOME/hermit/access.jsonl` (fallback
    /// `~/.local/state/hermit/access.jsonl`).
    #[arg(long)]
    pub access_log: Option<PathBuf>,

    /// Write hermit's own info/debug output to this file instead of
    /// stderr.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Command and arguments to run inside the sandbox.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct EditConfigArgs {
    #[command(subcommand)]
    pub action: EditConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum EditConfigAction {
    /// Append an `[[access_rule]]` to `<config>`. Same validation
    /// as the runtime loader, so a bad combination of flags is
    /// rejected before the file is written.
    AddRule(AddRuleArgs),
    /// Remove `[[access_rule]]` entries matching the given selector.
    RemoveRule(RemoveRuleArgs),
    /// Print a human-readable summary of the config (rules,
    /// mechanisms, DNS upstream, sandbox mode, etc.). Useful for
    /// confirming the result of add-rule / remove-rule.
    Show(ShowArgs),
}

#[derive(Parser, Debug)]
pub struct ShowArgs {
    /// Path to the TOML config. Not modified. Defaults to `hermit.toml`
    /// in the current directory.
    #[arg(default_value = "hermit.toml")]
    pub config: PathBuf,
}

#[derive(Parser, Debug)]
pub struct AddRuleArgs {
    /// Path to the TOML config. Edited in place. Defaults to
    /// `hermit.toml` in the current directory.
    #[arg(default_value = "hermit.toml")]
    pub config: PathBuf,

    /// Hostname this rule covers. Mutually exclusive with `--ip`.
    #[arg(long, conflicts_with = "ip")]
    pub host: Option<String>,

    /// Literal IP this rule covers (bypass-only). Mutually
    /// exclusive with `--host`.
    #[arg(long)]
    pub ip: Option<std::net::IpAddr>,

    /// Enforcement mechanism: `mitm` (default), `sni`, or `bypass`.
    #[arg(long, default_value = "mitm")]
    pub mechanism: String,

    /// Optional path prefix (mitm only).
    #[arg(long)]
    pub path_prefix: Option<String>,

    /// Optional comma-separated HTTP methods (mitm only).
    #[arg(long, value_delimiter = ',')]
    pub methods: Option<Vec<String>>,

    /// Protocol — `tcp` or `udp`. Required for bypass.
    #[arg(long)]
    pub protocol: Option<String>,

    /// Port. Required for bypass. Reserved values 80/443 are
    /// rejected.
    #[arg(long)]
    pub port: Option<u16>,
}

#[derive(Parser, Debug)]
pub struct RemoveRuleArgs {
    /// Path to the TOML config. Edited in place. Defaults to
    /// `hermit.toml` in the current directory.
    #[arg(default_value = "hermit.toml")]
    pub config: PathBuf,

    /// Match rules with this hostname.
    #[arg(long, conflicts_with = "ip")]
    pub host: Option<String>,

    /// Match rules with this literal IP.
    #[arg(long)]
    pub ip: Option<std::net::IpAddr>,

    /// When multiple rules match the selector, remove all of them.
    /// Without this flag, matching more than one entry is an error
    /// (safer default — ambiguity usually means the selector was
    /// too broad).
    #[arg(long)]
    pub all_matching: bool,
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
    /// Defaults to `~/.hermit/signer.cert.pem` (the path written by
    /// `hermit keygen` with default flags).
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Path to the signer's PKCS8 ed25519 private key in PEM form.
    /// Defaults to `~/.hermit/signer.key.pem` (the path written by
    /// `hermit keygen` with default flags).
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Config file to sign (must not already have a `[signature]`
    /// section). Defaults to `hermit.toml` in the current directory.
    #[arg(default_value = "hermit.toml")]
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
    /// Defaults to `~/.hermit/signer.cert.pem` (parent directory
    /// is created on demand).
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Write the PKCS8 ed25519 private key here (PEM). The file is
    /// created with mode 0600. Defaults to `~/.hermit/signer.key.pem`
    /// (parent directory is created on demand).
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Subject common name for the generated cert.
    #[arg(long, default_value = "hermit-signer")]
    pub subject: String,

    /// Overwrite `--cert` / `--key` if they already exist.
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Debug)]
pub struct ProxyArgs {
    /// URL of the config to load. Same shape as `hermit run --config`.
    /// Every `[[access_rule]]` is enforced (or observed when
    /// `--permit-all` is set). Bypass / port_forward entries are
    /// silently skipped — they only function with the nft DNAT
    /// proxy mode does not install.
    #[arg(long)]
    pub config: String,

    /// Skip signature verification on the loaded config(s).
    #[arg(long)]
    pub allow_unsigned: bool,

    /// Address the MITM proxy should listen on. Point clients at
    /// this address as their `HTTPS_PROXY` (proxy mode handles
    /// the CONNECT tunnel via the HTTP listener — see
    /// `--listen-http` below — but the MITM listener is also
    /// reachable for transparent flows when the operator wires
    /// up DNAT externally).
    #[arg(long, default_value = "127.0.0.1:1443")]
    pub listen_https: String,

    /// Address the HTTP proxy should listen on. Set the client's
    /// `HTTP_PROXY` and `HTTPS_PROXY` to `http://<addr>` to route
    /// traffic through hermit.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub listen_http: String,

    /// Optional UDP address for the DNS server. When set, hermit
    /// runs a DNS server that filters allowed hostnames and
    /// forwards to the upstream resolver in `[dns]`. Most
    /// `HTTP_PROXY` clients don't need this — the proxy receives
    /// the hostname directly via CONNECT — so it's off by default.
    #[arg(long)]
    pub listen_dns: Option<String>,

    /// Write the ephemeral CA certificate (PEM) here so the
    /// client can be configured to trust it. Without this the
    /// PEM is printed to stdout at startup so it can be piped to
    /// a file or to the system trust store.
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    /// Disable the rule check — every host is allowed and every
    /// access is recorded to the access log. Mirrors the
    /// observation behavior of `hermit learn`, but for an
    /// arbitrary client driven through `HTTP_PROXY`.
    #[arg(long)]
    pub permit_all: bool,

    /// Append JSON-lines block events to this file. Defaults to
    /// `$XDG_STATE_HOME/hermit/blocks.jsonl`. Pass `--no-block-log`
    /// to disable.
    #[arg(long, conflicts_with = "no_block_log")]
    pub block_log: Option<PathBuf>,

    /// Disable block-event logging entirely.
    #[arg(long)]
    pub no_block_log: bool,

    /// Where to write `tcp_observe`/allow events. Useful with
    /// `--permit-all` to capture a learn-style trace from a
    /// client that points at the proxy.
    #[arg(long)]
    pub access_log: Option<PathBuf>,

    /// Write hermit's own info/warn/debug output to this file
    /// instead of stderr.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Verbose output. `-v` info, `-vv` debug, `-vvv` trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
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
                assert_eq!(args.cert, Some(PathBuf::from("/tmp/cert.pem")));
                assert_eq!(args.key, Some(PathBuf::from("/tmp/key.pem")));
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
    fn parse_sign_uses_defaults_when_flags_omitted() {
        // No --cert, --key, or positional config: clap should accept
        // the call so the runtime can substitute the default paths.
        let cli = Cli::parse_from(["hermit", "sign"]);
        match cli.command {
            Command::Sign(args) => {
                assert!(args.cert.is_none());
                assert!(args.key.is_none());
                assert_eq!(args.config, PathBuf::from("hermit.toml"));
                assert!(args.output.is_none());
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
    fn parse_keygen_with_explicit_paths() {
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
                assert_eq!(args.cert, Some(PathBuf::from("/tmp/c.pem")));
                assert_eq!(args.key, Some(PathBuf::from("/tmp/k.pem")));
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
    fn parse_keygen_uses_defaults_when_flags_omitted() {
        // `hermit keygen` with no flags now succeeds; both --cert and
        // --key fall back to ~/.hermit/signer.{cert,key}.pem at
        // runtime.
        let cli = Cli::parse_from(["hermit", "keygen"]);
        match cli.command {
            Command::Keygen(args) => {
                assert!(args.cert.is_none());
                assert!(args.key.is_none());
                assert_eq!(args.subject, "hermit-signer");
                assert!(!args.force);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_keygen_partial_flags_are_independent() {
        // Either flag on its own is legal — the missing one falls
        // back to its default.
        let cli = Cli::parse_from(["hermit", "keygen", "--cert", "/x"]);
        match cli.command {
            Command::Keygen(args) => {
                assert_eq!(args.cert, Some(PathBuf::from("/x")));
                assert!(args.key.is_none());
            }
            _ => panic!("wrong subcommand"),
        }
        let cli = Cli::parse_from(["hermit", "keygen", "--key", "/x"]);
        match cli.command {
            Command::Keygen(args) => {
                assert!(args.cert.is_none());
                assert_eq!(args.key, Some(PathBuf::from("/x")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_learn_with_config() {
        let cli = Cli::parse_from([
            "hermit",
            "learn",
            "--config",
            "file:///tmp/wip.toml",
            "--",
            "make",
        ]);
        match cli.command {
            Command::Learn(args) => {
                assert_eq!(args.config.as_deref(), Some("file:///tmp/wip.toml"));
                assert_eq!(args.command, vec!["make"]);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_learn_without_config() {
        // The whole point of making --config optional: a fresh
        // user with no rules yet should be able to invoke learn
        // and have hermit synthesize a passthrough config.
        let cli = Cli::parse_from(["hermit", "learn", "--", "make"]);
        match cli.command {
            Command::Learn(args) => {
                assert!(args.config.is_none());
                assert_eq!(args.command, vec!["make"]);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn learn_requires_command() {
        assert!(Cli::try_parse_from(["hermit", "learn"]).is_err());
    }

    #[test]
    fn legacy_flags_are_gone() {
        // The old positional mode (`hermit -- cmd`) and flags like
        // --net, --allow must no longer parse at top level.
        assert!(Cli::try_parse_from(["hermit", "--net", "isolate", "--", "make"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "--allow", "x", "--", "make"]).is_err());
        assert!(Cli::try_parse_from(["hermit", "--", "make"]).is_err());
    }

    #[test]
    fn parse_edit_config_show_defaults_to_local_hermit_toml() {
        // edit-config show / add-rule / remove-rule: the positional
        // <CONFIG> defaults to `hermit.toml` so the common case
        // (operating on the project's config) needs no argument.
        let cli = Cli::parse_from(["hermit", "edit-config", "show"]);
        match cli.command {
            Command::EditConfig(EditConfigArgs {
                action: EditConfigAction::Show(args),
            }) => assert_eq!(args.config, PathBuf::from("hermit.toml")),
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_edit_config_add_rule_defaults_config_path() {
        let cli = Cli::parse_from(["hermit", "edit-config", "add-rule", "--host", "x.example"]);
        match cli.command {
            Command::EditConfig(EditConfigArgs {
                action: EditConfigAction::AddRule(args),
            }) => {
                assert_eq!(args.config, PathBuf::from("hermit.toml"));
                assert_eq!(args.host.as_deref(), Some("x.example"));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_edit_config_remove_rule_defaults_config_path() {
        let cli =
            Cli::parse_from(["hermit", "edit-config", "remove-rule", "--host", "x.example"]);
        match cli.command {
            Command::EditConfig(EditConfigArgs {
                action: EditConfigAction::RemoveRule(args),
            }) => {
                assert_eq!(args.config, PathBuf::from("hermit.toml"));
                assert_eq!(args.host.as_deref(), Some("x.example"));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_proxy_minimal_uses_defaults() {
        let cli = Cli::parse_from([
            "hermit", "proxy", "--config", "file:///tmp/hermit.toml",
        ]);
        match cli.command {
            Command::Proxy(args) => {
                assert_eq!(args.config, "file:///tmp/hermit.toml");
                assert_eq!(args.listen_https, "127.0.0.1:1443");
                assert_eq!(args.listen_http, "127.0.0.1:1080");
                assert!(args.listen_dns.is_none());
                assert!(args.ca_cert.is_none());
                assert!(!args.permit_all);
                assert!(!args.allow_unsigned);
                assert!(!args.no_block_log);
                assert!(args.block_log.is_none());
                assert!(args.access_log.is_none());
                assert!(args.log_file.is_none());
                assert_eq!(args.verbose, 0);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_proxy_requires_config() {
        // Same shape as `run`: no positional fallback, --config
        // is the only way to point at a TOML.
        assert!(Cli::try_parse_from(["hermit", "proxy"]).is_err());
    }

    #[test]
    fn parse_proxy_with_all_flags() {
        let cli = Cli::parse_from([
            "hermit", "proxy",
            "--config", "https://example.com/h.toml",
            "--allow-unsigned",
            "--listen-https", "0.0.0.0:1443",
            "--listen-http", "0.0.0.0:1080",
            "--listen-dns", "127.0.0.1:5353",
            "--ca-cert", "/tmp/ca.pem",
            "--permit-all",
            "--access-log", "/tmp/access.jsonl",
            "--log-file", "/tmp/proxy.log",
            "-vv",
        ]);
        match cli.command {
            Command::Proxy(args) => {
                assert_eq!(args.config, "https://example.com/h.toml");
                assert!(args.allow_unsigned);
                assert_eq!(args.listen_https, "0.0.0.0:1443");
                assert_eq!(args.listen_http, "0.0.0.0:1080");
                assert_eq!(args.listen_dns.as_deref(), Some("127.0.0.1:5353"));
                assert_eq!(args.ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
                assert!(args.permit_all);
                assert_eq!(args.access_log, Some(PathBuf::from("/tmp/access.jsonl")));
                assert_eq!(args.log_file, Some(PathBuf::from("/tmp/proxy.log")));
                assert_eq!(args.verbose, 2);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parse_proxy_block_log_no_block_log_conflict() {
        // Same belt-and-suspenders rule as `run`: passing both
        // is ambiguous so clap rejects it up front.
        let err = Cli::try_parse_from([
            "hermit", "proxy",
            "--config", "file:///x.toml",
            "--block-log", "/tmp/b.jsonl",
            "--no-block-log",
        ])
        .expect_err("clap must reject --block-log with --no-block-log");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be used with") || msg.contains("conflict"),
            "expected a conflict error, got: {msg}"
        );
    }
}
