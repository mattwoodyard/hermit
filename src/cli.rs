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
    /// with a best-effort mechanism guess (`splice` if the host's TLS
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
    /// Create an empty trust directory (default `~/.hermit/keys`).
    /// Run once on a fresh machine before `hermit verify` /
    /// `hermit run` against signed configs — those subcommands
    /// expect the directory to already exist. Idempotent: if the
    /// directory is already there, the call succeeds silently.
    Init(InitArgs),
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

    /// Enforcement mechanism: `mitm` (default), `splice`, or `bypass`.
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

    /// Maximum-detail debugging — each TCP connection gets its
    /// own tracing span (`conn=<id>`, `peer=<addr>`) and every
    /// proxy hop emits a trace event: SO_ORIGINAL_DST result,
    /// HTTP request line, host header, policy verdict, CONNECT
    /// target parse, port-allowlist check, upstream dial,
    /// body-framing mode, splice start/end. Implies `-vvv` plus
    /// `target=… path:line` in the format so a single connection
    /// can be followed end-to-end. For finer control (e.g. only
    /// `sni_proxy::forward` at trace), set `RUST_LOG`
    /// directly — that takes precedence over `--trace`.
    #[arg(long)]
    pub trace: bool,
}

#[derive(Parser, Debug)]
pub struct InitArgs {
    /// Trust directory to create. Defaults to `$HERMIT_TRUST_DIR`
    /// when set, otherwise `~/.hermit/keys`. The directory is
    /// created with mode 0700 since it holds private trust
    /// anchors — anyone who can write a `.pem` here can sign
    /// configs that `hermit run` will accept.
    #[arg(long)]
    pub trust_dir: Option<PathBuf>,
}
