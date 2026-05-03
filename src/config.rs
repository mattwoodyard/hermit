//! Unified configuration schema for hermit.
//!
//! A hermit config is a single TOML file that bundles what used to live
//! across `.hermit/home-files`, `.hermit/network-policy.toml`, and a
//! pile of CLI flags. It ends with a `[signature]` section over which
//! hermit enforces an x509-signed trust anchor.
//!
//! ```toml
//! include = ["file:///etc/hermit/shared-rules.toml"]
//!
//! [sandbox]
//! net = "isolate"
//! passthrough = ["/opt/data"]
//!
//! [[home_file]]
//! action = "pass"
//! path = "~/.ssh"
//!
//! [[access_rule]]
//! host = "api.github.com"
//! methods = ["GET"]
//!
//! [[port_forward]]
//! port = 8443
//!
//! [[rule]]
//! match = 'url.host == "api.github.com"'
//! credential = "gh"
//!
//! [credential.gh]
//! source = { type = "env", name = "GITHUB_TOKEN" }
//! inject = [{ header = "Authorization", value = "Bearer {cred}" }]
//!
//! [signature]
//! cert = "<base64 DER>"
//! signature = "<base64 bytes>"
//! algorithm = "ed25519"
//! ```
//!
//! ## Including other configs
//!
//! The top-level `include = ["<url>", ...]` field pulls in other config
//! files and merges their content into the including file. Each entry is
//! a URL using the same schemes hermit supports elsewhere (`file://` or
//! `https://`); relative URLs resolve against the including file's URL.
//!
//! Semantics:
//!
//! * Each included file is fetched, its signature verified (under the
//!   same trust policy as the root config), and parsed independently.
//! * Inclusion is recursive — an included file may itself `include =
//!   [...]`. Cycles are detected and rejected.
//! * Merge order is depth-first in declaration order: each include is
//!   fully merged *before* the including file's own entries.
//! * For arrays (`home_file`, `access_rule`, `port_forward`, `rule`):
//!   the merged list is `include_1_entries ++ include_2_entries ++ ... ++
//!   own_entries`. Evaluation semantics of downstream consumers then
//!   decide whether order matters (e.g. injection rules are first-match).
//! * For scalar fields (`sandbox.net`) and tables (`sandbox`,
//!   `credential.<name>`): the last writer wins. The including file is
//!   merged last, so it overrides anything an include provided.
//! * `[signature]` sections in included files are consumed during
//!   verification and then dropped — they don't merge.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sni_proxy::credential::Credential;
use sni_proxy::network_policy::{MatchRuleSpec, NetworkPolicy};
use sni_proxy::policy::{AccessRule, HttpMethod, IpRule};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::home_files::HomeFileDirective;

/// Whole deserialized config. Fields group by TOML section; each is
/// optional so a minimal config with just `[sandbox]` is valid.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Other config URLs to merge into this one. See module-level
    /// docs for merge semantics.
    #[serde(default)]
    pub include: Vec<String>,

    /// Tracks whether `[sandbox]` was present in the TOML. When merging,
    /// an absent sandbox block leaves the accumulator's value intact; a
    /// present block (even with default values) overwrites it field-by-field.
    /// Serialized via a custom deserializer below.
    #[serde(default, rename = "sandbox", deserialize_with = "deserialize_sandbox_opt")]
    pub sandbox_override: Option<SandboxConfig>,

    #[serde(default, rename = "home_file")]
    pub home_files: Vec<HomeFileSpec>,

    #[serde(default, rename = "access_rule")]
    pub access_rules: Vec<AccessRuleSpec>,

    /// `[dns]` section — upstream resolver configuration. Wrapped
    /// in an `Option` at the serde layer so the merge path can
    /// tell "no `[dns]` block" from "empty `[dns]` block" — the
    /// same trick `sandbox_override` uses. Without this, a file
    /// without a `[dns]` section would still deserialize to the
    /// default `DnsConfig` and clobber a previously-merged
    /// override. Use [`Config::dns()`] to get the effective value.
    #[serde(default, rename = "dns", deserialize_with = "deserialize_dns_opt")]
    pub dns_override: Option<DnsConfig>,

    /// Additional TCP ports (beyond the built-in 80/443) that the
    /// sandbox redirects into the proxy. Each entry picks which proxy
    /// handles it (plain HTTP vs. TLS/SNI).
    #[serde(default, rename = "port_forward")]
    pub port_forwards: Vec<PortForwardSpec>,

    #[serde(default, rename = "rule")]
    pub injection_rules: Vec<MatchRuleSpec>,

    #[serde(default)]
    pub credential: HashMap<String, Credential>,

    /// Present only after signing. Missing during the signing step.
    #[serde(default)]
    pub signature: Option<SignatureSection>,
}

/// Wraps `SandboxConfig` in an `Option` during deserialization so we can
/// distinguish "no `[sandbox]` block" from "empty `[sandbox]` block".
/// Only the merge path cares about this — `Config::sandbox()` collapses
/// the distinction back to a concrete `SandboxConfig`.
fn deserialize_sandbox_opt<'de, D>(deserializer: D) -> Result<Option<SandboxConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SandboxConfig::deserialize(deserializer).map(Some)
}

fn deserialize_dns_opt<'de, D>(deserializer: D) -> Result<Option<DnsConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    DnsConfig::deserialize(deserializer).map(Some)
}

impl Config {
    /// Effective `[sandbox]` values, falling back to defaults when the
    /// config (or its includes) never specified one.
    pub fn sandbox(&self) -> SandboxConfig {
        self.sandbox_override.clone().unwrap_or_default()
    }

    /// Effective `[dns]` values, falling back to the built-in
    /// default (`1.1.1.1:53`) when no config in the include chain
    /// set one.
    pub fn dns(&self) -> DnsConfig {
        self.dns_override.clone().unwrap_or_default()
    }
}

/// `[dns]` section — controls where hermit's in-namespace DNS
/// forwards allowed queries. Omitting the section entirely keeps the
/// default upstream (Cloudflare public resolver); setting `upstream`
/// points at an alternative.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// `ip:port` of the resolver to forward allowed queries to.
    /// Defaults to `1.1.1.1:53`. Must parse as a `SocketAddr`.
    #[serde(default = "default_dns_upstream")]
    pub upstream: String,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream: default_dns_upstream(),
        }
    }
}

fn default_dns_upstream() -> String {
    "1.1.1.1:53".to_string()
}

impl DnsConfig {
    /// Parse `upstream` into a `SocketAddr`. Returns an error with
    /// context when the string is malformed so the failure surface
    /// is "hermit refuses to start with a bad config" rather than a
    /// runtime panic on the first allowed DNS query.
    pub fn upstream_addr(&self) -> Result<std::net::SocketAddr> {
        self.upstream
            .parse()
            .with_context(|| format!("invalid dns.upstream {:?}", self.upstream))
    }
}

/// `[sandbox]` section.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    #[serde(default)]
    pub net: NetMode,

    #[serde(default)]
    pub passthrough: Vec<PathBuf>,
}

/// Network isolation mode (config form). Converts to [`crate::cli::NetMode`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    #[default]
    Host,
    Isolate,
}

impl NetMode {
    pub fn to_cli(self) -> crate::cli::NetMode {
        match self {
            NetMode::Host => crate::cli::NetMode::Host,
            NetMode::Isolate => crate::cli::NetMode::Isolate,
        }
    }
}

/// `[[home_file]]` entry. `action` picks among
/// copy/pass/read/hide/redirect mirroring the verbs in the
/// line-based format. `source` is required (and only meaningful)
/// when `action = "redirect"`; ignored otherwise.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeFileSpec {
    pub action: HomeFileAction,
    pub path: String,
    /// Host-side source path for `action = "redirect"`. The
    /// sandbox sees the bytes that live here at the namespace
    /// location given by `path`. Required for redirect, must
    /// be `None` for any other action (validated when the spec
    /// is converted to a [`HomeFileDirective`]).
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HomeFileAction {
    Copy,
    Pass,
    Read,
    /// Mask a path inside the sandbox. See
    /// [`crate::home_files::HomeFileDirective::Hide`] for
    /// semantics — useful for hiding a specific child of a
    /// `Pass`-mounted parent directory.
    Hide,
    /// Bind-mount a host file/dir at a different namespace
    /// path. Requires the `source` field on `HomeFileSpec`.
    Redirect,
}

/// `[[access_rule]]` entry — hostname plus optional path prefix /
/// methods / enforcement mechanism.
///
/// Either `host` or `ip` must be set (but not both): `host` is the
/// common case, `ip` is a bypass-only literal-IP entry for services
/// the sandbox reaches without a DNS query we control.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRuleSpec {
    /// Hostname this rule covers. Mutually exclusive with `ip`.
    #[serde(default)]
    pub host: Option<String>,
    /// Literal IP address this rule covers (bypass rules only).
    /// Mutually exclusive with `host`.
    #[serde(default)]
    pub ip: Option<std::net::IpAddr>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// How this rule is enforced: `mitm` (default), `splice`, or
    /// `bypass`.
    ///
    /// `splice` rules relay raw bytes after a hostname check: on
    /// the transparent path we peek the TLS SNI, on the forward
    /// path we read the `CONNECT` target. Either way no payload
    /// is inspected — `path_prefix`, `methods`, and credential
    /// injection cannot be honored on a `splice` rule. Use this
    /// for cert-pinning clients.
    ///
    /// `bypass` rules are plain-relay: the bypass listener on
    /// `(protocol, port)` accepts child traffic, `SO_ORIGINAL_DST` /
    /// `IP_RECVORIGDSTADDR` yields the real destination, the DNS
    /// cache reverse-maps the IP back to a hostname for policy, and
    /// bytes are spliced. Requires `protocol` + `port`; rejects
    /// `path_prefix` + `methods` (no plaintext visibility).
    #[serde(default)]
    pub mechanism: AccessMechanismSpec,

    /// For `mechanism = "bypass"`: which L4 protocol. Required.
    #[serde(default)]
    pub protocol: Option<BypassProtocolSpec>,

    /// For `mechanism = "bypass"`: which TCP/UDP port to relay.
    /// Required. Values 80 and 443 are reserved for the MITM/HTTP
    /// listeners and rejected.
    #[serde(default)]
    pub port: Option<u16>,
}

/// TOML surface for [`sni_proxy::policy::Mechanism`]. Kept separate
/// from the policy enum so we can evolve the user-facing string names
/// without changing the library type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMechanismSpec {
    #[default]
    Mitm,
    Splice,
    Bypass,
}

/// TOML surface for [`sni_proxy::policy::BypassProtocol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BypassProtocolSpec {
    Tcp,
    Udp,
}

impl BypassProtocolSpec {
    pub fn to_policy(self) -> sni_proxy::policy::BypassProtocol {
        match self {
            BypassProtocolSpec::Tcp => sni_proxy::policy::BypassProtocol::Tcp,
            BypassProtocolSpec::Udp => sni_proxy::policy::BypassProtocol::Udp,
        }
    }
}

/// `[[port_forward]]` entry — an extra sandboxed TCP port that the
/// proxy should intercept.
///
/// `protocol = "https"` routes traffic through the MITM/SNI proxy
/// (same listener as :443), `protocol = "http"` routes it through the
/// plain HTTP proxy (same listener as :80). The upstream connection
/// keeps the original port, so intercepting :8443 → reaches the real
/// upstream on :8443, not :443.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForwardSpec {
    pub port: u16,
    #[serde(default)]
    pub protocol: PortProtocol,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    #[default]
    Https,
    Http,
}

/// `[signature]` section — x509 cert (DER, base64) plus signature bytes.
/// Only ed25519 is accepted for now; the `algorithm` field is explicit to
/// make future rollover obvious.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSection {
    /// Base64-encoded signer cert (DER form).
    pub cert: String,
    /// Base64-encoded signature bytes over the content *before* the
    /// `[signature]` line (see `crate::signature` for exact framing).
    pub signature: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "ed25519".to_string()
}

impl Config {
    /// Parse a TOML string into a `Config`. Signature verification is
    /// handled separately by [`crate::signature`] against the raw bytes —
    /// this function only concerns itself with schema.
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("parsing hermit config TOML")?;
        config.validate_port_forwards()?;
        Ok(config)
    }

    /// Fold `other` into `self` using the include-merge rules described at
    /// the module level: arrays append (`self` comes first — i.e. `other`
    /// is treated as the "later" writer), scalar/table fields adopt
    /// `other`'s value when present, `credential` entries last-writer-wins
    /// per key, and `[signature]` is cleared (signatures don't merge).
    ///
    /// Note on array ordering: the caller controls who is "self" and who
    /// is "other". When assembling a config, the accumulator is `self`
    /// and each newly-loaded file is `other`. This yields the documented
    /// order where includes-first, own-last.
    pub fn merge_from(&mut self, other: Config) {
        // include is a compile-time directive for the loader, not runtime
        // state; there's nothing to merge.
        if let Some(sb) = other.sandbox_override {
            self.sandbox_override = Some(sb);
        }
        if let Some(d) = other.dns_override {
            self.dns_override = Some(d);
        }
        self.home_files.extend(other.home_files);
        self.access_rules.extend(other.access_rules);
        self.port_forwards.extend(other.port_forwards);
        self.injection_rules.extend(other.injection_rules);
        for (k, v) in other.credential {
            self.credential.insert(k, v);
        }
        // Signatures stay attached to the file they cover; a merged result
        // has no single signature to present.
        self.signature = None;
    }

    /// Reject port_forward entries that would shadow hermit's own
    /// loopback listeners or a reserved-for-redirect port (0).
    pub(crate) fn validate_port_forwards(&self) -> Result<()> {
        use std::collections::HashSet;
        // Ports hermit binds the internal proxy listeners on — see
        // `process::PROXY_LISTEN_PORT` / `HTTP_PROXY_LISTEN_PORT`.
        // Redirecting those would either short-circuit or loop.
        const RESERVED: &[u16] = &[1443, 1080];
        let mut seen = HashSet::new();
        for (i, pf) in self.port_forwards.iter().enumerate() {
            if pf.port == 0 {
                bail!("port_forward #{i}: port 0 is not valid");
            }
            if RESERVED.contains(&pf.port) {
                bail!(
                    "port_forward #{i}: port {} is reserved for hermit's internal proxy listeners",
                    pf.port
                );
            }
            if !seen.insert(pf.port) {
                bail!("port_forward #{i}: port {} listed twice", pf.port);
            }
        }
        Ok(())
    }

    /// Adapt `[[home_file]]` entries into the existing `HomeFileDirective`
    /// enum, expanding `~` against `home_dir` and rejecting `..`.
    pub fn home_file_directives(
        &self,
        home_dir: &Path,
    ) -> Result<Vec<HomeFileDirective>> {
        self.home_files
            .iter()
            .enumerate()
            .map(|(i, hf)| {
                let expanded = expand_tilde(&hf.path, home_dir);
                reject_dotdot(&expanded, i)?;
                // `source` validation: required-and-only-allowed
                // for redirect. Catching this at config-load time
                // surfaces the typo "I gave a source on a pass
                // directive" before any mounts happen.
                let action_label = match hf.action {
                    HomeFileAction::Copy => "copy",
                    HomeFileAction::Pass => "pass",
                    HomeFileAction::Read => "read",
                    HomeFileAction::Hide => "hide",
                    HomeFileAction::Redirect => "redirect",
                };
                match hf.action {
                    HomeFileAction::Redirect => {
                        let source = hf.source.as_deref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "[[home_file]] #{i}: action = \"redirect\" requires a `source` field"
                            )
                        })?;
                        let source_path = expand_tilde(source, home_dir);
                        Ok(HomeFileDirective::Redirect {
                            path: expanded,
                            source: source_path,
                        })
                    }
                    _ if hf.source.is_some() => Err(anyhow::anyhow!(
                        "[[home_file]] #{i}: `source` is only meaningful with action = \"redirect\" (this entry has action = {:?})",
                        action_label
                    )),
                    HomeFileAction::Copy => Ok(HomeFileDirective::Copy(expanded)),
                    HomeFileAction::Pass => Ok(HomeFileDirective::Pass(expanded)),
                    HomeFileAction::Read => Ok(HomeFileDirective::Read(expanded)),
                    HomeFileAction::Hide => Ok(HomeFileDirective::Hide(expanded)),
                }
            })
            .collect()
    }

    /// Compile `[[access_rule]]` entries into hostname-keyed
    /// [`AccessRule`]s and IP-keyed [`IpRule`]s. Validation is
    /// performed during compilation so any error surfaces at
    /// config-load time, not when the first connection tries to
    /// exercise the bad rule.
    pub fn compile_rules(&self) -> Result<(Vec<AccessRule>, Vec<IpRule>)> {
        let mut host_rules = Vec::new();
        let mut ip_rules = Vec::new();
        for (i, ar) in self.access_rules.iter().enumerate() {
            match compile_access_rule(i, ar)? {
                CompiledRule::Host(r) => host_rules.push(r),
                CompiledRule::Ip(r) => ip_rules.push(r),
            }
        }
        Ok((host_rules, ip_rules))
    }

    /// Host-keyed subset of [`compile_rules`]. Kept for callers and
    /// tests that only care about hostname rules.
    pub fn access_rules(&self) -> Result<Vec<AccessRule>> {
        Ok(self.compile_rules()?.0)
    }

    /// IP-keyed subset of [`compile_rules`].
    pub fn ip_rules(&self) -> Result<Vec<IpRule>> {
        Ok(self.compile_rules()?.1)
    }

    /// Build a `NetworkPolicy` (credential injection) from the
    /// `[[rule]]` + `[credential.*]` sections. Returns `None` when there
    /// are no injection rules, avoiding the cost of compiling an empty
    /// policy.
    pub fn network_policy(&self) -> Result<Option<NetworkPolicy>> {
        if self.injection_rules.is_empty() {
            return Ok(None);
        }
        let np = NetworkPolicy::compile(
            self.injection_rules.clone(),
            self.credential.clone(),
        )
        .context("compiling credential-injection rules")?;
        Ok(Some(np))
    }
}

/// Output of [`compile_access_rule`] — a single spec lands in
/// exactly one bucket.
enum CompiledRule {
    Host(AccessRule),
    Ip(IpRule),
}

/// Validate one `[[access_rule]]` spec and emit either a host or
/// IP rule. Most of the file's "parse don't validate" guarantees
/// live here, so every error path names the offending field.
fn compile_access_rule(i: usize, ar: &AccessRuleSpec) -> Result<CompiledRule> {
    // First: which keying was used?
    let label = match (&ar.host, &ar.ip) {
        (Some(h), None) => format!("host={h:?}"),
        (None, Some(ip)) => format!("ip={ip}"),
        (Some(_), Some(_)) => bail!(
            "access_rule #{i}: `host` and `ip` are mutually exclusive — \
             set one or the other"
        ),
        (None, None) => bail!(
            "access_rule #{i}: must set either `host = \"…\"` or `ip = \"…\"`"
        ),
    };

    // `methods` validation is cross-cutting; check it up front so
    // we can report the error with good context regardless of which
    // keying the rule uses.
    let methods = match &ar.methods {
        None => None,
        Some(list) => {
            let mut set = HashSet::new();
            for m in list {
                let method = HttpMethod::from_str(m)
                    .with_context(|| format!("access_rule #{i}: method {m:?}"))?;
                set.insert(method);
            }
            if set.is_empty() {
                bail!(
                    "access_rule #{i}: empty methods list (omit the field to allow any method)"
                );
            }
            Some(set)
        }
    };

    // Resolve + validate the mechanism. L7 narrowing (path_prefix /
    // methods) can only be enforced with plaintext visibility, so
    // accepting it on `splice` or `bypass` would silently widen the
    // allowlist. IP-keyed rules are bypass-only because mitm/splice
    // fundamentally work on hostnames.
    let mechanism = match ar.mechanism {
        AccessMechanismSpec::Mitm => {
            if ar.protocol.is_some() || ar.port.is_some() {
                bail!(
                    "access_rule #{i} ({label}): `protocol` and `port` are only \
                     meaningful with mechanism = \"bypass\""
                );
            }
            if ar.ip.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"mitm\" requires a \
                     hostname — IP-keyed rules only support bypass"
                );
            }
            sni_proxy::policy::Mechanism::Mitm
        }
        AccessMechanismSpec::Splice => {
            if ar.path_prefix.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"splice\" is \
                     incompatible with path_prefix — the splice engine relays \
                     raw bytes and never sees the HTTP path."
                );
            }
            if ar.methods.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"splice\" is \
                     incompatible with methods — the splice engine relays \
                     raw bytes and never sees the HTTP method."
                );
            }
            if ar.protocol.is_some() || ar.port.is_some() {
                bail!(
                    "access_rule #{i} ({label}): `protocol` and `port` are only \
                     meaningful with mechanism = \"bypass\""
                );
            }
            if ar.ip.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"splice\" requires a \
                     hostname — IP-keyed rules only support bypass"
                );
            }
            sni_proxy::policy::Mechanism::Splice
        }
        AccessMechanismSpec::Bypass => {
            if ar.path_prefix.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"bypass\" is \
                     incompatible with path_prefix — the bypass relay never \
                     inspects the payload."
                );
            }
            if ar.methods.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"bypass\" is \
                     incompatible with methods — the bypass relay never \
                     inspects the payload."
                );
            }
            let protocol = ar.protocol.ok_or_else(|| {
                anyhow::anyhow!(
                    "access_rule #{i} ({label}): mechanism = \"bypass\" requires \
                     `protocol = \"tcp\"` or `\"udp\"`"
                )
            })?;
            let port = ar.port.ok_or_else(|| {
                anyhow::anyhow!(
                    "access_rule #{i} ({label}): mechanism = \"bypass\" requires \
                     `port = <number>`"
                )
            })?;
            if port == 80 || port == 443 {
                bail!(
                    "access_rule #{i} ({label}): bypass port {port} is reserved \
                     for the MITM/HTTP proxy. For certificate-pinned HTTPS use \
                     mechanism = \"sni\" instead."
                );
            }
            sni_proxy::policy::Mechanism::Bypass {
                protocol: protocol.to_policy(),
                port,
            }
        }
    };

    Ok(match (&ar.host, &ar.ip) {
        (Some(h), None) => CompiledRule::Host(AccessRule {
            hostname: h.to_ascii_lowercase(),
            path_prefix: ar.path_prefix.clone(),
            methods,
            mechanism,
        }),
        (None, Some(ip)) => CompiledRule::Ip(IpRule {
            ip: *ip,
            mechanism,
        }),
        _ => unreachable!("earlier match on host/ip pair already exhaustive"),
    })
}

fn expand_tilde(raw: &str, home_dir: &Path) -> PathBuf {
    if raw == "~" {
        home_dir.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home_dir.join(rest)
    } else {
        PathBuf::from(raw)
    }
}

fn reject_dotdot(path: &Path, index: usize) -> Result<()> {
    for c in path.components() {
        if let std::path::Component::ParentDir = c {
            bail!(
                "home_file #{index} path must not contain '..': {}",
                path.display()
            );
        }
    }
    Ok(())
}

