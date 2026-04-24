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

    /// `[dns]` section — upstream resolver configuration. Absent
    /// means use the built-in default (Cloudflare's 1.1.1.1:53).
    #[serde(default)]
    pub dns: DnsConfig,

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

impl Config {
    /// Effective `[sandbox]` values, falling back to defaults when the
    /// config (or its includes) never specified one.
    pub fn sandbox(&self) -> SandboxConfig {
        self.sandbox_override.clone().unwrap_or_default()
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

/// `[[home_file]]` entry. `action` picks among copy/pass/read mirroring
/// the verbs in the old line-based format.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeFileSpec {
    pub action: HomeFileAction,
    pub path: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HomeFileAction {
    Copy,
    Pass,
    Read,
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
    /// How this rule is enforced: `mitm` (default), `sni`, or
    /// `bypass`.
    ///
    /// `sni` rules are cut-through: we look up the TLS SNI, match
    /// against policy, and from there splice bytes without inspecting
    /// them. `path_prefix`, `methods`, and credential injection cannot
    /// be honored on an `sni` rule.
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
/// (e.g. alias `sni-passthrough` → `Sni`) without changing the
/// library type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMechanismSpec {
    #[default]
    Mitm,
    Sni,
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
                Ok(match hf.action {
                    HomeFileAction::Copy => HomeFileDirective::Copy(expanded),
                    HomeFileAction::Pass => HomeFileDirective::Pass(expanded),
                    HomeFileAction::Read => HomeFileDirective::Read(expanded),
                })
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
    // accepting it on `sni` or `bypass` would silently widen the
    // allowlist. IP-keyed rules are bypass-only because MITM/SNI
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
        AccessMechanismSpec::Sni => {
            if ar.path_prefix.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"sni\" is \
                     incompatible with path_prefix — the SNI cut-through proxy \
                     never sees the HTTP path."
                );
            }
            if ar.methods.is_some() {
                bail!(
                    "access_rule #{i} ({label}): mechanism = \"sni\" is \
                     incompatible with methods — the SNI cut-through proxy \
                     never sees the HTTP method."
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
                    "access_rule #{i} ({label}): mechanism = \"sni\" requires a \
                     hostname — IP-keyed rules only support bypass"
                );
            }
            sni_proxy::policy::Mechanism::Sni
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

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[sandbox]
net = "isolate"
passthrough = ["/opt/extra"]

[[home_file]]
action = "pass"
path = "~/.ssh"

[[home_file]]
action = "copy"
path = "~/.gitconfig"

[[access_rule]]
host = "registry.npmjs.org"

[[access_rule]]
host = "api.github.com"
path_prefix = "/repos/"
methods = ["GET", "POST"]

[[rule]]
match = 'url.host == "api.github.com"'
credential = "gh"

[credential.gh]
source = { type = "env", name = "GITHUB_TOKEN" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]

[signature]
cert = "BASE64_CERT"
signature = "BASE64_SIG"
algorithm = "ed25519"
"#;

    #[test]
    fn parses_full_example() {
        let c = Config::parse(FULL).unwrap();
        let sb = c.sandbox();
        assert_eq!(sb.net, NetMode::Isolate);
        assert_eq!(sb.passthrough, vec![PathBuf::from("/opt/extra")]);
        assert_eq!(c.home_files.len(), 2);
        assert_eq!(c.access_rules.len(), 2);
        assert_eq!(c.injection_rules.len(), 1);
        assert_eq!(c.credential.len(), 1);
        let sig = c.signature.as_ref().unwrap();
        assert_eq!(sig.algorithm, "ed25519");
    }

    #[test]
    fn home_files_adapt_and_expand_tilde() {
        let c = Config::parse(FULL).unwrap();
        let dirs = c.home_file_directives(Path::new("/home/u")).unwrap();
        assert_eq!(
            dirs,
            vec![
                HomeFileDirective::Pass(PathBuf::from("/home/u/.ssh")),
                HomeFileDirective::Copy(PathBuf::from("/home/u/.gitconfig")),
            ]
        );
    }

    #[test]
    fn home_files_reject_dotdot() {
        let toml = r#"
[[home_file]]
action = "pass"
path = "../escape"
"#;
        let c = Config::parse(toml).unwrap();
        assert!(c.home_file_directives(Path::new("/home/u")).is_err());
    }

    #[test]
    fn access_rules_adapt_with_methods() {
        let c = Config::parse(FULL).unwrap();
        let rules = c.access_rules().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].hostname, "registry.npmjs.org");
        assert!(rules[0].methods.is_none());
        assert_eq!(rules[1].hostname, "api.github.com");
        assert_eq!(rules[1].path_prefix.as_deref(), Some("/repos/"));
        assert_eq!(rules[1].methods.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn access_rule_unknown_method_is_error() {
        let toml = r#"
[[access_rule]]
host = "x"
methods = ["BOGUS"]
"#;
        let c = Config::parse(toml).unwrap();
        assert!(c.access_rules().is_err());
    }

    #[test]
    fn access_rule_default_mechanism_is_mitm() {
        let toml = r#"
[[access_rule]]
host = "x"
"#;
        let c = Config::parse(toml).unwrap();
        let rules = c.access_rules().unwrap();
        assert_eq!(rules[0].mechanism, sni_proxy::policy::Mechanism::Mitm);
    }

    #[test]
    fn access_rule_sni_mechanism_parses() {
        let toml = r#"
[[access_rule]]
host = "pinned.example"
mechanism = "sni"
"#;
        let c = Config::parse(toml).unwrap();
        let rules = c.access_rules().unwrap();
        assert_eq!(rules[0].mechanism, sni_proxy::policy::Mechanism::Sni);
    }

    #[test]
    fn access_rule_sni_with_path_prefix_is_error() {
        // An `sni` rule splices without inspecting HTTP — silently
        // ignoring `path_prefix` would widen the allowlist, so parse
        // must reject it. The error must name the offending field.
        let toml = r#"
[[access_rule]]
host = "pinned.example"
mechanism = "sni"
path_prefix = "/api/"
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.access_rules().expect_err("sni + path_prefix must fail");
        assert!(err.to_string().contains("path_prefix"),
            "error must mention path_prefix, got: {err}");
    }

    #[test]
    fn access_rule_sni_with_methods_is_error() {
        let toml = r#"
[[access_rule]]
host = "pinned.example"
mechanism = "sni"
methods = ["GET"]
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.access_rules().expect_err("sni + methods must fail");
        assert!(err.to_string().contains("methods"),
            "error must mention methods, got: {err}");
    }

    #[test]
    fn access_rule_unknown_mechanism_is_error() {
        // Guards against typos like `mechanism = "snipassthrough"`
        // silently falling back to the default.
        let toml = r#"
[[access_rule]]
host = "x"
mechanism = "bogus"
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn access_rule_bypass_parses_tcp_and_udp() {
        let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
port = 88

[[access_rule]]
host = "ldap.example"
mechanism = "bypass"
protocol = "tcp"
port = 389
"#;
        let c = Config::parse(toml).unwrap();
        let rules = c.access_rules().unwrap();
        use sni_proxy::policy::{BypassProtocol, Mechanism};
        assert_eq!(
            rules[0].mechanism,
            Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 }
        );
        assert_eq!(
            rules[1].mechanism,
            Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 389 }
        );
    }

    #[test]
    fn access_rule_bypass_requires_protocol() {
        let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
port = 88
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.access_rules().unwrap_err().to_string();
        assert!(err.contains("protocol"), "error should name `protocol`: {err}");
    }

    #[test]
    fn access_rule_bypass_requires_port() {
        let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.access_rules().unwrap_err().to_string();
        assert!(err.contains("port"), "error should name `port`: {err}");
    }

    #[test]
    fn access_rule_bypass_rejects_reserved_ports() {
        // 80 + 443 belong to the MITM/HTTP listeners — a bypass rule
        // there would silently break interception for every other
        // host on that port, so the config loader rejects it.
        for port in [80u16, 443] {
            let toml = format!(
                r#"
[[access_rule]]
host = "pinned.example"
mechanism = "bypass"
protocol = "tcp"
port = {port}
"#
            );
            let c = Config::parse(&toml).unwrap();
            let err = c.access_rules().unwrap_err().to_string();
            assert!(
                err.contains("reserved"),
                "port {port} should be rejected as reserved, got: {err}"
            );
        }
    }

    #[test]
    fn access_rule_bypass_rejects_path_prefix_and_methods() {
        let toml_path = r#"
[[access_rule]]
host = "x"
mechanism = "bypass"
protocol = "tcp"
port = 8080
path_prefix = "/api/"
"#;
        let err = Config::parse(toml_path)
            .unwrap()
            .access_rules()
            .unwrap_err()
            .to_string();
        assert!(err.contains("path_prefix"));

        let toml_methods = r#"
[[access_rule]]
host = "x"
mechanism = "bypass"
protocol = "tcp"
port = 8080
methods = ["GET"]
"#;
        let err = Config::parse(toml_methods)
            .unwrap()
            .access_rules()
            .unwrap_err()
            .to_string();
        assert!(err.contains("methods"));
    }

    #[test]
    fn access_rule_ip_bypass_parses() {
        let toml = r#"
[[access_rule]]
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
        let c = Config::parse(toml).unwrap();
        let (host_rules, ip_rules) = c.compile_rules().unwrap();
        assert!(host_rules.is_empty());
        assert_eq!(ip_rules.len(), 1);
        assert_eq!(ip_rules[0].ip, "10.0.0.5".parse::<std::net::IpAddr>().unwrap());
        use sni_proxy::policy::{BypassProtocol, Mechanism};
        assert_eq!(
            ip_rules[0].mechanism,
            Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 }
        );
    }

    #[test]
    fn access_rule_requires_host_or_ip() {
        let toml = r#"
[[access_rule]]
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.compile_rules().unwrap_err().to_string();
        assert!(err.contains("must set either `host`") || err.contains("must set either"));
    }

    #[test]
    fn access_rule_host_and_ip_are_mutually_exclusive() {
        let toml = r#"
[[access_rule]]
host = "x.example"
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.compile_rules().unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn access_rule_ip_rejects_mitm_mechanism() {
        let toml = r#"
[[access_rule]]
ip = "10.0.0.5"
mechanism = "mitm"
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.compile_rules().unwrap_err().to_string();
        assert!(err.contains("mitm"));
    }

    #[test]
    fn access_rule_ip_rejects_sni_mechanism() {
        let toml = r#"
[[access_rule]]
ip = "10.0.0.5"
mechanism = "sni"
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.compile_rules().unwrap_err().to_string();
        assert!(err.contains("sni"));
    }

    #[test]
    fn access_rule_mixed_host_and_ip_configs_both_compile() {
        let toml = r#"
[[access_rule]]
host = "kdc.example"
mechanism = "bypass"
protocol = "udp"
port = 88

[[access_rule]]
ip = "10.0.0.5"
mechanism = "bypass"
protocol = "udp"
port = 88
"#;
        let c = Config::parse(toml).unwrap();
        let (host_rules, ip_rules) = c.compile_rules().unwrap();
        assert_eq!(host_rules.len(), 1);
        assert_eq!(ip_rules.len(), 1);
    }

    #[test]
    fn access_rule_protocol_port_require_bypass_mechanism() {
        // If someone accidentally drops `mechanism = "bypass"` but
        // leaves the protocol/port fields, they clearly meant bypass
        // — surfacing the error tells them to add it rather than
        // silently promoting the rule to a MITM rule that ignores
        // both fields.
        let toml = r#"
[[access_rule]]
host = "x"
protocol = "tcp"
port = 8080
"#;
        let c = Config::parse(toml).unwrap();
        let err = c.access_rules().unwrap_err().to_string();
        assert!(err.contains("bypass"));
    }

    #[test]
    fn dns_default_upstream_is_cloudflare() {
        // Matches the documented default — don't silently move users
        // off it. If you change the default, also change this test
        // plus the doc string on `default_dns_upstream`.
        let c = Config::parse("").unwrap();
        assert_eq!(c.dns.upstream, "1.1.1.1:53");
        let addr = c.dns.upstream_addr().unwrap();
        assert_eq!(addr.port(), 53);
    }

    #[test]
    fn dns_upstream_override_parses() {
        let toml = r#"
[dns]
upstream = "8.8.8.8:53"
"#;
        let c = Config::parse(toml).unwrap();
        assert_eq!(c.dns.upstream, "8.8.8.8:53");
        assert!(c.dns.upstream_addr().is_ok());
    }

    #[test]
    fn dns_upstream_malformed_addr_is_error_at_load_time() {
        // We don't want a bad `upstream` value to fail on the first
        // DNS query — catch it at config parse so the user sees the
        // problem before any work is done.
        let toml = r#"
[dns]
upstream = "not-an-address"
"#;
        let c = Config::parse(toml).unwrap();
        assert!(c.dns.upstream_addr().is_err());
    }

    #[test]
    fn dns_unknown_field_is_rejected() {
        // Guard against typos in the `[dns]` section being silently
        // ignored — `deny_unknown_fields` on `DnsConfig` enforces
        // this but a test pins the behavior.
        let toml = r#"
[dns]
upstream = "1.1.1.1:53"
servers = ["8.8.8.8:53"]
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn access_rule_empty_methods_list_is_error() {
        let toml = r#"
[[access_rule]]
host = "x"
methods = []
"#;
        let c = Config::parse(toml).unwrap();
        assert!(c.access_rules().is_err());
    }

    #[test]
    fn network_policy_present_when_rules_exist() {
        let c = Config::parse(FULL).unwrap();
        assert!(c.network_policy().unwrap().is_some());
    }

    #[test]
    fn network_policy_absent_when_no_rules() {
        let c = Config::parse("[sandbox]\nnet = \"host\"").unwrap();
        assert!(c.network_policy().unwrap().is_none());
    }

    #[test]
    fn network_policy_rule_refers_unknown_credential_errors() {
        let toml = r#"
[[rule]]
match = 'url.host == "x"'
credential = "ghost"
"#;
        let c = Config::parse(toml).unwrap();
        assert!(c.network_policy().is_err());
    }

    #[test]
    fn minimal_config_parses() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.sandbox().net, NetMode::Host);
        assert!(c.home_files.is_empty());
        assert!(c.access_rules.is_empty());
        assert!(c.signature.is_none());
    }

    #[test]
    fn unknown_top_level_field_is_error() {
        let toml = r#"
[sandbox]
net = "host"

[what_is_this]
nope = true
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn unknown_sandbox_field_is_error() {
        let toml = r#"
[sandbox]
net = "host"
rogue_field = 1
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn net_mode_conversion() {
        assert_eq!(NetMode::Host.to_cli(), crate::cli::NetMode::Host);
        assert_eq!(NetMode::Isolate.to_cli(), crate::cli::NetMode::Isolate);
    }

    #[test]
    fn port_forward_parses_defaults_to_https() {
        let toml = r#"
[[port_forward]]
port = 8443
"#;
        let c = Config::parse(toml).unwrap();
        assert_eq!(c.port_forwards.len(), 1);
        assert_eq!(c.port_forwards[0].port, 8443);
        assert_eq!(c.port_forwards[0].protocol, PortProtocol::Https);
    }

    #[test]
    fn port_forward_parses_http() {
        let toml = r#"
[[port_forward]]
port = 8080
protocol = "http"
"#;
        let c = Config::parse(toml).unwrap();
        assert_eq!(c.port_forwards[0].protocol, PortProtocol::Http);
    }

    #[test]
    fn port_forward_rejects_reserved() {
        for p in [1443, 1080] {
            let toml = format!("[[port_forward]]\nport = {}\n", p);
            let err = Config::parse(&toml).unwrap_err().to_string();
            assert!(err.contains("reserved"), "got: {err}");
        }
    }

    #[test]
    fn port_forward_rejects_duplicate() {
        let toml = r#"
[[port_forward]]
port = 8443
[[port_forward]]
port = 8443
protocol = "http"
"#;
        let err = Config::parse(toml).unwrap_err().to_string();
        assert!(err.contains("listed twice"), "got: {err}");
    }

    #[test]
    fn port_forward_rejects_zero() {
        let toml = r#"
[[port_forward]]
port = 0
"#;
        let err = Config::parse(toml).unwrap_err().to_string();
        assert!(err.contains("not valid"), "got: {err}");
    }

    #[test]
    fn port_forward_rejects_unknown_protocol() {
        let toml = r#"
[[port_forward]]
port = 9000
protocol = "quic"
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn include_field_parses_as_empty_by_default() {
        let c = Config::parse("").unwrap();
        assert!(c.include.is_empty());
    }

    #[test]
    fn include_field_parses_urls() {
        let c = Config::parse(r#"include = ["file:///a.toml", "file:///b.toml"]"#).unwrap();
        assert_eq!(c.include.len(), 2);
        assert_eq!(c.include[0], "file:///a.toml");
    }

    #[test]
    fn merge_appends_arrays_other_last() {
        // Base config has one rule; `other` adds another. Since the
        // include protocol treats the including file as "other" (merged
        // last), the including file's entries land after the included
        // file's entries when the caller sets up `self = includes_merged`.
        let mut a = Config::parse(r#"[[access_rule]]
host = "a.com""#).unwrap();
        let b = Config::parse(r#"[[access_rule]]
host = "b.com""#).unwrap();
        a.merge_from(b);
        let rules = a.access_rules().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].hostname, "a.com");
        assert_eq!(rules[1].hostname, "b.com");
    }

    #[test]
    fn merge_sandbox_other_overrides_when_present() {
        let mut a = Config::parse(r#"[sandbox]
net = "host""#).unwrap();
        let b = Config::parse(r#"[sandbox]
net = "isolate""#).unwrap();
        a.merge_from(b);
        assert_eq!(a.sandbox().net, NetMode::Isolate);
    }

    #[test]
    fn merge_sandbox_absent_in_other_preserves_self() {
        let mut a = Config::parse(r#"[sandbox]
net = "isolate""#).unwrap();
        let b = Config::parse("").unwrap();
        a.merge_from(b);
        assert_eq!(a.sandbox().net, NetMode::Isolate);
    }

    #[test]
    fn merge_credential_last_writer_wins_per_key() {
        let mut a = Config::parse(r#"
[credential.gh]
source = { type = "env", name = "FIRST" }
inject = [{ header = "X-Tok", value = "{cred}" }]
"#).unwrap();
        let b = Config::parse(r#"
[credential.gh]
source = { type = "env", name = "SECOND" }
inject = [{ header = "X-Tok", value = "{cred}" }]
"#).unwrap();
        a.merge_from(b);
        // `other` wins for same key — inspect via serde round-trip of the
        // underlying Credential (no public accessor, so use Debug).
        let dbg = format!("{:?}", a.credential.get("gh").unwrap());
        assert!(dbg.contains("SECOND"), "expected SECOND to win, got: {dbg}");
    }

    #[test]
    fn merge_clears_signature() {
        let mut a = Config::parse(r#"
[signature]
cert = "AA"
signature = "BB"
algorithm = "ed25519"
"#).unwrap();
        assert!(a.signature.is_some());
        let b = Config::parse("").unwrap();
        a.merge_from(b);
        assert!(a.signature.is_none(), "signature must not survive merge");
    }

    #[test]
    fn merge_concatenates_home_files_port_forwards_and_rules() {
        let mut a = Config::parse(r#"
[[home_file]]
action = "copy"
path = "~/.bashrc"
[[port_forward]]
port = 8443
"#).unwrap();
        let b = Config::parse(r#"
[[home_file]]
action = "pass"
path = "~/.ssh"
[[port_forward]]
port = 8080
protocol = "http"
[[rule]]
match = 'url.host == "x.com"'
credential = "gh"
[credential.gh]
source = { type = "env", name = "GH" }
inject = [{ header = "A", value = "{cred}" }]
"#).unwrap();
        a.merge_from(b);
        assert_eq!(a.home_files.len(), 2);
        assert_eq!(a.port_forwards.len(), 2);
        assert_eq!(a.injection_rules.len(), 1);
        assert_eq!(a.credential.len(), 1);
    }
}
