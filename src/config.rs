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
use sni_proxy::policy::{AccessRule, HttpMethod};
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

/// `[[access_rule]]` entry — hostname plus optional path prefix / methods.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRuleSpec {
    pub host: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
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

    /// Adapt `[[access_rule]]` entries into sni-proxy's `AccessRule`.
    pub fn access_rules(&self) -> Result<Vec<AccessRule>> {
        self.access_rules
            .iter()
            .enumerate()
            .map(|(i, ar)| {
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
                            bail!("access_rule #{i}: empty methods list (omit the field to allow any method)");
                        }
                        Some(set)
                    }
                };
                Ok(AccessRule {
                    hostname: ar.host.to_ascii_lowercase(),
                    path_prefix: ar.path_prefix.clone(),
                    methods,
                })
            })
            .collect()
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
