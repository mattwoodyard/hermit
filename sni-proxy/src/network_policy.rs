//! Network policy: load rules and credentials from `.hermit/network-policy.toml`,
//! compile match expressions, and resolve a request to its injection actions.
//!
//! The TOML shape is:
//! ```toml
//! [[rule]]
//! match = 'url.host == "api.github.com"'
//! credential = "gh_token"
//!
//! [credential.gh_token]
//! source = { type = "env", name = "GITHUB_TOKEN" }
//! inject = [{ header = "Authorization", value = "Bearer {cred}" }]
//! ```

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::credential::{Credential, CredentialResolver, InjectAction};
use crate::match_dsl::Expr;

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rule: Vec<MatchRuleSpec>,
    #[serde(default)]
    credential: HashMap<String, Credential>,
}

/// Serde-shape of a single `[[rule]]` entry: a DSL match expression and
/// the name of the credential to inject when it fires. Exposed so callers
/// that already have these values parsed (e.g. from a larger config file)
/// can build a `NetworkPolicy` without re-serializing.
#[derive(Debug, Clone, Deserialize)]
pub struct MatchRuleSpec {
    pub r#match: String,
    pub credential: String,
}

pub struct CompiledRule {
    expr: Expr,
    pub credential: String,
}

pub struct NetworkPolicy {
    pub(crate) rules: Vec<CompiledRule>,
    resolver: CredentialResolver,
}

impl NetworkPolicy {
    /// Load and compile a policy from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading network policy {path:?}"))?;
        Self::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let parsed: PolicyFile =
            toml::from_str(text).context("parsing network policy TOML")?;
        Self::compile(parsed.rule, parsed.credential)
    }

    /// Build a policy from already-deserialized rule specs and credentials.
    /// Use this when the rules/credentials live inside a larger config
    /// document (see hermit::config).
    pub fn compile(
        rule_specs: Vec<MatchRuleSpec>,
        credentials: HashMap<String, Credential>,
    ) -> Result<Self> {
        let mut rules = Vec::with_capacity(rule_specs.len());
        for (i, r) in rule_specs.into_iter().enumerate() {
            if !credentials.contains_key(&r.credential) {
                return Err(anyhow!(
                    "rule #{i} references unknown credential {:?}",
                    r.credential
                ));
            }
            let expr = Expr::compile(&r.r#match)
                .with_context(|| format!("compiling match for rule #{i}"))?;
            rules.push(CompiledRule {
                expr,
                credential: r.credential,
            });
        }

        Ok(Self {
            rules,
            resolver: CredentialResolver::new(credentials),
        })
    }

    /// Return the first matching rule (if any) for a request.
    pub fn resolve(&self, req: &http::Request<()>) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.expr.eval(req))
    }

    /// Return injection actions for a rule's credential (the declared list).
    pub fn inject_actions(&self, rule: &CompiledRule) -> Option<&[InjectAction]> {
        self.resolver.get_credential(&rule.credential).map(|c| c.inject.as_slice())
    }

    /// Acquire the credential value for a rule. Runs the script (or reads
    /// env/file) and returns the caller-ready value.
    pub async fn acquire(&self, rule: &CompiledRule, match_host: Option<&str>) -> Result<String> {
        self.resolver.resolve(&rule.credential, match_host).await
    }

    /// Drop the cached value for the named credential so the
    /// next [`acquire`](Self::acquire) re-runs the source.
    /// Used by the MITM engine on a 401 from upstream — the
    /// next request gets a fresh access token instead of
    /// replaying the stale one.
    pub fn invalidate(&self, name: &str) {
        self.resolver.invalidate(name);
    }
}

/// Apply template substitution: replace `{cred}` with the acquired value.
pub fn render_inject_value(template: &str, cred: &str) -> String {
    template.replace("{cred}", cred)
}

/// Wrappers around `network_policy`'s private items for the
/// dedicated test crate.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    pub fn rule_count(p: &super::NetworkPolicy) -> usize {
        p.rules.len()
    }
}
