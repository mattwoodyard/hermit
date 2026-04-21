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
    rules: Vec<CompiledRule>,
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
}

/// Apply template substitution: replace `{cred}` with the acquired value.
pub fn render_inject_value(template: &str, cred: &str) -> String {
    template.replace("{cred}", cred)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn req(method: &str, uri: &str) -> Request<()> {
        Request::builder().method(method).uri(uri).body(()).unwrap()
    }

    const SAMPLE: &str = r#"
[[rule]]
match = 'url.host == "api.github.com" && method == "GET"'
credential = "gh_token"

[[rule]]
match = 'url.host ~ ".*\.openai\.com"'
credential = "openai_key"

[credential.gh_token]
source = { type = "env", name = "GITHUB_TOKEN" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]

[credential.openai_key]
source = { type = "script", command = ["/bin/echo", "-n", "sk-abc"], ttl_secs = 60 }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#;

    #[test]
    fn loads_and_compiles() {
        let p = NetworkPolicy::from_toml(SAMPLE).unwrap();
        assert_eq!(p.rules.len(), 2);
    }

    #[test]
    fn first_match_wins() {
        let p = NetworkPolicy::from_toml(SAMPLE).unwrap();

        let r = p.resolve(&req("GET", "https://api.github.com/users")).unwrap();
        assert_eq!(r.credential, "gh_token");

        let r = p.resolve(&req("GET", "https://api.openai.com/v1")).unwrap();
        assert_eq!(r.credential, "openai_key");

        assert!(p.resolve(&req("GET", "https://example.com/")).is_none());

        // Method narrows: POST to github.com should not match the first rule
        assert!(p.resolve(&req("POST", "https://api.github.com/")).is_none());
    }

    #[test]
    fn unknown_credential_reference_is_error() {
        let toml = r#"
[[rule]]
match = 'url.host == "x"'
credential = "ghost"
"#;
        assert!(NetworkPolicy::from_toml(toml).is_err());
    }

    #[test]
    fn bad_match_expression_is_error() {
        let toml = r#"
[[rule]]
match = 'this is not valid'
credential = "k"

[credential.k]
source = { type = "env", name = "X" }
"#;
        assert!(NetworkPolicy::from_toml(toml).is_err());
    }

    #[test]
    fn template_substitution() {
        assert_eq!(render_inject_value("Bearer {cred}", "tok"), "Bearer tok");
        assert_eq!(render_inject_value("no-placeholder", "tok"), "no-placeholder");
        assert_eq!(
            render_inject_value("{cred}/{cred}", "x"),
            "x/x",
            "multiple placeholders all get replaced"
        );
    }

    #[tokio::test]
    async fn acquire_runs_source_and_returns_value() {
        let p = NetworkPolicy::from_toml(SAMPLE).unwrap();
        let rule = p
            .resolve(&req("GET", "https://api.openai.com/v1"))
            .unwrap();
        let v = p.acquire(rule, Some("api.openai.com")).await.unwrap();
        assert_eq!(v, "sk-abc");

        let actions = p.inject_actions(rule).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].header, "Authorization");
        assert_eq!(
            render_inject_value(&actions[0].value, &v),
            "Bearer sk-abc"
        );
    }

    #[test]
    fn empty_policy_matches_nothing() {
        let p = NetworkPolicy::from_toml("").unwrap();
        assert!(p.resolve(&req("GET", "https://x/")).is_none());
    }
}
