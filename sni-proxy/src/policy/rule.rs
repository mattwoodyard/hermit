//! Per-host access rules: hostname + optional path-prefix + optional method
//! filter, plus the enforcement [`Mechanism`] (MITM / Splice / Bypass).
//!
//! Includes the path-traversal guard that catches `..` segments in both
//! literal and percent-encoded forms — without it, a rule like
//! `host/api/=GET` would be bypassed by `/api/../private`, which the
//! upstream server would normalize back outside the prefix.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use super::method::HttpMethod;

/// Verdict returned by a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

/// How a matched rule is actually enforced on the wire.
///
/// - `Mitm`: terminate TLS with the hermit CA, fully parse HTTP, apply
///   `path_prefix` / `methods`, optionally inject credentials. This is
///   the default and the only mechanism that supports L7 filtering.
/// - `Splice`: a "cut-through" splice — we read the TLS ClientHello, look
///   up the hostname against policy, and from there on shuttle bytes
///   bidirectionally without inspecting them. Incompatible with
///   `path_prefix`, `methods`, and credential injection.
/// - `Bypass { protocol, port }`: plain relay for non-HTTP protocols
///   (Kerberos UDP, LDAP, SSH, ...). The bypass relay listens on a
///   dedicated port; SO_ORIGINAL_DST / IP_RECVORIGDSTADDR gives us the
///   real destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mechanism {
    /// Full MITM with plaintext inspection.
    #[default]
    Mitm,
    /// Splice raw bytes — no TLS termination, no L7 inspection.
    /// Use this for cert-pinning clients that would reject the
    /// hermit-minted leaf.
    Splice,
    /// Transparent relay on the given (protocol, port).
    Bypass {
        protocol: BypassProtocol,
        port: u16,
    },
}

/// L4 protocol for a `Bypass` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BypassProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for BypassProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BypassProtocol::Tcp => write!(f, "tcp"),
            BypassProtocol::Udp => write!(f, "udp"),
        }
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mechanism::Mitm => write!(f, "mitm"),
            Mechanism::Splice => write!(f, "splice"),
            Mechanism::Bypass { protocol, port } => write!(f, "bypass({protocol}/{port})"),
        }
    }
}

/// A single access rule. Hostname is always required.
/// Path prefix and methods are optional narrowing filters.
#[derive(Debug, Clone)]
pub struct AccessRule {
    /// Required hostname (exact match, lowercase).
    pub hostname: String,
    /// Optional path prefix (e.g. "/api/v1/"). `None` = any path.
    pub path_prefix: Option<String>,
    /// Optional method restriction. `None` = any method.
    pub methods: Option<HashSet<HttpMethod>>,
    /// How this rule is enforced at connection time. See [`Mechanism`].
    pub mechanism: Mechanism,
}

impl AccessRule {
    /// Create a hostname-only rule (allows any path and method, MITM).
    pub fn host_only(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into().to_ascii_lowercase(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Mitm,
        }
    }

    /// Check whether this rule matches the given request.
    pub(super) fn matches(&self, hostname: &str, path: &str, method: &str) -> bool {
        if !self.hostname.eq_ignore_ascii_case(hostname) {
            return false;
        }
        if let Some(ref prefix) = self.path_prefix {
            if !path.starts_with(prefix.as_str()) {
                return false;
            }
            // `starts_with` alone is fooled by `/repos/../user/keys`,
            // which the upstream will normalize back to `/user/keys`
            // and serve outside the intended prefix.
            if path_contains_dotdot_segment(path) {
                return false;
            }
        }
        if let Some(ref allowed) = self.methods {
            match HttpMethod::from_str(method) {
                Ok(m) => {
                    if !allowed.contains(&m) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }

    /// Check whether this rule's hostname matches (for DNS/connection-level checks).
    pub(super) fn matches_host(&self, hostname: &str) -> bool {
        self.hostname.eq_ignore_ascii_case(hostname)
    }
}

/// Return true if any `/`-separated segment of `path` decodes to
/// `..`. Catches `/repos/../user`, `/repos/%2e%2e/user`, and the
/// mixed-encoding variants — all of which collapse to a path
/// outside the configured prefix once the upstream server
/// normalizes the request.
fn path_contains_dotdot_segment(path: &str) -> bool {
    let path_only = path.split(['?', '#']).next().unwrap_or(path);
    for segment in path_only.split('/') {
        if segment_is_dotdot(segment) {
            return true;
        }
    }
    false
}

fn segment_is_dotdot(seg: &str) -> bool {
    let bytes = seg.as_bytes();
    let mut i = 0;
    let mut dots = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            dots += 1;
            i += 1;
        } else if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1] == b'2'
            && (bytes[i + 2] == b'e' || bytes[i + 2] == b'E')
        {
            dots += 1;
            i += 3;
        } else {
            return false;
        }
    }
    dots == 2
}

#[derive(Debug, Clone)]
pub struct ParseRuleError(pub String);

impl fmt::Display for ParseRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid access rule: {}", self.0)
    }
}

impl std::error::Error for ParseRuleError {}

impl FromStr for AccessRule {
    type Err = ParseRuleError;

    /// Parse a rule string in the format: `hostname[/path][=METHOD,METHOD]`
    ///
    /// Examples:
    /// - `"registry.npmjs.org"` — allow all
    /// - `"registry.npmjs.org/-/npm/v1/=GET"` — GET only on that prefix
    /// - `"github.com/api/v3/=GET,POST"` — GET or POST on /api/v3/
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseRuleError("empty rule".into()));
        }

        let (host_path, methods) = match s.rsplit_once('=') {
            Some((hp, m)) => (hp, Some(m)),
            None => (s, None),
        };

        let (hostname, path_prefix) = match host_path.find('/') {
            Some(idx) => {
                let (h, p) = host_path.split_at(idx);
                (h, Some(p.to_string()))
            }
            None => (host_path, None),
        };

        if hostname.is_empty() {
            return Err(ParseRuleError("empty hostname".into()));
        }

        let methods = match methods {
            Some(m) => {
                let mut set = HashSet::new();
                for part in m.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    let method = HttpMethod::from_str(part)
                        .map_err(|e| ParseRuleError(e.to_string()))?;
                    set.insert(method);
                }
                if set.is_empty() {
                    return Err(ParseRuleError("empty method list after '='".into()));
                }
                Some(set)
            }
            None => None,
        };

        Ok(AccessRule {
            hostname: hostname.to_ascii_lowercase(),
            path_prefix,
            methods,
            mechanism: Mechanism::default(),
        })
    }
}

/// Bypass-only allowlist entry keyed by a literal IP. The MITM and
/// Splice mechanisms fundamentally operate on hostnames, so they can't
/// be expressed as IP rules — parsing rejects the combination.
///
/// The motivating case is services the sandbox reaches by IP rather
/// than via DNS: internal test fixtures, a pinned upstream given as
/// an address, or a KDC behind a round-robin where hermit's DNS
/// cache never sees the final IP.
#[derive(Debug, Clone)]
pub struct IpRule {
    pub ip: std::net::IpAddr,
    /// Always a `Bypass` variant after validation.
    pub mechanism: Mechanism,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- AccessRule parsing ---

    #[test]
    fn parse_rule_hostname_only() {
        let rule: AccessRule = "example.com".parse().unwrap();
        assert_eq!(rule.hostname, "example.com");
        assert!(rule.path_prefix.is_none());
        assert!(rule.methods.is_none());
    }

    #[test]
    fn parse_rule_with_path() {
        let rule: AccessRule = "example.com/api/v1/".parse().unwrap();
        assert_eq!(rule.hostname, "example.com");
        assert_eq!(rule.path_prefix.as_deref(), Some("/api/v1/"));
        assert!(rule.methods.is_none());
    }

    #[test]
    fn parse_rule_with_path_and_methods() {
        let rule: AccessRule = "example.com/api/v1/=GET,POST".parse().unwrap();
        assert_eq!(rule.hostname, "example.com");
        assert_eq!(rule.path_prefix.as_deref(), Some("/api/v1/"));
        let methods = rule.methods.unwrap();
        assert!(methods.contains(&HttpMethod::Get));
        assert!(methods.contains(&HttpMethod::Post));
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn parse_rule_hostname_with_methods_no_path() {
        let rule: AccessRule = "example.com=GET".parse().unwrap();
        assert_eq!(rule.hostname, "example.com");
        assert!(rule.path_prefix.is_none());
        let methods = rule.methods.unwrap();
        assert!(methods.contains(&HttpMethod::Get));
        assert_eq!(methods.len(), 1);
    }

    #[test]
    fn parse_rule_uppercase_hostname_lowered() {
        let rule: AccessRule = "Example.COM".parse().unwrap();
        assert_eq!(rule.hostname, "example.com");
    }

    #[test]
    fn parse_rule_empty_fails() {
        assert!("".parse::<AccessRule>().is_err());
        assert!("  ".parse::<AccessRule>().is_err());
    }

    #[test]
    fn parse_rule_empty_methods_fails() {
        assert!("example.com=".parse::<AccessRule>().is_err());
    }

    #[test]
    fn parse_rule_invalid_method_fails() {
        assert!("example.com=CONNECT".parse::<AccessRule>().is_err());
    }

    // --- AccessRule matching ---

    #[test]
    fn rule_matches_host_only() {
        let rule = AccessRule::host_only("example.com");
        assert!(rule.matches("example.com", "/anything", "GET"));
        assert!(rule.matches("example.com", "/foo/bar", "POST"));
        assert!(!rule.matches("other.com", "/", "GET"));
    }

    #[test]
    fn rule_matches_path_prefix() {
        let rule: AccessRule = "example.com/api/".parse().unwrap();
        assert!(rule.matches("example.com", "/api/v1/foo", "GET"));
        assert!(rule.matches("example.com", "/api/", "POST"));
        assert!(!rule.matches("example.com", "/other", "GET"));
    }

    #[test]
    fn rule_matches_methods() {
        let rule: AccessRule = "example.com=GET,HEAD".parse().unwrap();
        assert!(rule.matches("example.com", "/any", "GET"));
        assert!(rule.matches("example.com", "/any", "HEAD"));
        assert!(!rule.matches("example.com", "/any", "POST"));
        assert!(!rule.matches("example.com", "/any", "DELETE"));
    }

    #[test]
    fn rule_matches_path_and_methods() {
        let rule: AccessRule = "example.com/api/=GET".parse().unwrap();
        assert!(rule.matches("example.com", "/api/foo", "GET"));
        assert!(!rule.matches("example.com", "/api/foo", "POST"));
        assert!(!rule.matches("example.com", "/other", "GET"));
    }

    #[test]
    fn rule_matches_case_insensitive_host() {
        let rule = AccessRule::host_only("example.com");
        assert!(rule.matches("Example.COM", "/", "GET"));
    }

    // --- Mechanism default ---

    #[test]
    fn mechanism_default_is_mitm() {
        let r: AccessRule = "host.example".parse().unwrap();
        assert_eq!(r.mechanism, Mechanism::Mitm);
    }

    // --- path traversal ---

    fn rule_with_prefix(host: &str, prefix: &str) -> AccessRule {
        AccessRule {
            hostname: host.to_string(),
            path_prefix: Some(prefix.to_string()),
            methods: None,
            mechanism: Mechanism::Mitm,
        }
    }

    #[test]
    fn matches_rejects_literal_dotdot_in_prefix_path() {
        let r = rule_with_prefix("api.example", "/repos/");
        assert!(r.matches("api.example", "/repos/foo", "GET"));
        assert!(!r.matches("api.example", "/repos/../user/keys", "GET"));
        assert!(!r.matches("api.example", "/repos/..", "GET"));
    }

    #[test]
    fn matches_rejects_percent_encoded_dotdot_in_prefix_path() {
        let r = rule_with_prefix("api.example", "/repos/");
        assert!(!r.matches("api.example", "/repos/%2e%2e/user", "GET"));
        assert!(!r.matches("api.example", "/repos/%2E%2E/user", "GET"));
        assert!(!r.matches("api.example", "/repos/.%2e/user", "GET"));
        assert!(!r.matches("api.example", "/repos/%2e./user", "GET"));
    }

    #[test]
    fn matches_allows_double_dot_inside_a_segment() {
        let r = rule_with_prefix("api.example", "/repos/");
        assert!(r.matches("api.example", "/repos/foo..bar", "GET"));
        assert!(r.matches("api.example", "/repos/.config", "GET"));
    }

    #[test]
    fn matches_dotdot_check_only_applies_when_prefix_is_set() {
        let r = AccessRule::host_only("api.example");
        assert!(r.matches("api.example", "/anything/../else", "GET"));
    }

    #[test]
    fn matches_ignores_dotdot_in_query_string() {
        let r = rule_with_prefix("api.example", "/repos/");
        assert!(r.matches("api.example", "/repos/x?ref=..", "GET"));
    }
}
