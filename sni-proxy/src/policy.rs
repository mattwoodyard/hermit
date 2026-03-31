use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

/// Verdict returned by a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

// ---------------------------------------------------------------------------
// HttpMethod — closed enum, parse-don't-validate
// ---------------------------------------------------------------------------

/// HTTP methods that can appear in access rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Patch,
    Options,
}

impl FromStr for HttpMethod {
    type Err = ParseMethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            "PATCH" => Ok(Self::Patch),
            "OPTIONS" => Ok(Self::Options),
            _ => Err(ParseMethodError(s.to_string())),
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Head => write!(f, "HEAD"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Delete => write!(f, "DELETE"),
            Self::Patch => write!(f, "PATCH"),
            Self::Options => write!(f, "OPTIONS"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParseMethodError(pub String);

impl fmt::Display for ParseMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown HTTP method: '{}'", self.0)
    }
}

impl std::error::Error for ParseMethodError {}

// ---------------------------------------------------------------------------
// AccessRule — a single allow rule
// ---------------------------------------------------------------------------

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
}

impl AccessRule {
    /// Create a hostname-only rule (allows any path and method).
    pub fn host_only(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into().to_ascii_lowercase(),
            path_prefix: None,
            methods: None,
        }
    }

    /// Check whether this rule matches the given request.
    fn matches(&self, hostname: &str, path: &str, method: &str) -> bool {
        if !self.hostname.eq_ignore_ascii_case(hostname) {
            return false;
        }
        if let Some(ref prefix) = self.path_prefix {
            if !path.starts_with(prefix.as_str()) {
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
                // Unknown method never matches a restricted rule
                Err(_) => return false,
            }
        }
        true
    }

    /// Check whether this rule's hostname matches (for DNS/connection-level checks).
    fn matches_host(&self, hostname: &str) -> bool {
        self.hostname.eq_ignore_ascii_case(hostname)
    }
}

// ---------------------------------------------------------------------------
// Rule parsing: "host[/path][=METHOD,METHOD]"
// ---------------------------------------------------------------------------

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

        // Split off methods after '='
        let (host_path, methods) = match s.rsplit_once('=') {
            Some((hp, m)) => (hp, Some(m)),
            None => (s, None),
        };

        // Split hostname from path at the first '/'
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
        })
    }
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Decides whether a connection to a given hostname is permitted.
/// Used by DNS and initial TLS accept (where only hostname is known).
pub trait ConnectionPolicy: Send + Sync {
    fn check(&self, hostname: &str) -> Verdict;
}

/// Request-level policy: checks hostname, path, and method.
/// Used by the MITM proxy after HTTP parsing.
pub trait RequestPolicy: ConnectionPolicy {
    fn check_request(&self, hostname: &str, path: &str, method: &str) -> Verdict;
}

// ---------------------------------------------------------------------------
// RuleSet — the main policy implementation
// ---------------------------------------------------------------------------

/// Policy built from a list of [`AccessRule`]s.
///
/// - `check` (hostname-only): allows if *any* rule matches the hostname.
/// - `check_request`: allows if *any* rule matches hostname + path + method.
pub struct RuleSet {
    /// Rules grouped by lowercase hostname for fast lookup.
    by_host: HashMap<String, Vec<AccessRule>>,
}

impl RuleSet {
    pub fn new(rules: Vec<AccessRule>) -> Self {
        let mut by_host: HashMap<String, Vec<AccessRule>> = HashMap::new();
        for rule in rules {
            by_host
                .entry(rule.hostname.to_ascii_lowercase())
                .or_default()
                .push(rule);
        }
        Self { by_host }
    }
}

impl ConnectionPolicy for RuleSet {
    fn check(&self, hostname: &str) -> Verdict {
        let key = hostname.to_ascii_lowercase();
        match self.by_host.get(&key) {
            Some(rules) if rules.iter().any(|r| r.matches_host(hostname)) => Verdict::Allow,
            _ => Verdict::Deny,
        }
    }
}

impl RequestPolicy for RuleSet {
    fn check_request(&self, hostname: &str, path: &str, method: &str) -> Verdict {
        let key = hostname.to_ascii_lowercase();
        match self.by_host.get(&key) {
            Some(rules) if rules.iter().any(|r| r.matches(hostname, path, method)) => {
                Verdict::Allow
            }
            _ => Verdict::Deny,
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy types (kept for backward compat and simple use cases)
// ---------------------------------------------------------------------------

/// Allowlist policy: only explicitly listed hostnames are permitted.
pub struct AllowList {
    hosts: HashSet<String>,
}

impl AllowList {
    pub fn new(hosts: HashSet<String>) -> Self {
        Self { hosts }
    }
}

impl ConnectionPolicy for AllowList {
    fn check(&self, hostname: &str) -> Verdict {
        if self.hosts.contains(hostname) {
            Verdict::Allow
        } else {
            Verdict::Deny
        }
    }
}

/// Allow everything (useful for testing or pass-through mode).
pub struct AllowAll;

impl ConnectionPolicy for AllowAll {
    fn check(&self, _hostname: &str) -> Verdict {
        Verdict::Allow
    }
}

impl RequestPolicy for AllowAll {
    fn check_request(&self, _hostname: &str, _path: &str, _method: &str) -> Verdict {
        Verdict::Allow
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- HttpMethod ---

    #[test]
    fn parse_method_valid() {
        assert_eq!(HttpMethod::from_str("GET").unwrap(), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("get").unwrap(), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("Post").unwrap(), HttpMethod::Post);
        assert_eq!(HttpMethod::from_str("DELETE").unwrap(), HttpMethod::Delete);
        assert_eq!(HttpMethod::from_str("patch").unwrap(), HttpMethod::Patch);
    }

    #[test]
    fn parse_method_invalid() {
        assert!(HttpMethod::from_str("CONNECT").is_err());
        assert!(HttpMethod::from_str("").is_err());
        assert!(HttpMethod::from_str("FOOBAR").is_err());
    }

    #[test]
    fn method_display_roundtrip() {
        for m in [
            HttpMethod::Get,
            HttpMethod::Head,
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Delete,
            HttpMethod::Patch,
            HttpMethod::Options,
        ] {
            assert_eq!(HttpMethod::from_str(&m.to_string()).unwrap(), m);
        }
    }

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

    // --- RuleSet ---

    #[test]
    fn ruleset_hostname_only_like_allowlist() {
        let rs = RuleSet::new(vec![AccessRule::host_only("example.com")]);
        assert_eq!(rs.check("example.com"), Verdict::Allow);
        assert_eq!(rs.check("evil.com"), Verdict::Deny);
    }

    #[test]
    fn ruleset_empty_denies_all() {
        let rs = RuleSet::new(vec![]);
        assert_eq!(rs.check("anything.com"), Verdict::Deny);
        assert_eq!(
            rs.check_request("anything.com", "/", "GET"),
            Verdict::Deny
        );
    }

    #[test]
    fn ruleset_host_check_allows_if_any_rule_matches_host() {
        // Two rules for same host: one restricts path, one doesn't.
        // Host-level check should allow since the host appears in rules.
        let rs = RuleSet::new(vec![
            "example.com/api/=GET".parse().unwrap(),
            "example.com/static/".parse().unwrap(),
        ]);
        assert_eq!(rs.check("example.com"), Verdict::Allow);
    }

    #[test]
    fn ruleset_request_check_path_method() {
        let rs = RuleSet::new(vec![
            "example.com/api/=GET".parse().unwrap(),
            "example.com/upload/=POST".parse().unwrap(),
        ]);
        assert_eq!(
            rs.check_request("example.com", "/api/foo", "GET"),
            Verdict::Allow
        );
        assert_eq!(
            rs.check_request("example.com", "/upload/bar", "POST"),
            Verdict::Allow
        );
        assert_eq!(
            rs.check_request("example.com", "/api/foo", "POST"),
            Verdict::Deny
        );
        assert_eq!(
            rs.check_request("example.com", "/other", "GET"),
            Verdict::Deny
        );
    }

    #[test]
    fn ruleset_multiple_hosts() {
        let rs = RuleSet::new(vec![
            AccessRule::host_only("a.com"),
            "b.com/x/=GET".parse().unwrap(),
        ]);
        assert_eq!(rs.check_request("a.com", "/anything", "DELETE"), Verdict::Allow);
        assert_eq!(rs.check_request("b.com", "/x/y", "GET"), Verdict::Allow);
        assert_eq!(rs.check_request("b.com", "/x/y", "POST"), Verdict::Deny);
        assert_eq!(rs.check_request("c.com", "/", "GET"), Verdict::Deny);
    }

    // --- Legacy types ---

    #[test]
    fn allowlist_permits_listed_host() {
        let policy = AllowList::new(["example.com".into()].into());
        assert_eq!(policy.check("example.com"), Verdict::Allow);
    }

    #[test]
    fn allowlist_denies_unlisted_host() {
        let policy = AllowList::new(["example.com".into()].into());
        assert_eq!(policy.check("evil.com"), Verdict::Deny);
    }

    #[test]
    fn allowlist_empty_denies_all() {
        let policy = AllowList::new(HashSet::new());
        assert_eq!(policy.check("anything.com"), Verdict::Deny);
    }

    #[test]
    fn allow_all_permits_everything() {
        let policy = AllowAll;
        assert_eq!(policy.check("anything.com"), Verdict::Allow);
        assert_eq!(
            policy.check_request("any.com", "/path", "POST"),
            Verdict::Allow
        );
    }
}
