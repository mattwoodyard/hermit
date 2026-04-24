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

/// How a matched rule is actually enforced on the wire.
///
/// - `Mitm`: terminate TLS with the hermit CA, fully parse HTTP, apply
///   `path_prefix` / `methods`, optionally inject credentials. This is
///   the default and the only mechanism that supports L7 filtering.
/// - `Sni`: a "cut-through" splice — we read the TLS ClientHello, look
///   up the hostname against policy, and from there on shuttle bytes
///   bidirectionally without inspecting them. Incompatible with
///   `path_prefix`, `methods`, and credential injection (we never see
///   the plaintext). Use for hostnames whose transport must remain
///   unmodified (e.g. certificate-pinning clients).
/// - `Bypass { protocol, port }`: plain relay for non-HTTP protocols
///   (Kerberos UDP, LDAP, SSH, ...). The bypass relay listens on a
///   dedicated port, SO_ORIGINAL_DST / IP_RECVORIGDSTADDR gives us the
///   real destination, the DNS cache maps that back to a hostname for
///   the policy check, and we splice bytes. No interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mechanism {
    /// Full MITM with plaintext inspection.
    #[default]
    Mitm,
    /// SNI-only cut-through proxy; no plaintext inspection.
    Sni,
    /// Transparent relay on the given (protocol, port). Decisions
    /// happen on hostname — the port identifies which listener this
    /// rule is served from.
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
            Mechanism::Sni => write!(f, "sni"),
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
            mechanism: Mechanism::default(),
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

    /// Which enforcement mechanism should be used for this hostname.
    /// Defaults to [`Mechanism::Mitm`] so existing policies that don't
    /// know about mechanisms behave as before; [`RuleSet`] overrides
    /// this to consult its per-rule mechanism field.
    fn mechanism(&self, _hostname: &str) -> Mechanism {
        Mechanism::Mitm
    }
}

/// Request-level policy: checks hostname, path, and method.
/// Used by the MITM proxy after HTTP parsing.
pub trait RequestPolicy: ConnectionPolicy {
    fn check_request(&self, hostname: &str, path: &str, method: &str) -> Verdict;
}

// ---------------------------------------------------------------------------
// IpRule — allowlist entry keyed by a literal IP instead of a hostname.
// ---------------------------------------------------------------------------

/// Bypass-only allowlist entry keyed by a literal IP. The MITM and
/// SNI mechanisms fundamentally operate on hostnames (SNI lookup on
/// TLS, etc.) so they can't be expressed as IP rules — parsing
/// rejects the combination.
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

// ---------------------------------------------------------------------------
// RuleSet — the main policy implementation
// ---------------------------------------------------------------------------

/// Policy built from a list of [`AccessRule`]s (hostname-keyed) and,
/// optionally, [`IpRule`]s (literal-IP-keyed).
///
/// - `check` (hostname-only): allows if *any* host rule matches.
/// - `check_request`: allows if *any* host rule matches hostname +
///   path + method.
/// - `is_bypass_allowed` / `is_bypass_allowed_by_ip`: the bypass
///   relays' gate, consulted after `SO_ORIGINAL_DST` / the DNS
///   cache produces either a hostname or a bare IP.
pub struct RuleSet {
    /// Host rules grouped by lowercase hostname for O(1) lookup.
    by_host: HashMap<String, Vec<AccessRule>>,
    /// IP rules grouped by literal IP. Only populated when the
    /// config declares `ip = "…"` rules.
    by_ip: HashMap<std::net::IpAddr, Vec<IpRule>>,
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
        Self {
            by_host,
            by_ip: HashMap::new(),
        }
    }

    /// Builder-style extension: attach literal-IP rules. Kept as a
    /// separate call so the common hostname-only case remains the
    /// one-liner it was before IP rules existed.
    pub fn with_ip_rules(mut self, rules: Vec<IpRule>) -> Self {
        for rule in rules {
            self.by_ip.entry(rule.ip).or_default().push(rule);
        }
        self
    }

    /// Pick the enforcement mechanism for a TLS connection that
    /// arrived at the MITM listener.
    ///
    /// Bypass rules do not compete for this listener — they get their
    /// own ports — so they are skipped here. Among Mitm and Sni:
    ///
    /// - If *any* matching rule requests [`Mechanism::Mitm`], we MITM.
    ///   A single Mitm rule beats any number of Sni rules because the
    ///   Mitm rule's path/method narrowing can only be enforced with
    ///   plaintext visibility; falling through to Sni would silently
    ///   widen the allowlist.
    /// - Otherwise, if any rule matches and is [`Mechanism::Sni`], we
    ///   splice.
    /// - If no MITM/SNI rule matches, return `None`; the caller
    ///   interprets that as "this hostname is not served by the MITM
    ///   listener" and denies.
    pub fn mechanism_for(&self, hostname: &str) -> Option<Mechanism> {
        let key = hostname.to_ascii_lowercase();
        let rules = self.by_host.get(&key)?;
        let mut saw_sni = false;
        for r in rules {
            if !r.matches_host(hostname) {
                continue;
            }
            match r.mechanism {
                Mechanism::Mitm => return Some(Mechanism::Mitm),
                Mechanism::Sni => saw_sni = true,
                Mechanism::Bypass { .. } => {} // handled by the bypass relays
            }
        }
        if saw_sni {
            Some(Mechanism::Sni)
        } else {
            None
        }
    }

    /// Does `hostname` have a bypass rule for this exact
    /// `(protocol, port)`? Called by the bypass relay once
    /// `SO_ORIGINAL_DST` + the DNS cache reverse-map have
    /// produced a hostname. Distinct-protocol and distinct-port
    /// rules intentionally don't match — the whole point is that
    /// each relay listens on exactly one (proto, port).
    pub fn is_bypass_allowed(
        &self,
        hostname: &str,
        protocol: BypassProtocol,
        port: u16,
    ) -> bool {
        let key = hostname.to_ascii_lowercase();
        let Some(rules) = self.by_host.get(&key) else {
            tracing::trace!(host = %key, ?protocol, port,
                "policy: is_bypass_allowed — host not in ruleset");
            return false;
        };
        let allowed = rules
            .iter()
            .filter(|r| r.matches_host(hostname))
            .any(|r| matches!(r.mechanism, Mechanism::Bypass { protocol: p, port: po }
                if p == protocol && po == port));
        tracing::trace!(host = %key, ?protocol, port, candidate_rules = rules.len(), allowed,
            "policy: is_bypass_allowed");
        allowed
    }

    /// Counterpart to [`is_bypass_allowed`] for the literal-IP
    /// path. The bypass relays fall through to this when
    /// `DnsCache::reverse` can't map the dst back to a name — the
    /// child is trying to reach a raw IP, and we only allow that
    /// when it was declared as an `ip = "…"` rule.
    pub fn is_bypass_allowed_by_ip(
        &self,
        ip: std::net::IpAddr,
        protocol: BypassProtocol,
        port: u16,
    ) -> bool {
        let Some(rules) = self.by_ip.get(&ip) else {
            tracing::trace!(%ip, ?protocol, port,
                "policy: is_bypass_allowed_by_ip — ip not in ruleset");
            return false;
        };
        let allowed = rules
            .iter()
            .any(|r| matches!(r.mechanism, Mechanism::Bypass { protocol: p, port: po }
                if p == protocol && po == port));
        tracing::trace!(%ip, ?protocol, port, candidate_rules = rules.len(), allowed,
            "policy: is_bypass_allowed_by_ip");
        allowed
    }

    /// Distinct `(protocol, port)` pairs touched by any bypass rule
    /// — hostname- or IP-keyed. Used by the runtime to decide
    /// which bypass listeners + nft redirects to set up. IP-only
    /// endpoints still need their own listener and DNAT rule, so
    /// they must be included here.
    pub fn bypass_endpoints(&self) -> Vec<(BypassProtocol, u16)> {
        let mut set = std::collections::HashSet::new();
        for rules in self.by_host.values() {
            for r in rules {
                if let Mechanism::Bypass { protocol, port } = r.mechanism {
                    set.insert((protocol, port));
                }
            }
        }
        for rules in self.by_ip.values() {
            for r in rules {
                if let Mechanism::Bypass { protocol, port } = r.mechanism {
                    set.insert((protocol, port));
                }
            }
        }
        let mut v: Vec<_> = set.into_iter().collect();
        v.sort(); // deterministic order for tests + log output
        v
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

    fn mechanism(&self, hostname: &str) -> Mechanism {
        // An unknown host will be denied by `check`; the mechanism
        // response for it doesn't route any real traffic, so we just
        // fall back to the default rather than complicating the
        // signature with a fallible return.
        self.mechanism_for(hostname).unwrap_or_default()
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

    // --- Mechanism dispatch ---

    fn rule_with_mech(host: &str, mechanism: Mechanism) -> AccessRule {
        AccessRule {
            hostname: host.to_string(),
            path_prefix: None,
            methods: None,
            mechanism,
        }
    }

    #[test]
    fn mechanism_default_is_mitm() {
        let r: AccessRule = "host.example".parse().unwrap();
        assert_eq!(r.mechanism, Mechanism::Mitm);
    }

    #[test]
    fn mechanism_for_unknown_host_is_none() {
        let rs = RuleSet::new(vec![rule_with_mech("ok.example", Mechanism::Mitm)]);
        assert!(rs.mechanism_for("other.example").is_none());
    }

    #[test]
    fn mechanism_for_mitm_rule() {
        let rs = RuleSet::new(vec![rule_with_mech("ok.example", Mechanism::Mitm)]);
        assert_eq!(rs.mechanism_for("ok.example"), Some(Mechanism::Mitm));
    }

    #[test]
    fn mechanism_for_sni_rule() {
        let rs = RuleSet::new(vec![rule_with_mech("pinned.example", Mechanism::Sni)]);
        assert_eq!(rs.mechanism_for("pinned.example"), Some(Mechanism::Sni));
    }

    #[test]
    fn mechanism_mitm_wins_when_rules_conflict() {
        // A hostname with both a Mitm rule (say, /api/ path_prefix) and
        // a Sni rule (catch-all) must resolve to Mitm. Otherwise a
        // Sni-wins rule would silently widen the allowlist by bypassing
        // the path/method check the Mitm rule encoded.
        let rs = RuleSet::new(vec![
            rule_with_mech("dual.example", Mechanism::Sni),
            rule_with_mech("dual.example", Mechanism::Mitm),
        ]);
        assert_eq!(rs.mechanism_for("dual.example"), Some(Mechanism::Mitm));
    }

    #[test]
    fn mechanism_lookup_is_case_insensitive() {
        let rs = RuleSet::new(vec![rule_with_mech("Mixed.Example", Mechanism::Sni)]);
        assert_eq!(rs.mechanism_for("mixed.example"), Some(Mechanism::Sni));
        assert_eq!(rs.mechanism_for("MIXED.EXAMPLE"), Some(Mechanism::Sni));
    }

    // --- Bypass ---

    fn bypass_rule(host: &str, protocol: BypassProtocol, port: u16) -> AccessRule {
        AccessRule {
            hostname: host.to_string(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol, port },
        }
    }

    #[test]
    fn is_bypass_allowed_happy_path() {
        let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
        assert!(rs.is_bypass_allowed("kdc.example", BypassProtocol::Udp, 88));
    }

    #[test]
    fn is_bypass_allowed_rejects_wrong_protocol() {
        // UDP rule must not authorize a TCP listener even on the
        // matching port — they're different wires.
        let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
        assert!(!rs.is_bypass_allowed("kdc.example", BypassProtocol::Tcp, 88));
    }

    #[test]
    fn is_bypass_allowed_rejects_wrong_port() {
        let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
        assert!(!rs.is_bypass_allowed("kdc.example", BypassProtocol::Udp, 99));
    }

    #[test]
    fn is_bypass_allowed_rejects_wrong_host() {
        let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
        assert!(!rs.is_bypass_allowed("other.example", BypassProtocol::Udp, 88));
    }

    #[test]
    fn is_bypass_allowed_is_case_insensitive() {
        let rs = RuleSet::new(vec![bypass_rule("KDC.Example", BypassProtocol::Udp, 88)]);
        assert!(rs.is_bypass_allowed("kdc.example", BypassProtocol::Udp, 88));
    }

    #[test]
    fn bypass_rules_do_not_influence_mechanism_for() {
        // A bypass-only host must not surface as Mitm/Sni to the
        // TLS dispatch — the mechanism_for result is what the MITM
        // listener consults, and bypass belongs to a different
        // listener entirely.
        let rs = RuleSet::new(vec![bypass_rule("kdc.example", BypassProtocol::Udp, 88)]);
        assert_eq!(rs.mechanism_for("kdc.example"), None);
    }

    #[test]
    fn is_bypass_allowed_by_ip_happy_path() {
        let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
            ip: "10.0.0.5".parse().unwrap(),
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
        }]);
        assert!(rs.is_bypass_allowed_by_ip(
            "10.0.0.5".parse().unwrap(),
            BypassProtocol::Udp,
            88,
        ));
    }

    #[test]
    fn is_bypass_allowed_by_ip_rejects_wrong_proto_port() {
        let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
            ip: "10.0.0.5".parse().unwrap(),
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
        }]);
        assert!(!rs.is_bypass_allowed_by_ip(
            "10.0.0.5".parse().unwrap(),
            BypassProtocol::Tcp,
            88,
        ));
        assert!(!rs.is_bypass_allowed_by_ip(
            "10.0.0.5".parse().unwrap(),
            BypassProtocol::Udp,
            99,
        ));
    }

    #[test]
    fn is_bypass_allowed_by_ip_unknown_ip_is_denied() {
        let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
            ip: "10.0.0.5".parse().unwrap(),
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
        }]);
        assert!(!rs.is_bypass_allowed_by_ip(
            "10.0.0.99".parse().unwrap(),
            BypassProtocol::Udp,
            88,
        ));
    }

    #[test]
    fn bypass_endpoints_includes_ip_keyed_rules() {
        // An ip-only rule still needs its own listener + DNAT
        // entry, so it must show up in `bypass_endpoints`.
        let rs = RuleSet::new(vec![]).with_ip_rules(vec![IpRule {
            ip: "10.0.0.5".parse().unwrap(),
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 389 },
        }]);
        assert_eq!(
            rs.bypass_endpoints(),
            vec![(BypassProtocol::Tcp, 389)]
        );
    }

    #[test]
    fn bypass_endpoints_deduplicates() {
        let rs = RuleSet::new(vec![
            bypass_rule("a.example", BypassProtocol::Udp, 88),
            bypass_rule("b.example", BypassProtocol::Udp, 88), // same endpoint, different host
            bypass_rule("a.example", BypassProtocol::Tcp, 389),
        ]);
        let got = rs.bypass_endpoints();
        assert_eq!(
            got,
            vec![
                (BypassProtocol::Tcp, 389),
                (BypassProtocol::Udp, 88),
            ]
        );
    }
}
