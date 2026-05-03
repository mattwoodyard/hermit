//! Policy aggregations and the `ConnectionPolicy` / `RequestPolicy`
//! traits that the rest of the proxy consults.

use std::collections::{HashMap, HashSet};

use super::rule::{AccessRule, BypassProtocol, IpRule, Mechanism, Verdict};

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

/// Policy built from a list of [`AccessRule`]s (hostname-keyed) and,
/// optionally, [`IpRule`]s (literal-IP-keyed).
pub struct RuleSet {
    by_host: HashMap<String, Vec<AccessRule>>,
    by_ip: HashMap<std::net::IpAddr, Vec<IpRule>>,
    /// Learn-mode override: every `check` / `check_request` short-
    /// circuits to [`Verdict::Allow`] regardless of `by_host` /
    /// `by_ip`. Set via [`RuleSet::with_permit_all`]; intended
    /// solely for `hermit learn` so the proxies *observe* every
    /// access without enforcing a rule.
    permit_all: bool,
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
            permit_all: false,
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

    /// Switch into learn mode — every check returns [`Verdict::Allow`].
    pub fn with_permit_all(mut self, permit: bool) -> Self {
        self.permit_all = permit;
        self
    }

    pub fn is_permit_all(&self) -> bool {
        self.permit_all
    }

    /// Pick the enforcement mechanism for a TLS connection that
    /// arrived at the MITM listener.
    ///
    /// Bypass rules do not compete for this listener — they get their
    /// own ports — so they are skipped here. Among Mitm and Splice,
    /// Mitm wins when both match the same host: a single Mitm rule
    /// beats any number of Splice rules because the Mitm rule's
    /// path/method narrowing can only be enforced with plaintext
    /// visibility; falling through to Splice would silently widen
    /// the allowlist.
    ///
    /// Returns `None` if the hostname isn't served by the MITM listener.
    pub fn mechanism_for(&self, hostname: &str) -> Option<Mechanism> {
        let key = hostname.to_ascii_lowercase();
        let rules = self.by_host.get(&key)?;
        let mut saw_splice = false;
        for r in rules {
            if !r.matches_host(hostname) {
                continue;
            }
            match r.mechanism {
                Mechanism::Mitm => return Some(Mechanism::Mitm),
                Mechanism::Splice => saw_splice = true,
                Mechanism::Bypass { .. } => {} // handled by the bypass relays
            }
        }
        if saw_splice {
            Some(Mechanism::Splice)
        } else {
            None
        }
    }

    /// Does `hostname` have a bypass rule for this exact
    /// `(protocol, port)`? Distinct-protocol and distinct-port
    /// rules intentionally don't match.
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

    /// Counterpart to [`is_bypass_allowed`] for the literal-IP path.
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

    /// Distinct `(protocol, port)` pairs touched by any bypass rule —
    /// hostname- or IP-keyed. Used by the runtime to decide which
    /// bypass listeners + nft redirects to set up.
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
        v.sort();
        v
    }
}

impl ConnectionPolicy for RuleSet {
    fn check(&self, hostname: &str) -> Verdict {
        if self.permit_all {
            return Verdict::Allow;
        }
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
        if self.permit_all {
            return Verdict::Allow;
        }
        let key = hostname.to_ascii_lowercase();
        match self.by_host.get(&key) {
            Some(rules) if rules.iter().any(|r| r.matches(hostname, path, method)) => {
                Verdict::Allow
            }
            _ => Verdict::Deny,
        }
    }
}

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

