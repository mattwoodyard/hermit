use std::collections::HashSet;

/// Verdict returned by a connection policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

/// Decides whether a connection to a given hostname is permitted.
pub trait ConnectionPolicy: Send + Sync {
    fn check(&self, hostname: &str) -> Verdict;
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
