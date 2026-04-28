//! In-memory DNS answer cache, shared between the hermit DNS server
//! (which populates it on every upstream answer) and the various
//! relays (which reverse-map an SO_ORIGINAL_DST IP back to the
//! hostname the child originally asked for).
//!
//! Policy decisions never trust an IP that didn't flow through this
//! cache — if a relay sees a dst IP that is neither in a
//! literally-configured allowlist entry nor in the cache, the
//! connection is denied. That's what anchors hostname-centric policy
//! in a world where we route by dst-IP at the kernel level.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{debug, trace};

/// Name ↔ IP cache. Intended to be shared via `Arc<DnsCache>`.
///
/// The two maps are kept separately rather than derived from each
/// other so forward/reverse lookups are both O(1). CDN-style fan-out
/// (many names → one IP) resolves to whichever hostname was most
/// recently observed — good enough for audit; policy is enforced on
/// the *forward* lookup at DNS time, not on the reverse.
#[derive(Default)]
pub struct DnsCache {
    /// host → list of (ip, expiry) pairs; a host may legitimately
    /// hold several IPs (multi-A round-robin, dual-stack, etc.).
    fwd: Mutex<HashMap<String, Vec<(IpAddr, Instant)>>>,
    /// ip → (host, expiry); the most-recently-written host wins.
    rev: Mutex<HashMap<IpAddr, (String, Instant)>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember that `host` resolved to `ip` with the given TTL.
    /// Hostnames are stored in lowercase so case-variant queries
    /// share a single entry.
    pub fn insert(&self, host: &str, ip: IpAddr, ttl: Duration) {
        let expiry = Instant::now() + ttl;
        let key = host.to_ascii_lowercase();
        let ttl_secs = ttl.as_secs();

        let mut fwd = self.fwd.lock().unwrap();
        let entries = fwd.entry(key.clone()).or_default();
        let refreshed = match entries.iter_mut().find(|(existing_ip, _)| *existing_ip == ip) {
            Some(existing) => {
                existing.1 = expiry;
                true
            }
            None => {
                entries.push((ip, expiry));
                false
            }
        };
        let ip_count = entries.len();

        let mut rev = self.rev.lock().unwrap();
        let replaced = rev.insert(ip, (key.clone(), expiry)).is_some();

        if refreshed {
            debug!(host = %key, %ip, ttl_secs, ip_count, "dns-cache: refreshed");
        } else if replaced {
            debug!(host = %key, %ip, ttl_secs, ip_count,
                "dns-cache: inserted (ip previously mapped to a different host)");
        } else {
            debug!(host = %key, %ip, ttl_secs, ip_count, "dns-cache: inserted");
        }
    }

    /// Reverse-lookup: which hostname did we most recently hand out
    /// for this IP? Expired entries are lazily evicted so stale
    /// mappings never influence policy decisions.
    pub fn reverse(&self, ip: IpAddr) -> Option<String> {
        let mut rev = self.rev.lock().unwrap();
        match rev.get(&ip) {
            Some((host, expiry)) if *expiry > Instant::now() => {
                let host = host.clone();
                trace!(%ip, host = %host, "dns-cache: reverse hit");
                Some(host)
            }
            Some(_) => {
                debug!(%ip, "dns-cache: reverse found expired entry, evicting");
                rev.remove(&ip);
                None
            }
            None => {
                trace!(%ip, "dns-cache: reverse miss");
                None
            }
        }
    }

    /// Forward lookup: all un-expired IPs associated with `host`.
    /// Expired entries are purged as a side effect.
    pub fn lookup(&self, host: &str) -> Vec<IpAddr> {
        let key = host.to_ascii_lowercase();
        let mut fwd = self.fwd.lock().unwrap();
        let Some(entries) = fwd.get_mut(&key) else {
            trace!(host = %key, "dns-cache: lookup miss");
            return Vec::new();
        };
        let now = Instant::now();
        let before = entries.len();
        entries.retain(|(_, exp)| *exp > now);
        let evicted = before - entries.len();
        let ips: Vec<IpAddr> = entries.iter().map(|(ip, _)| *ip).collect();
        if entries.is_empty() {
            debug!(host = %key, evicted, "dns-cache: lookup — all entries expired, removing host");
            fwd.remove(&key);
        } else if evicted > 0 {
            debug!(host = %key, live = ips.len(), evicted, "dns-cache: lookup partial expiry");
        } else {
            trace!(host = %key, live = ips.len(), "dns-cache: lookup hit");
        }
        ips
    }

    /// Insert with a test-supplied `Instant` — used by tests to
    /// exercise expiry without sleeping. Not public outside the crate.
    #[cfg(test)]
    pub(crate) fn insert_with_expiry(&self, host: &str, ip: IpAddr, expiry: Instant) {
        let key = host.to_ascii_lowercase();
        let mut fwd = self.fwd.lock().unwrap();
        let entries = fwd.entry(key.clone()).or_default();
        match entries.iter_mut().find(|(existing_ip, _)| *existing_ip == ip) {
            Some(existing) => existing.1 = expiry,
            None => entries.push((ip, expiry)),
        }
        let mut rev = self.rev.lock().unwrap();
        rev.insert(ip, (key, expiry));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn insert_then_reverse_returns_host() {
        let c = DnsCache::new();
        c.insert("example.com", ipv4(203, 0, 113, 7), Duration::from_secs(60));
        assert_eq!(c.reverse(ipv4(203, 0, 113, 7)).as_deref(), Some("example.com"));
    }

    #[test]
    fn reverse_unknown_ip_is_none() {
        let c = DnsCache::new();
        assert!(c.reverse(ipv4(1, 2, 3, 4)).is_none());
    }

    #[test]
    fn reverse_lowercases_the_stored_hostname() {
        // Case-variant DNS queries must collapse to a single policy
        // key so that `cache.reverse(ip) == "example.com"` regardless
        // of whether the caller asked for Example.COM.
        let c = DnsCache::new();
        c.insert("Example.COM", ipv4(1, 1, 1, 1), Duration::from_secs(60));
        assert_eq!(c.reverse(ipv4(1, 1, 1, 1)).as_deref(), Some("example.com"));
    }

    #[test]
    fn multi_a_answers_produce_reverse_entry_per_ip() {
        // Multi-A responses (load-balanced services) must land in
        // the reverse map for *every* address, so the bypass relay
        // can authorize traffic no matter which IP the child
        // resolver picks. `fwd` also needs all three so
        // hostname-driven lookups stay honest.
        let c = DnsCache::new();
        for octet in [1u8, 2, 3] {
            c.insert(
                "kdc.example",
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, octet)),
                Duration::from_secs(300),
            );
        }
        for octet in [1u8, 2, 3] {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, octet));
            assert_eq!(
                c.reverse(ip).as_deref(),
                Some("kdc.example"),
                "reverse({ip}) should map to kdc.example"
            );
        }
        assert_eq!(c.lookup("kdc.example").len(), 3);
    }

    #[test]
    fn lookup_returns_all_ips_for_host() {
        let c = DnsCache::new();
        c.insert("multi.test", ipv4(10, 0, 0, 1), Duration::from_secs(60));
        c.insert("multi.test", ipv4(10, 0, 0, 2), Duration::from_secs(60));
        let mut got = c.lookup("multi.test");
        got.sort();
        assert_eq!(got, vec![ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2)]);
    }

    #[test]
    fn duplicate_insert_refreshes_ttl_does_not_duplicate() {
        let c = DnsCache::new();
        c.insert("x.test", ipv4(10, 0, 0, 1), Duration::from_secs(1));
        c.insert("x.test", ipv4(10, 0, 0, 1), Duration::from_secs(600));
        assert_eq!(c.lookup("x.test").len(), 1);
    }

    #[test]
    fn expired_entry_is_evicted_on_reverse() {
        // Reverse lookups must not return a host whose TTL has
        // passed — otherwise stale DNS leaks into policy decisions.
        let c = DnsCache::new();
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        c.insert_with_expiry("old.test", ipv4(10, 0, 0, 9), past);
        assert!(c.reverse(ipv4(10, 0, 0, 9)).is_none());
    }

    #[test]
    fn expired_entry_is_purged_from_lookup() {
        let c = DnsCache::new();
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        c.insert_with_expiry("old.test", ipv4(10, 0, 0, 9), past);
        assert!(c.lookup("old.test").is_empty());
    }

    #[test]
    fn lookup_mixes_live_and_expired_keeping_only_live() {
        let c = DnsCache::new();
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        c.insert_with_expiry("mix.test", ipv4(1, 0, 0, 1), past);
        c.insert("mix.test", ipv4(2, 0, 0, 2), Duration::from_secs(60));
        let got = c.lookup("mix.test");
        assert_eq!(got, vec![ipv4(2, 0, 0, 2)]);
    }

    #[test]
    fn later_write_wins_on_reverse_when_ip_reused() {
        // CDNs reuse IPs across hostnames. Reverse lookup returns
        // whichever hostname was most recently handed out, matching
        // "which request did the child most likely mean?" semantics.
        let c = DnsCache::new();
        c.insert("first.test", ipv4(1, 1, 1, 1), Duration::from_secs(60));
        c.insert("second.test", ipv4(1, 1, 1, 1), Duration::from_secs(60));
        assert_eq!(c.reverse(ipv4(1, 1, 1, 1)).as_deref(), Some("second.test"));
    }
}
