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

/// Wrappers around `dns_cache`'s private items for the dedicated
/// test crate. Off by default; `sni-proxy-tests` flips on the
/// `__test_internals` feature in its `[dependencies]` entry.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use std::net::IpAddr;
    use std::time::Instant;

    pub fn insert_with_expiry(
        cache: &super::DnsCache,
        host: &str,
        ip: IpAddr,
        expiry: Instant,
    ) {
        cache.insert_with_expiry(host, ip, expiry);
    }
}
