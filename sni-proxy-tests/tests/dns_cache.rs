//! Tests for `sni_proxy::dns_cache`. Reaches `insert_with_expiry`
//! via the `__test_internals` wrapper so test fixtures can plant
//! pre-expired entries without sleeping.

use sni_proxy::dns_cache::DnsCache;
use sni_proxy::dns_cache::__test_internals::insert_with_expiry;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

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
    insert_with_expiry(&c, "old.test", ipv4(10, 0, 0, 9), past);
    assert!(c.reverse(ipv4(10, 0, 0, 9)).is_none());
}

#[test]
fn expired_entry_is_purged_from_lookup() {
    let c = DnsCache::new();
    let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    insert_with_expiry(&c, "old.test", ipv4(10, 0, 0, 9), past);
    assert!(c.lookup("old.test").is_empty());
}

#[test]
fn lookup_mixes_live_and_expired_keeping_only_live() {
    let c = DnsCache::new();
    let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    insert_with_expiry(&c, "mix.test", ipv4(1, 0, 0, 1), past);
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
