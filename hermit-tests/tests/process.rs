//! Tests for `hermit::process`. The items used here were promoted
//! from `pub(crate)` to `pub` (with `#[doc(hidden)]`) for test
//! access — wrappers would have been too verbose for `FdLayout`'s
//! 7 fields and 3 methods.

use hermit::process::{
    compute_bypass_tcp_allocations, compute_bypass_udp_allocations, proxy_env_vars,
    readiness_pipe, BYPASS_TCP_BASE_PORT, BYPASS_UDP_BASE_PORT, CHILD_PID, FdLayout,
    HTTP_PROXY_LISTEN_PORT, NftPlan,
};
use sni_proxy::policy::RuleSet;
use std::sync::atomic::Ordering;

#[test]
fn test_readiness_pipe_signal() {
    let (reader, writer) = readiness_pipe().unwrap();
    writer.signal();
    reader.wait().unwrap();
}

#[test]
fn test_readiness_pipe_drop_without_signal() {
    let (reader, writer) = readiness_pipe().unwrap();
    drop(writer);
    let result = reader.wait();
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("died before signaling"),
    );
}

#[test]
fn test_child_pid_atomic_default() {
    // CHILD_PID starts at 0
    assert_eq!(CHILD_PID.load(Ordering::SeqCst), 0);
}

#[test]
fn bypass_tcp_allocations_give_distinct_relay_ports() {
    use sni_proxy::policy::{AccessRule, BypassProtocol, Mechanism};
    let rules = RuleSet::new(vec![
        AccessRule {
            hostname: "a.example".into(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 389 },
        },
        AccessRule {
            hostname: "b.example".into(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 22 },
        },
        // UDP rule must not appear in the TCP allocation list.
        AccessRule {
            hostname: "c.example".into(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
        },
    ]);
    let allocs = compute_bypass_tcp_allocations(&rules);
    assert_eq!(allocs.len(), 2);
    let relay_ports: std::collections::HashSet<_> =
        allocs.iter().map(|a| a.relay_port).collect();
    assert_eq!(relay_ports.len(), 2);
    for a in &allocs {
        assert!(a.relay_port >= BYPASS_TCP_BASE_PORT);
    }
}

#[test]
fn bypass_udp_allocations_coexist_with_tcp_on_same_port() {
    use sni_proxy::policy::{AccessRule, BypassProtocol, Mechanism};
    let rules = RuleSet::new(vec![
        AccessRule {
            hostname: "kdc.example".into(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Udp, port: 88 },
        },
        AccessRule {
            hostname: "kdc.example".into(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 88 },
        },
    ]);
    let tcp_allocs = compute_bypass_tcp_allocations(&rules);
    let udp_allocs = compute_bypass_udp_allocations(&rules);
    assert_eq!(tcp_allocs.len(), 1);
    assert_eq!(udp_allocs.len(), 1);
    assert!(tcp_allocs[0].relay_port >= BYPASS_TCP_BASE_PORT);
    assert!(tcp_allocs[0].relay_port < BYPASS_UDP_BASE_PORT);
    assert!(udp_allocs[0].relay_port >= BYPASS_UDP_BASE_PORT);
}

#[test]
fn bypass_tcp_allocations_deduplicate_same_port_different_hosts() {
    use sni_proxy::policy::{AccessRule, BypassProtocol, Mechanism};
    let rules = RuleSet::new(vec![
        AccessRule {
            hostname: "a.example".into(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 22 },
        },
        AccessRule {
            hostname: "b.example".into(),
            path_prefix: None,
            methods: None,
            mechanism: Mechanism::Bypass { protocol: BypassProtocol::Tcp, port: 22 },
        },
    ]);
    let allocs = compute_bypass_tcp_allocations(&rules);
    assert_eq!(allocs.len(), 1, "same port must share one relay listener");
}

#[test]
fn proxy_env_vars_cover_both_casings_and_no_proxy() {
    let vars: std::collections::HashMap<_, _> = proxy_env_vars().into_iter().collect();
    let expected_url = format!("http://127.0.0.1:{}", HTTP_PROXY_LISTEN_PORT);
    for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
        assert_eq!(vars.get(k).map(|s| s.as_str()), Some(expected_url.as_str()),
            "missing or wrong value for {k}");
    }
    for k in ["NO_PROXY", "no_proxy"] {
        let v = vars.get(k).expect("missing NO_PROXY casing");
        assert!(v.contains("127.0.0.1"), "NO_PROXY missing 127.0.0.1: {v}");
        assert!(v.contains("localhost"), "NO_PROXY missing localhost: {v}");
    }
}

#[test]
fn nft_plan_render_lists_rules_in_install_order() {
    let mut plan = NftPlan::default();
    plan.push_tcp(Some(443), 1443, "MITM proxy");
    plan.push_tcp(Some(80), 1080, "HTTP proxy");
    plan.push_tcp(Some(8443), 1443, "port_forward https → MITM");
    plan.push_tcp(Some(389), 1090, "bypass-tcp");
    plan.push_udp_v4(88, 1400, "bypass-udp v4");
    plan.push_udp_v6(88, 1400, "bypass-udp v6");
    plan.push_tcp(None, 1500, "learn-mode observer (catch-all)");

    let out = plan.render();
    for label in [
        "MITM proxy", "HTTP proxy", "port_forward https",
        "bypass-tcp", "bypass-udp v4", "bypass-udp v6",
        "learn-mode observer",
    ] {
        assert!(out.contains(label), "missing {label} in: {out}");
    }
    assert!(out.contains(":   * ->"),
        "catch-all must render with `*` source port: {out}");
    let i_443 = out.find("[ 1]").expect("rule [ 1] missing");
    let i_obs = out.find("[ 7]").expect("rule [ 7] missing");
    assert!(i_443 < i_obs, "rule order must be preserved");
    assert!(out.contains("[::1]:1400"), "udp v6 must use [::1]: {out}");
}

#[test]
fn nft_plan_render_handles_no_rules() {
    let plan = NftPlan::default();
    assert!(plan.render().contains("(no rules)"));
}

#[test]
fn nft_plan_aligns_source_port_column() {
    let mut plan = NftPlan::default();
    plan.push_tcp(Some(443), 1443, "MITM");
    plan.push_tcp(Some(80), 1080, "HTTP");
    plan.push_tcp(Some(50000), 1090, "bypass");
    let out = plan.render();
    assert!(out.contains(":   80 ->"), "80 should be right-padded: {out}");
    assert!(out.contains(":50000 ->"), "{out}");
}

// --- FdLayout round-trip --------------------------------------------

fn sample_layout(tcp: usize, udp: usize, learn: bool) -> FdLayout {
    let bypass_tcp: Vec<i32> = (10..10 + tcp as i32).collect();
    let bypass_udp_v4: Vec<i32> = (100..100 + udp as i32).collect();
    let bypass_udp_v6: Vec<i32> = (200..200 + udp as i32).collect();
    FdLayout {
        https: 3,
        http: 4,
        dns: 5,
        bypass_tcp,
        bypass_udp_v4,
        bypass_udp_v6,
        observer: if learn { Some(999) } else { None },
    }
}

#[test]
fn fd_layout_to_vec_no_bypass_no_learn() {
    let l = sample_layout(0, 0, false);
    assert_eq!(l.to_vec(), vec![3, 4, 5]);
}

#[test]
fn fd_layout_to_vec_includes_bypass_tcp_then_udp_then_observer() {
    let l = sample_layout(2, 1, true);
    assert_eq!(l.to_vec(), vec![3, 4, 5, 10, 11, 100, 200, 999]);
}

#[test]
fn fd_layout_round_trip_no_bypass() {
    let original = sample_layout(0, 0, false);
    let parsed = FdLayout::from_vec(original.to_vec(), 0, 0, false).unwrap();
    assert_eq!(parsed.https, original.https);
    assert_eq!(parsed.http, original.http);
    assert_eq!(parsed.dns, original.dns);
    assert!(parsed.bypass_tcp.is_empty());
    assert!(parsed.bypass_udp_v4.is_empty());
    assert!(parsed.bypass_udp_v6.is_empty());
    assert!(parsed.observer.is_none());
}

#[test]
fn fd_layout_round_trip_with_bypass_and_learn() {
    let original = sample_layout(3, 2, true);
    let parsed = FdLayout::from_vec(original.to_vec(), 3, 2, true).unwrap();
    assert_eq!(parsed.https, 3);
    assert_eq!(parsed.bypass_tcp, vec![10, 11, 12]);
    assert_eq!(parsed.bypass_udp_v4, vec![100, 101]);
    assert_eq!(parsed.bypass_udp_v6, vec![200, 201]);
    assert_eq!(parsed.observer, Some(999));
}

#[test]
fn fd_layout_from_vec_rejects_short_buffer() {
    let err = FdLayout::from_vec(vec![3, 4, 5], 1, 0, false).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("expected 4"), "got: {msg}");
    assert!(msg.contains("got 3"), "got: {msg}");
}

#[test]
fn fd_layout_from_vec_rejects_long_buffer() {
    let err = FdLayout::from_vec(vec![3, 4, 5, 6, 7], 0, 0, false).unwrap_err();
    assert!(err.to_string().contains("got 5"));
}

#[test]
fn fd_layout_expected_total_matches_to_vec_len() {
    for tcp in 0..4 {
        for udp in 0..4 {
            for learn in [false, true] {
                let layout = sample_layout(tcp, udp, learn);
                let total = FdLayout::expected_total(tcp, udp, learn);
                assert_eq!(
                    layout.to_vec().len(),
                    total,
                    "tcp={tcp} udp={udp} learn={learn}: \
                     expected_total disagrees with to_vec().len()"
                );
            }
        }
    }
}
