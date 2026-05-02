#![no_main]
//! Fuzz the upstream DNS response parser.
//!
//! `dns_forwarder::parse_answers` reads bytes that arrived from the
//! upstream DNS server (1.1.1.1 by default). That server is *not*
//! the attacker, but the bytes still flow over UDP across an
//! attacker-reachable network — a hostile resolver, a poisoned
//! cache, or any on-path adversary can deliver crafted responses.
//! The parser walks compressed labels and length-prefixed RDATA,
//! both of which historically are footguns.

use libfuzzer_sys::fuzz_target;
use sni_proxy::dns_forwarder;

fuzz_target!(|data: &[u8]| {
    // `parse_answers` returns Vec<ForwardedAnswer> — never errors,
    // just drops malformed records. We assert the no-panic / no-UB
    // invariant by simply running it on arbitrary bytes.
    let _ = dns_forwarder::parse_answers(data);
});
