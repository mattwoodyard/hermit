#![no_main]
//! Fuzz the inbound DNS query parser.
//!
//! `dns::parse_query` reads a UDP datagram from inside the sandbox.
//! The datagram is fully attacker-controlled — the sandboxed process
//! can send any bytes to 127.0.0.1:53 — so the parser is on the
//! direct trust boundary. Bugs here surface as panics in the DNS
//! responder task or, worse, as a stale `name_wire` slice that gets
//! echoed verbatim into the response.

use libfuzzer_sys::fuzz_target;
use sni_proxy::dns;

fuzz_target!(|data: &[u8]| {
    let _ = dns::parse_query(data);
});
