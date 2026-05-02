#![no_main]
//! Fuzz the TLS ClientHello SNI extractor.
//!
//! `extract_sni` is the very first parser to touch attacker-controlled
//! bytes — every TLS connection that arrives at the MITM, transparent,
//! or forward listeners passes through it. The function inspects raw
//! TLS record framing, walks extensions, and reads length-prefixed
//! fields. A panic here would take a connection task down; a length
//! confusion or out-of-bounds read could be exploitable on the host.

use libfuzzer_sys::fuzz_target;
use sni_proxy::sni;

fuzz_target!(|data: &[u8]| {
    // The function returns Result<SniResult>; we don't care which
    // variant — only that it never panics, never reads past `data`,
    // and never loops indefinitely. Drop the result.
    let _ = sni::extract_sni(data);
});
