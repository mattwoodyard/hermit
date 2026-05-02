#![no_main]
//! Fuzz `http::set_header`, the function the MITM engine uses to
//! splice credential-injection headers into a request before
//! forwarding it upstream.
//!
//! The function takes three pieces of input:
//!   * the existing head bytes (a parsed-already HTTP head — but
//!     in a fuzzer those bytes are arbitrary)
//!   * a header name (bounded by the RFC 7230 tchar validator)
//!   * a header value (bounded by the CR/LF/NUL validator)
//!
//! Recent commits hardened both validators to refuse smuggling
//! shapes (`\r\n` in the value, `:` in the name, etc.). The
//! fuzzer's job is to keep those guards honest: a malformed
//! input must produce an `Err` and *must not* leave the buffer
//! partially edited.

use libfuzzer_sys::{arbitrary, fuzz_target};
use sni_proxy::http;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input<'a> {
    head: &'a [u8],
    name: &'a str,
    value: &'a str,
}

fuzz_target!(|input: Input<'_>| {
    let mut buf = input.head.to_vec();
    let before = buf.clone();
    match http::set_header(&mut buf, input.name, input.value) {
        Ok(()) => {
            // No panic, no UB — that's enough for the no-crash
            // contract. The function may have edited `buf`, which
            // is the documented success path.
        }
        Err(_) => {
            // Documented invariant: rejection leaves the buffer
            // unchanged. A partial edit on rejection would smuggle
            // header bytes back upstream.
            assert_eq!(
                buf, before,
                "set_header rejected input but mutated the buffer"
            );
        }
    }
});
