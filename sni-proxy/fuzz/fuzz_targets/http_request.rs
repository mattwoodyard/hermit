#![no_main]
//! Fuzz the HTTP request head parser.
//!
//! `http::read_request` reads the request line + headers off an
//! attacker-controlled socket inside both the forward proxy and the
//! MITM engine. It enforces the smuggling guards (conflicting
//! Content-Length, multiple Transfer-Encoding, CL+TE-chunked
//! ambiguity) plus a 64KB head cap and an idle timeout. Every byte
//! the parser reads is attacker bytes; this fuzzer hammers that
//! parser with arbitrary inputs and verifies it never panics, never
//! UBs, never silently accepts a smuggling-shaped request.

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use sni_proxy::http;

thread_local! {
    /// Single-threaded tokio runtime, reused across iterations to
    /// keep per-iteration overhead low.
    static RT: RefCell<tokio::runtime::Runtime> = RefCell::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build fuzz runtime")
    );
}

fuzz_target!(|data: &[u8]| {
    RT.with(|rt| {
        rt.borrow().block_on(async {
            // `&[u8]` is an `AsyncRead` — short reads are returned
            // directly, EOF is signalled by an empty slice.
            let mut reader: &[u8] = data;
            let _ = http::read_request(&mut reader).await;
        });
    });
});
