#![no_main]
//! Fuzz the HTTP response head parser.
//!
//! `http::read_response` parses bytes that arrived from the upstream
//! origin server. The MITM engine forwards those bytes back to the
//! client *and* uses the parsed status to drive cache invalidation
//! (401 → drop the credential entry). A hostile origin can craft
//! arbitrary responses, so this is on the trust boundary too.
//! Smuggling guards mirror the request parser (multi-CL, multi-TE).

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use sni_proxy::http;

thread_local! {
    static RT: RefCell<tokio::runtime::Runtime> = RefCell::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build fuzz runtime")
    );
}

fuzz_target!(|data: &[u8]| {
    RT.with(|rt| {
        rt.borrow().block_on(async {
            let mut reader: &[u8] = data;
            let _ = http::read_response(&mut reader).await;
        });
    });
});
