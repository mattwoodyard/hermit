//! Minimal HTTP/1.1 request parsing and forwarding.
//!
//! Submodules:
//! - [`parse`]: request and response head parsing (smuggling guards live here)
//! - [`body`]: streaming forwarders for chunked / content-length / EOF-framed bodies
//! - [`headers`]: insert/replace + RFC 7230 validators for header name/value
//! - [`responder`]: canned 4xx responses (403, 421)

mod body;
mod headers;
mod parse;
mod responder;

pub use body::{
    forward_body_content_length, forward_chunked_body, forward_until_eof, IO_IDLE_TIMEOUT,
};
pub use headers::set_header;
pub use parse::{host_without_port, read_request, read_response, Request, Response};
pub use responder::{write_403, write_421};

/// Wrappers around `http`'s private items for the dedicated test
/// crate (`sni-proxy-tests`). Off by default; the test crate flips on
/// the `__test_internals` feature in its `[dependencies]` entry.
///
/// Wrappers (rather than `pub use`) because Rust E0364 forbids
/// re-exporting `pub(crate)` items outside the crate. The items
/// themselves stay `pub(crate)` — the broadening is contained to
/// these wrapper signatures.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    pub fn split_absolute_form(target: &str) -> (String, Option<String>) {
        super::parse::split_absolute_form(target)
    }
}
