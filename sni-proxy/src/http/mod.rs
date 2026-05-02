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
