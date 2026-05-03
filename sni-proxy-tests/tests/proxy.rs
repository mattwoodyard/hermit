//! Tests for `sni_proxy::proxy` accept-loop helpers. `get_original_dst`
//! is part of the public API — no `__test_internals` wrappers needed.
//!
//! NOTE: `get_original_dst_returns_none_on_normal_socket` is a
//! pre-existing environmental failure on loopback in some
//! environments — moved here verbatim.

use sni_proxy::proxy::get_original_dst;
use tokio::net::{TcpListener, TcpStream};

#[test]
fn get_original_dst_returns_none_on_normal_socket() {
    // A regular socket (not redirected) should return None, not crash
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        assert!(get_original_dst(&client).is_none());
    });
}
