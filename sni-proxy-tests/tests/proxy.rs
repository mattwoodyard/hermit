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

#[test]
fn get_original_dst_handles_ipv6_socket_without_crashing() {
    // Regression for the v4-only assumption in get_original_dst:
    // probing an IPv6 socket used to call getsockopt with the v4
    // (sockaddr_in) ABI, which would either truncate the reply or
    // return success with garbage. After the v6 patch, a non-DNAT'd
    // v6 socket must return None just like the v4 path — no panic,
    // no junk address. We can't easily stage a real DNAT'd v6 tuple
    // in a unit test, but the no-DNAT loopback path exercises the
    // family-probe + the v6 getsockopt branch.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        assert!(get_original_dst(&client).is_none());
    });
}
