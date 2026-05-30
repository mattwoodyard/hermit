//! Tests for `sni_proxy::conntrack` — the CTNETLINK lookup that
//! recovers the pre-NAT destination of a DNAT'd UDP datagram. We
//! exercise the wire encoding (`build_request`) and the response
//! parser (`parse_orig_dst`) against hand-built byte buffers so
//! the tests run without holding `CAP_NET_ADMIN` and without
//! hitting the real conntrack table.

use sni_proxy::conntrack::__test_internals::{
    build_request_for_test, parse_orig_dst_for_test, synth_response_v4,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[test]
fn build_request_v4_has_expected_top_level_shape() {
    // Reply tuple = (listener=127.0.0.1:1500, child=127.0.0.1:33333), proto=UDP.
    let src: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1500));
    let dst: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 33333));
    let buf = build_request_for_test(src, dst, libc::IPPROTO_UDP as u8).unwrap();

    // First 4 bytes: nlmsg_len = total length, native byte order.
    let nlmsg_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
    assert_eq!(nlmsg_len, buf.len(), "nlmsg_len must match the buffer size");

    // Bytes 4..6: nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET
    //                       = (1 << 8) | 1 = 0x0101.
    let ty = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
    assert_eq!(
        ty, 0x0101,
        "nlmsg_type must encode (NFNL_SUBSYS_CTNETLINK<<8)|CT_GET = 0x0101"
    );

    // Bytes 6..8: NLM_F_REQUEST | NLM_F_ACK.
    let flags = u16::from_ne_bytes(buf[6..8].try_into().unwrap());
    let expected_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    assert_eq!(flags, expected_flags);

    // Byte 16 is nfgenmsg.nfgen_family. For a v4 lookup it must be AF_INET.
    assert_eq!(buf[16], libc::AF_INET as u8);

    // Sanity: the encoded request should be at least nlmsghdr (16) +
    // nfgenmsg (4) + nested CTA_TUPLE_REPLY large enough for a v4
    // tuple. The exact size depends on padding, but it's well above
    // 32 bytes.
    assert!(buf.len() > 32, "request unreasonably short: {} bytes", buf.len());
}

#[test]
fn build_request_v4_carries_dst_port_in_network_order() {
    // Use a port whose endianness is unambiguous: 0x1234 -> BE [0x12, 0x34].
    let src: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0x1234));
    let dst: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0x5678));
    let buf = build_request_for_test(src, dst, libc::IPPROTO_UDP as u8).unwrap();
    // Port bytes BE somewhere in the buffer. Looking for [0x12, 0x34]
    // and [0x56, 0x78] adjacently is sufficient — there's nothing
    // else in the encoded request that would produce those byte
    // pairs at a 4-aligned offset.
    let found_src_port = buf.windows(2).any(|w| w == [0x12, 0x34]);
    let found_dst_port = buf.windows(2).any(|w| w == [0x56, 0x78]);
    assert!(found_src_port, "src port 0x1234 not present in BE bytes");
    assert!(found_dst_port, "dst port 0x5678 not present in BE bytes");
}

#[test]
fn build_request_rejects_mixed_family() {
    let v4: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 100));
    let v6: SocketAddr = "[::1]:200".parse().unwrap();
    let err = build_request_for_test(v4, v6, libc::IPPROTO_UDP as u8)
        .expect_err("mixed-family tuple must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn parse_orig_dst_recovers_dst_from_synthetic_ct_new_response() {
    // Synthesise the response the kernel would send with a CT_NEW
    // message carrying CTA_TUPLE_ORIG. Dst = 203.0.113.42:88.
    let buf = synth_response_v4([203, 0, 113, 42], 88);
    let dst = parse_orig_dst_for_test(&buf).expect("parser must succeed");
    let expected: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 42), 88));
    assert_eq!(dst, expected);
}

#[test]
fn parse_orig_dst_returns_not_found_on_empty_buffer() {
    let err = parse_orig_dst_for_test(&[])
        .expect_err("empty response must surface as NotFound");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}
