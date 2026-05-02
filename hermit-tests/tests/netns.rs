//! Tests for `hermit::netns`.
//!
//! Reaches into private items via `hermit::netns::__test_internals`
//! (only available because hermit-tests turns on the
//! `__test_internals` feature).

use hermit::netns::__test_internals::{
    check_netlink_acks, hermit_table, output_chain, set_interface_up, TABLE_NAME,
};
use rustables::{
    expr::{Immediate, Nat, NatType, Register},
    ChainType, Protocol, ProtocolFamily, Rule,
};

#[test]
fn table_descriptor_has_expected_name() {
    let t = hermit_table();
    assert_eq!(t.get_name().map(|s| s.as_str()), Some(TABLE_NAME));
}

#[test]
fn output_chain_descriptor_is_nat_on_output_hook() {
    let t = hermit_table();
    let c = output_chain(&t);
    assert_eq!(c.get_name().map(|s| s.as_str()), Some("output"));
    assert_eq!(c.get_type(), Some(&ChainType::Nat));
    let hook = c.get_hook().expect("hook set");
    // get_class returns the raw NF_INET_LOCAL_OUT value, not the enum.
    assert_eq!(hook.get_class().copied(), Some(libc::NF_INET_LOCAL_OUT as u32));
}

#[test]
fn redirect_rule_builds_without_error() {
    // We can construct the rule descriptor without touching the kernel.
    // Sending the batch would need CAP_NET_ADMIN; we don't do that here.
    let t = hermit_table();
    let c = output_chain(&t);
    let r = Rule::new(&c)
        .expect("rule constructor")
        .dport(443, Protocol::TCP)
        .with_expr(Immediate::new_data(vec![127, 0, 0, 1], Register::Reg1))
        .with_expr(Immediate::new_data(1443u16.to_be_bytes().to_vec(), Register::Reg2))
        .with_expr(
            Nat::default()
                .with_nat_type(NatType::DNat)
                .with_family(ProtocolFamily::Ipv4)
                .with_ip_register(Register::Reg1)
                .with_port_register(Register::Reg2),
        );
    // Non-empty expression list == builder succeeded.
    assert!(r.get_expressions().is_some());
}

#[test]
fn set_interface_up_rejects_long_name() {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(sock >= 0);
    let long_name = "a".repeat(libc::IFNAMSIZ + 1);
    let result = set_interface_up(sock, &long_name);
    unsafe { libc::close(sock) };
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too long"));
}

#[test]
fn set_interface_up_fails_on_nonexistent_interface() {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(sock >= 0);
    let result = set_interface_up(sock, "hermittest0");
    unsafe { libc::close(sock) };
    // Should fail — interface doesn't exist
    assert!(result.is_err());
}

// --- check_netlink_acks fixture tests --------------------------------
//
// The function walks a netlink response buffer looking for nlmsgerr
// entries. Each kernel message starts with a 16-byte nlmsghdr:
//   u32 nlmsg_len  (total length including header, native-endian)
//   u16 nlmsg_type
//   u16 nlmsg_flags
//   u32 nlmsg_seq
//   u32 nlmsg_pid
// For NLMSG_ERROR (type=0x2) the payload is i32 error followed by
// the original request header. Messages are 4-byte aligned.

fn nlmsg_header(len: u32, msg_type: u16) -> [u8; 16] {
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&len.to_ne_bytes());
    hdr[4..6].copy_from_slice(&msg_type.to_ne_bytes());
    // flags, seq, pid all zero — irrelevant to the parser
    hdr
}

fn nlmsgerr(error_code: i32) -> Vec<u8> {
    // Header (len=20) + i32 error. We omit the original request
    // header that real nlmsgerr carries; the parser only reads the
    // first 4 bytes of payload.
    let mut buf = nlmsg_header(20, libc::NLMSG_ERROR as u16).to_vec();
    buf.extend_from_slice(&error_code.to_ne_bytes());
    buf
}

fn nlmsg_success(payload_len: usize, msg_type: u16) -> Vec<u8> {
    let len = 16 + payload_len;
    let mut buf = nlmsg_header(len as u32, msg_type).to_vec();
    buf.extend(std::iter::repeat(0u8).take(payload_len));
    buf
}

#[test]
fn check_netlink_acks_accepts_success_ack() {
    // error=0 means the kernel acknowledged the request.
    let buf = nlmsgerr(0);
    check_netlink_acks(&buf).expect("error=0 ack must pass");
}

#[test]
fn check_netlink_acks_returns_error_for_negative_errno() {
    // Kernel reports negative errno; -EEXIST = -17.
    let buf = nlmsgerr(-(libc::EEXIST));
    let err = check_netlink_acks(&buf).expect_err("nonzero errno must fail");
    let msg = err.to_string();
    assert!(msg.contains("nftables netlink error"), "got: {msg}");
    // The os_error formatting for EEXIST mentions "exists".
    assert!(msg.to_lowercase().contains("exist"), "got: {msg}");
}

#[test]
fn check_netlink_acks_walks_multipart_to_first_error() {
    // Two success ACKs followed by an error must surface the error.
    let mut buf = nlmsgerr(0);
    buf.extend(nlmsgerr(0));
    buf.extend(nlmsgerr(-(libc::EINVAL)));
    let err = check_netlink_acks(&buf)
        .expect_err("error in third position must surface");
    assert!(err.to_string().contains("nftables netlink error"));
}

#[test]
fn check_netlink_acks_passes_all_success_multipart() {
    let mut buf = nlmsgerr(0);
    buf.extend(nlmsgerr(0));
    buf.extend(nlmsgerr(0));
    check_netlink_acks(&buf).expect("all-success multipart must pass");
}

#[test]
fn check_netlink_acks_handles_truncated_below_header() {
    // Fewer than 16 bytes — no message can be parsed; treat as empty.
    check_netlink_acks(&[]).expect("empty buffer is ok");
    check_netlink_acks(&[0u8; 8]).expect("under-header buffer is ok");
    check_netlink_acks(&[0u8; 15]).expect("one-byte-short buffer is ok");
}

#[test]
fn check_netlink_acks_stops_on_truncated_message_body() {
    // Header advertises 64 bytes but buffer is only 32 — parser must
    // bail out of the loop without panicking.
    let mut buf = nlmsg_header(64, libc::NLMSG_ERROR as u16).to_vec();
    buf.extend(std::iter::repeat(0u8).take(16)); // total 32 bytes
    check_netlink_acks(&buf).expect("truncated body must be skipped");
}

#[test]
fn check_netlink_acks_stops_on_truncated_error_payload() {
    // NLMSG_ERROR header advertising len=20 (header + 4-byte errno),
    // but the buffer cuts off after the header — no errno to read.
    let buf = nlmsg_header(20, libc::NLMSG_ERROR as u16).to_vec();
    // buf is exactly 16 bytes; parser sees nlmsg_len=20 > buf.len()=16
    // and breaks before touching the payload.
    check_netlink_acks(&buf).expect("missing errno payload must be skipped");
}

#[test]
fn check_netlink_acks_skips_non_error_messages() {
    // A success-typed message (e.g. NLMSG_DONE) should be walked past
    // without being interpreted as an errno.
    let mut buf = nlmsg_success(4, libc::NLMSG_DONE as u16);
    buf.extend(nlmsgerr(0));
    check_netlink_acks(&buf).expect("non-error messages must be skipped");
}

#[test]
fn check_netlink_acks_aligns_message_offsets_to_4_bytes() {
    // A message of length 17 should advance the cursor to offset 20
    // (next 4-byte boundary) before reading the next header.
    let mut buf = nlmsg_header(17, libc::NLMSG_DONE as u16).to_vec();
    buf.extend_from_slice(&[0u8]); // 1 payload byte → total 17
    buf.extend_from_slice(&[0u8; 3]); // 3 bytes of padding to 4-byte boundary
    // Now an error message at offset 20.
    buf.extend(nlmsgerr(-(libc::EPERM)));
    let err = check_netlink_acks(&buf)
        .expect_err("error after misaligned message must still surface");
    assert!(err.to_string().contains("nftables netlink error"));
}

#[test]
fn check_netlink_acks_rejects_undersized_nlmsg_len() {
    // nlmsg_len < NLMSG_HDR_LEN (16) is malformed — parser must not
    // loop forever on a zero-length advance.
    let buf = nlmsg_header(8, libc::NLMSG_ERROR as u16).to_vec();
    check_netlink_acks(&buf).expect("undersized nlmsg_len must be skipped");
}
