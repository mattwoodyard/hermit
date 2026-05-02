//! Tests for `hermit::fdpass`. All items used here are part of
//! the public API; no `__test_internals` needed.

use hermit::fdpass::{close_fd, recv_fds, send_fds, socketpair};

#[test]
fn socketpair_roundtrip() {
    let (a, b) = socketpair().unwrap();

    // Create a pipe to get two fds to send
    let mut pipe_fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);

    send_fds(a, &pipe_fds).unwrap();
    let received = recv_fds(b, 2).unwrap();

    assert_eq!(received.len(), 2);
    // The received fds should be different numbers but refer to the same pipes.
    // Write on original pipe write end, read from received read end.
    let msg = b"hello";
    let written = unsafe {
        libc::write(pipe_fds[1], msg.as_ptr() as *const libc::c_void, msg.len())
    };
    assert_eq!(written, msg.len() as isize);

    let mut buf = [0u8; 5];
    let read = unsafe {
        libc::read(received[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    assert_eq!(read, msg.len() as isize);
    assert_eq!(&buf, msg);

    // Cleanup
    for fd in [a, b, pipe_fds[0], pipe_fds[1], received[0], received[1]] {
        close_fd(fd);
    }
}

#[test]
fn recv_fds_detects_closed_peer() {
    let (a, b) = socketpair().unwrap();
    close_fd(b); // close sender
    let result = recv_fds(a, 1);
    assert!(result.is_err());
    close_fd(a);
}

#[test]
fn recv_fds_rejects_short_cmsg_rather_than_aliasing_stdin() {
    // The motivating threat: the parent asks for `count = 2`
    // fds but the child only sends 1 (e.g. RLIMIT_NOFILE
    // during sendmsg, or a future bug that miscounts). Without
    // the cmsg_len check, the second slot would be zero and
    // the parent's downstream `from_raw_fd(0)` would alias
    // stdin. The check refuses with a clear error.
    let (a, b) = socketpair().unwrap();
    // Send exactly 1 fd (the read end of a pipe).
    let mut pipe_fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    send_fds(a, &pipe_fds[..1]).unwrap();

    // Receiver asks for 2 — cmsg_len won't match the requested
    // payload size, so recv_fds must error rather than return
    // a Vec with a zero in the second slot.
    let err = recv_fds(b, 2).unwrap_err().to_string();
    assert!(
        err.contains("expected exactly") || err.contains("CTRUNC"),
        "expected payload-size mismatch error, got: {err}"
    );

    for fd in [a, b, pipe_fds[0], pipe_fds[1]] {
        close_fd(fd);
    }
}

#[test]
fn recv_fds_rejects_long_cmsg_too() {
    // Symmetric guard: peer sends MORE fds than the receiver
    // asked for. We sized the cmsg buffer for `count` fds, so
    // either MSG_CTRUNC fires (kernel had to drop some) or the
    // payload-size check rejects. Either way the receiver must
    // not silently accept a partial read.
    let (a, b) = socketpair().unwrap();
    // Send 2 fds.
    let mut pipe_fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    send_fds(a, &pipe_fds).unwrap();

    // Receiver only asks for 1 — the buffer is sized for 1
    // fd, so the kernel either truncates (MSG_CTRUNC) or the
    // cmsg_len exceeds our expected payload.
    let err = recv_fds(b, 1).unwrap_err().to_string();
    assert!(
        err.contains("expected exactly") || err.contains("CTRUNC"),
        "expected truncation/size-mismatch error, got: {err}"
    );

    for fd in [a, b, pipe_fds[0], pipe_fds[1]] {
        close_fd(fd);
    }
}
