//! File descriptor passing over Unix socketpairs via SCM_RIGHTS.
//!
//! Used to transfer listener sockets created in the child's network
//! namespace back to the parent, where the SNI proxy and DNS server run.

use anyhow::{bail, Result};
use std::os::unix::io::RawFd;

/// Create a Unix socketpair for fd passing. Returns (parent_fd, child_fd).
///
/// Both ends are SOCK_STREAM with O_CLOEXEC.
pub fn socketpair() -> Result<(RawFd, RawFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if ret < 0 {
        bail!("socketpair failed: {}", std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

/// Send file descriptors over a Unix socket using SCM_RIGHTS.
pub fn send_fds(sock: RawFd, fds: &[RawFd]) -> Result<()> {
    let data = [0u8; 1]; // sendmsg requires at least 1 byte of data
    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let fds_size = std::mem::size_of_val(fds);
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_size as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fds_size as u32) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(cmsg) as *mut RawFd,
            fds.len(),
        );
    }

    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    if ret < 0 {
        bail!("sendmsg(SCM_RIGHTS) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Receive file descriptors from a Unix socket using SCM_RIGHTS.
///
/// `count` is the number of fds expected.
pub fn recv_fds(sock: RawFd, count: usize) -> Result<Vec<RawFd>> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let fds_size = count * std::mem::size_of::<RawFd>();
    let cmsg_space = unsafe { libc::CMSG_SPACE(fds_size as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if ret < 0 {
        bail!("recvmsg(SCM_RIGHTS) failed: {}", std::io::Error::last_os_error());
    }
    if ret == 0 {
        bail!("recvmsg: peer closed before sending fds");
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        bail!("recvmsg: no control message received");
    }

    unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            bail!(
                "recvmsg: unexpected cmsg level={} type={}",
                (*cmsg).cmsg_level,
                (*cmsg).cmsg_type
            );
        }
    }

    let mut fds = vec![0i32; count];
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg) as *const RawFd,
            fds.as_mut_ptr(),
            count,
        );
    }

    Ok(fds)
}

/// Close a raw fd, ignoring errors.
pub fn close_fd(fd: RawFd) {
    unsafe { libc::close(fd) };
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
