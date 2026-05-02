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
/// `count` is the **exact** number of fds the caller expects. The
/// function fails (rather than silently returning fewer / zero-fds)
/// if the kernel delivered a different count or set MSG_CTRUNC.
///
/// Why exact-match matters: without the cmsg_len check, a short
/// cmsg (e.g. peer hit RLIMIT_NOFILE during sendmsg) would leave
/// the trailing entries of the output `Vec<i32>` as zeros. A
/// downstream `from_raw_fd(0)` then aliases the caller's stdin —
/// invisible until the caller writes "data" to what they think is
/// a network listener and corrupts their own terminal.
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

    // MSG_CTRUNC means the cmsg buffer wasn't large enough and the
    // kernel dropped fds (closing them, for SCM_RIGHTS). Either we
    // sized the buffer wrong (a bug) or the peer sent more fds
    // than asked — either way, refuse rather than guess which fds
    // we got.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!(
            "recvmsg: cmsg buffer was truncated (MSG_CTRUNC); some fds dropped"
        );
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        bail!("recvmsg: no control message received");
    }

    let (cmsg_len, level, ty) = unsafe {
        ((*cmsg).cmsg_len as usize, (*cmsg).cmsg_level, (*cmsg).cmsg_type)
    };
    if level != libc::SOL_SOCKET || ty != libc::SCM_RIGHTS {
        bail!("recvmsg: unexpected cmsg level={level} type={ty}");
    }

    // The cmsg's payload size is `cmsg_len - CMSG_LEN(0)`; require
    // it to be exactly `count * sizeof(RawFd)`. Anything else means
    // we'd be reading garbage (short cmsg) or leaving bytes in the
    // buffer (long cmsg, peer sent more than expected).
    let header_overhead = unsafe { libc::CMSG_LEN(0) } as usize;
    let payload_len = cmsg_len.checked_sub(header_overhead).ok_or_else(|| {
        anyhow::anyhow!("recvmsg: cmsg_len={cmsg_len} < CMSG_LEN(0)={header_overhead}")
    })?;
    if payload_len != fds_size {
        bail!(
            "recvmsg: SCM_RIGHTS payload is {payload_len} bytes; expected exactly {fds_size} \
             ({count} fds * {} bytes/fd) — refusing to read past or short of the cmsg",
            std::mem::size_of::<RawFd>()
        );
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

