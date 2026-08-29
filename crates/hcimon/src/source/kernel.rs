//! Linux kernel HCI monitor socket (`HCI_CHANNEL_MONITOR`).
//!
//! This is what BlueZ's btmon reads by default.  Every message carries a
//! 6-byte management header (`opcode`, `index`, `len`) followed by the
//! monitor packet; the kernel timestamp arrives as a `SCM_TIMESTAMP` control
//! message.  Requires `CAP_NET_RAW` (i.e. root or a capability grant).

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::thread::JoinHandle;

use anyhow::{bail, Context, Result};
use hcimon_capture::{Opcode, Packet, Timestamp};

use super::SourceCtx;

const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_HCI: libc::c_int = 1;
const HCI_DEV_NONE: u16 = 0xffff;
const HCI_CHANNEL_MONITOR: u16 = 2;
const MGMT_HDR_SIZE: usize = 6;

#[repr(C)]
struct SockaddrHci {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}

pub fn spawn(ctx: SourceCtx) -> Result<JoinHandle<()>> {
    let fd = open_monitor_socket()?;
    let thread = std::thread::Builder::new().name("kernel monitor".into()).spawn(move || run(ctx, fd))?;
    Ok(thread)
}

fn open_monitor_socket() -> Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the descriptor is wrapped in OwnedFd immediately.
    let raw = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI) };
    if raw < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EAFNOSUPPORT) || e.raw_os_error() == Some(libc::EPROTONOSUPPORT) {
            bail!("Bluetooth sockets are not available (is the bluetooth kernel module loaded?)");
        }
        return Err(e).context("failed to create HCI socket");
    }
    // SAFETY: raw is a valid, open descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let addr = SockaddrHci { hci_family: AF_BLUETOOTH as libc::sa_family_t, hci_dev: HCI_DEV_NONE, hci_channel: HCI_CHANNEL_MONITOR };
    // SAFETY: addr is a properly sized sockaddr for AF_BLUETOOTH.
    let rc = unsafe {
        libc::bind(fd.as_raw_fd(), &addr as *const SockaddrHci as *const libc::sockaddr, mem::size_of::<SockaddrHci>() as libc::socklen_t)
    };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::PermissionDenied {
            bail!("permission denied opening the HCI monitor socket (needs CAP_NET_RAW: run as root or `setcap cap_net_raw+ep`)");
        }
        return Err(e).context("failed to bind the HCI monitor channel");
    }
    let one: libc::c_int = 1;
    // SAFETY: standard setsockopt with an int option.
    unsafe {
        libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TIMESTAMP, &one as *const _ as *const libc::c_void, mem::size_of::<libc::c_int>() as libc::socklen_t);
        let tv = libc::timeval { tv_sec: 0, tv_usec: 100_000 };
        libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, mem::size_of::<libc::timeval>() as libc::socklen_t);
    }
    Ok(fd)
}

fn run(ctx: SourceCtx, fd: OwnedFd) {
    ctx.status("listening on the kernel HCI monitor socket");
    let mut buf = vec![0u8; MGMT_HDR_SIZE + hcimon_capture::MAX_PACKET_SIZE + 64];
    let mut control = [0u8; 256];
    while !ctx.stopped() {
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
        // SAFETY: msghdr is zero-initialised and then filled with valid pointers.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;
        // SAFETY: fd is open; msg points to buffers that outlive the call.
        let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => continue,
                _ => {
                    ctx.error(format!("monitor socket: {e}"));
                    return;
                }
            }
        }
        let n = n as usize;
        if n < MGMT_HDR_SIZE {
            continue;
        }
        let ts = timestamp_from_cmsg(&msg).unwrap_or_else(Timestamp::now);
        let opcode = u16::from_le_bytes([buf[0], buf[1]]);
        let index = u16::from_le_bytes([buf[2], buf[3]]);
        let len = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        let end = (MGMT_HDR_SIZE + len).min(n);
        let pkt = Packet { ts: Some(ts), index, opcode: Opcode::from_u16(opcode), drops: 0, data: buf[MGMT_HDR_SIZE..end].to_vec() };
        if !ctx.packet(pkt) {
            return;
        }
    }
    ctx.eof();
}

fn timestamp_from_cmsg(msg: &libc::msghdr) -> Option<Timestamp> {
    // SAFETY: the cmsg macros walk the control buffer that recvmsg filled.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMP {
                let tv = libc::CMSG_DATA(cmsg) as *const libc::timeval;
                let tv = std::ptr::read_unaligned(tv);
                return Some(Timestamp::from_timeval(tv.tv_sec as i64, tv.tv_usec as i64));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}
