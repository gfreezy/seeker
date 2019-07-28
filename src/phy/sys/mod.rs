use crate::phy::error;
use libc;
use mio::unix::EventedFd;
use mio::{Evented, Poll, PollOpt, Ready, Token};
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod tun;
//
//#[cfg(target_os = "linux")]
//#[path = "tun_linux.rs"]
//pub mod tun;

pub fn errno_str() -> String {
    let strerr = unsafe { libc::strerror(*libc::__error()) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

pub(crate) struct TunSocket {
    tun: tun::TunSocket,
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, error::Error> {
        Ok(TunSocket {
            tun: tun::TunSocket::new(name)?,
        })
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, error::Error> {
        self.tun.mtu()
    }
}

impl Read for TunSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.tun.read(buf) {
            Ok(filled_buf) => Ok(filled_buf.len()),
            Err(error::Error::IfaceRead(_errno)) => Err(io::Error::last_os_error()),
            Err(err) => panic!("unexpected error: {}", err),
        }
    }
}

impl Write for TunSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        Ok(self.tun.write4(buf))
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

impl Evented for TunSocket {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.tun.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.tun.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.tun.as_raw_fd()).deregister(poll)
    }
}
