use crate::phy::error;
use libc;
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

    pub fn name(&self) -> Result<String, error::Error> {
        self.tun.name()
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, error::Error> {
        self.tun.mtu()
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.tun.write4(src)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.tun.write6(src)
    }
}

impl Read for TunSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.tun.read(buf) {
            Ok(filled_buf) => Ok(filled_buf.len()),
            Err(error::Error::IfaceRead(errno)) => Err(io::Error::last_os_error()),
            Err(err) => panic!("unexpected error: {}", err),
        }
    }
}

impl Write for TunSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        Ok(self.write4(buf))
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
