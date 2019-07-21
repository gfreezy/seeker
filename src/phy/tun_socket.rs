use crate::phy::error;
use crate::phy::sys;
use smoltcp::phy;
use smoltcp::phy::{Device, DeviceCapabilities};
use smoltcp::time::Instant;
use std::cell::RefCell;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;

pub struct TunSocket {
    lower: Rc<RefCell<sys::TunSocket>>,
    mtu: usize,
    name: String,
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, error::Error> {
        let lower = sys::TunSocket::new(name)?;
        let mtu = lower.mtu()?;
        Ok(TunSocket {
            lower: Rc::new(RefCell::new(lower)),
            name: name.to_string(),
            mtu,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl<'a> Device<'a> for TunSocket {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; self.mtu];
        match lower.read(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken {
                    lower: self.lower.clone(),
                };
                Some((rx, tx))
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => None,
            Err(err) => panic!("{}", err),
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            lower: self.lower.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = self.mtu;
        cap
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower: Rc<RefCell<sys::TunSocket>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut lower = self.lower.borrow_mut();
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        lower.write(&buffer[..]).unwrap();
        result
    }
}
