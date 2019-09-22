use super::error;
use super::sys;

use std::io;
use std::io::{Read, Write};
use tokio::io::AsyncRead;
use tokio::prelude::{Async, AsyncWrite};
use tokio::reactor::PollEvented2;

pub struct TunSocket {
    io: PollEvented2<sys::TunSocket>,
    mtu: usize,
    name: String,
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, error::Error> {
        let lower = sys::TunSocket::new(name)?;
        let mtu = lower.mtu()?;
        Ok(TunSocket {
            io: PollEvented2::new(lower),
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

impl Read for TunSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.io.read(buf)
    }
}

impl Write for TunSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.io.flush()
    }
}

impl AsyncRead for TunSocket {
    fn poll_read(&mut self, buf: &mut [u8]) -> Result<Async<usize>, io::Error> {
        self.io.poll_read(buf)
    }
}

impl AsyncWrite for TunSocket {
    fn poll_write(&mut self, buf: &[u8]) -> Result<Async<usize>, io::Error> {
        self.io.poll_write(buf)
    }

    fn poll_flush(&mut self) -> Result<Async<()>, io::Error> {
        self.io.poll_flush()
    }

    fn shutdown(&mut self) -> Result<Async<()>, io::Error> {
        self.io.shutdown()
    }
}
