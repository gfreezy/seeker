use crate::phy::error;
use crate::phy::sys;
use futures::{AsyncRead, AsyncWrite};
use romio::raw::PollEvented;
use smoltcp::phy;
use smoltcp::phy::{Device, DeviceCapabilities};
use smoltcp::time::Instant;
use std::cell::RefCell;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::process::Command;
use std::rc::Rc;
use std::task::{Context, Poll};

pub struct TunSocket {
    io: PollEvented<sys::TunSocket>,
    mtu: usize,
    name: String,
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, error::Error> {
        let lower = sys::TunSocket::new(name)?;
        let mtu = lower.mtu()?;
        Ok(TunSocket {
            io: PollEvented::new(lower),
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

impl AsyncRead for TunSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_close(cx)
    }
}
