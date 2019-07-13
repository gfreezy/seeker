use crate::device::error;
use crate::device::sys;
use futures::{AsyncRead, AsyncWrite};
use romio::raw::PollEvented;
use romio::raw::{AsyncReadReady, AsyncWriteReady};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct TunSocket {
    io: PollEvented<sys::TunSocket>,
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, error::Error> {
        Ok(TunSocket {
            io: PollEvented::new(sys::TunSocket::new(name)?),
        })
    }

    pub fn name(&self) -> Result<String, error::Error> {
        self.io.get_ref().name()
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, error::Error> {
        self.io.get_ref().mtu()
    }
}

impl AsyncRead for TunSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
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

impl AsyncReadReady for TunSocket {
    type Ok = mio::Ready;
    type Err = io::Error;

    fn poll_read_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Ok, Self::Err>> {
        Pin::new(&mut self.io).poll_read_ready(cx)
    }
}

impl AsyncWriteReady for TunSocket {
    type Ok = mio::Ready;
    type Err = io::Error;

    fn poll_write_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Ok, Self::Err>> {
        self.io.poll_write_ready(cx)
    }
}
