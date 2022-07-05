mod obfs_http;

use async_std::{
    io::{Read, Write},
    net::TcpStream,
};
use dyn_clone::DynClone;

use obfs_http::ObfsHttpTcpStream;
use serde::Deserialize;

use std::{
    fmt::Debug,
    io::{IoSlice, IoSliceMut, Result},
    net::SocketAddr,
    pin::Pin,
};

pub trait Connection: Read + Write + Unpin + Send + Sync + DynClone {}

dyn_clone::clone_trait_object!(Connection);

/// Combined async reader and writer, `futures 0.3` version.
/// Note that this struct is only present in `readwrite` if "asyncstd" Cargo feature is enabled.
#[derive(Clone)]
pub struct TcpConnection {
    inner: Box<dyn Connection>,
}

#[derive(Clone, Copy, PartialEq, Debug, Deserialize)]
pub enum ObfsMode {
    Http,
    // Ssl,
}

impl Connection for TcpStream {}

impl TcpConnection {
    pub async fn connect_obfs(
        addr: SocketAddr,
        host: String,
        mode: ObfsMode,
    ) -> std::io::Result<Self> {
        let conn = match mode {
            ObfsMode::Http => {
                Box::new(ObfsHttpTcpStream::connect(addr, host).await?) as Box<dyn Connection>
            }
        };

        Ok(TcpConnection { inner: conn })
    }

    pub async fn connect_tcp(addr: SocketAddr) -> std::io::Result<Self> {
        let conn = Box::new(TcpStream::connect(addr).await?);

        Ok(TcpConnection { inner: conn })
    }

    pub fn new(conn: TcpStream) -> Self {
        TcpConnection {
            inner: Box::new(conn),
        }
    }
}

impl Read for TcpConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_read_vectored(cx, bufs)
    }
}

impl Write for TcpConnection {
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
