use async_std::net::driver::Watcher;
use futures::{AsyncRead, AsyncWrite};
use std::io;
use std::io::{Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

mod sys;

pub(crate) struct TunSocket {
    watcher: Watcher<sys::TunSocket>,
}

impl TunSocket {
    pub fn new(name: &str) -> TunSocket {
        TunSocket {
            watcher: Watcher::new(sys::TunSocket::new(name).expect("TunSocket::new")),
        }
    }
    pub fn name(&self) -> io::Result<String> {
        self.watcher.get_ref().name()
    }

    pub fn mtu(&self) -> io::Result<usize> {
        self.watcher.get_ref().mtu()
    }
}

impl AsyncRead for TunSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut &*self).poll_read(cx, buf)
    }
}

impl AsyncRead for &TunSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.watcher.poll_read_with(cx, |mut inner| inner.read(buf))
    }
}

impl AsyncWrite for TunSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut &*self).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut &*self).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut &*self).poll_close(cx)
    }
}

impl AsyncWrite for &TunSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.watcher
            .poll_write_with(cx, |mut inner| inner.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.watcher.poll_write_with(cx, |mut inner| inner.flush())
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::net::UdpSocket;
    use async_std::task::block_on;
    use futures::AsyncReadExt;
    use insta::assert_debug_snapshot;
    use sysconfig::setup_ip;

    #[test]
    fn test_recv_packets_from_tun() {
        let tun_name = "utun3";
        let mut tun_socket = TunSocket::new(tun_name);
        setup_ip(tun_name, "10.0.1.1", "10.0.1.0/24");

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 19];

        block_on(async move {
            let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            socket.send_to(&data, "10.0.1.2:80").await.unwrap();
            let mut buf = vec![0; 1024];
            let size = tun_socket.read(&mut buf).await.unwrap();

            assert_debug_snapshot!(&buf[(size - data.len())..size]);
        })
    }
}
