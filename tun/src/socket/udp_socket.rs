use crate::socket::to_socket_addr;
use crate::TUN;
use async_std::future::poll_fn;
use smoltcp::socket::{SocketHandle, UdpSocket};
use std::io;
use std::io::Result;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use std::time::Duration;
use tracing::debug;

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct TunUdpSocket {
    handle: SocketHandle,
}

impl TunUdpSocket {
    /// # Safety
    ///
    /// You need to make sure handle have at lease one reference.
    pub unsafe fn new(handle: SocketHandle) -> Self {
        debug!("TunUdpSocket.new: {}", handle);
        TunUdpSocket { handle }
    }

    pub fn handle(&self) -> SocketHandle {
        self.handle
    }

    pub fn local_addr(&self) -> SocketAddr {
        let mut guard = TUN.lock();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let socket = mut_tun.sockets.get::<UdpSocket>(self.handle);
        to_socket_addr(socket.endpoint())
    }

    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, SocketAddr)>> {
        debug!("TunUdpSocket.read");
        let mut guard = TUN.lock();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let mut socket = mut_tun.sockets.get::<UdpSocket>(self.handle);
        if socket.can_recv() {
            let (size, endpoint) = socket
                .recv_slice(buf)
                .map_err(|_| -> io::Error { io::ErrorKind::Other.into() })?;
            debug!("TunUdpSocket.read {} bytes", size);
            Poll::Ready(Ok((size, to_socket_addr(endpoint))))
        } else {
            let h = socket.handle();
            mut_tun
                .socket_read_tasks
                .insert(h, Some(cx.waker().clone()));
            debug!("TunUdpSocket.read blocks: {:?}", h);
            Poll::Pending
        }
    }

    pub fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<Result<usize>> {
        debug!("TunUdpSocket.write");
        let mut guard = TUN.lock();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let mut socket = mut_tun.sockets.get::<UdpSocket>(self.handle);
        if socket.can_send() {
            let endpoint = match target {
                SocketAddr::V4(addr) => addr.clone().into(),
                SocketAddr::V6(_) => unreachable!(),
            };
            socket
                .send_slice(buf, endpoint)
                .map_err(|_e| -> io::Error { io::ErrorKind::Other.into() })?;
            if let Some(waker) = mut_tun.tun_write_task.take() {
                waker.wake();
            }
            Poll::Ready(Ok(buf.len()))
        } else {
            let h = socket.handle();
            mut_tun
                .socket_write_tasks
                .insert(h, Some(cx.waker().clone()));
            Poll::Pending
        }
    }

    pub async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, addr)).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }
}

impl Clone for TunUdpSocket {
    fn clone(&self) -> Self {
        let mut guard = TUN.lock();
        let mut_tun = guard.as_mut().expect("no tun setup");
        mut_tun.sockets.retain(self.handle);
        TunUdpSocket {
            handle: self.handle,
        }
    }
}

impl Drop for TunUdpSocket {
    fn drop(&mut self) {
        debug!("TunUdpSocket.drop: {}", self.handle);
        let mut guard = TUN.lock();
        let mut_tun = guard.as_mut().expect("no tun setup");
        mut_tun.sockets.release(self.handle)
    }
}
