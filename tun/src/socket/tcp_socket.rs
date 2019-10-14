use crate::socket::to_socket_addr;
use crate::TUN;
use futures::{AsyncRead, AsyncWrite};
use smoltcp::socket::{SocketHandle, TcpSocket};
use std::io;
use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tracing::{debug, info};

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct TunTcpSocket {
    handle: SocketHandle,
}

impl TunTcpSocket {
    pub unsafe fn new(handle: SocketHandle) -> Self {
        debug!("TunTcpSocket.new: {}", handle);

        TunTcpSocket { handle }
    }

    pub fn local_addr(&self) -> SocketAddr {
        let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let socket = mut_tun.sockets.get::<TcpSocket>(self.handle);
        to_socket_addr(socket.local_endpoint())
    }

    pub fn remote_addr(&self) -> SocketAddr {
        let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let socket = mut_tun.sockets.get::<TcpSocket>(self.handle);
        to_socket_addr(socket.remote_endpoint())
    }

    pub fn handle(&self) -> SocketHandle {
        self.handle
    }
}

impl Clone for TunTcpSocket {
    fn clone(&self) -> Self {
        debug!("TunTcpSocket.clone: {}", self.handle);

        let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
        let mut_tun = guard.as_mut().expect("no tun setup");
        mut_tun.sockets.retain(self.handle);

        TunTcpSocket {
            handle: self.handle,
        }
    }
}

impl Drop for TunTcpSocket {
    fn drop(&mut self) {
        debug!("TunTcpSocket.drop: {}", self.handle);
        let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
        let mut_tun = guard.as_mut().expect("no tun setup");

        mut_tun.sockets.release(self.handle);
    }
}

impl AsyncRead for TunTcpSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let mut socket = mut_tun.sockets.get::<TcpSocket>(self.handle);
        debug!("TunTcpSocket.read socket state: {}", socket.state());
        if socket.may_recv() {
            if socket.can_recv() {
                let size = socket
                    .recv_slice(buf)
                    .map_err(|_| -> io::Error { io::ErrorKind::Other.into() })?;
                debug!(
                    "TunTcpSocket.read recv {} bytes",
                    size,
                    //                        std::str::from_utf8(buf).unwrap()
                );
                assert!(size > 0);
                Poll::Ready(Ok(size))
            } else {
                debug!("TunTcpSocket.read will block");
                let h = socket.handle();
                mut_tun
                    .socket_read_tasks
                    .insert(h, Some(cx.waker().clone()));
                Poll::Pending
            }
        } else {
            info!("read eof for tcp socket: {}", self.handle);
            Poll::Ready(Ok(0))
        }
    }
}

impl AsyncWrite for TunTcpSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        debug!("TunTcpSocket.write");
        let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let mut socket = mut_tun.sockets.get::<TcpSocket>(self.handle);
        if socket.may_send() {
            if socket.can_send() {
                let size = socket
                    .send_slice(buf)
                    .map_err(|_| -> io::Error { io::ErrorKind::Other.into() })?;
                debug!(
                    "TunTcpSocket.write send {} bytes",
                    size,
                    //                        std::str::from_utf8(buf).unwrap()
                );

                if let Some(waker) = mut_tun.tun_write_task.take() {
                    waker.wake();
                }
                Poll::Ready(Ok(size))
            } else {
                debug!("TunTcpSocket.write will block");
                let h = socket.handle();
                mut_tun
                    .socket_write_tasks
                    .insert(h, Some(cx.waker().clone()));
                Poll::Pending
            }
        } else {
            info!("write eof for tcp socket: {}", self.handle);
            Poll::Ready(Ok(0))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        debug!("flush");
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        debug!("close");
        Poll::Ready(Ok(()))
    }
}
