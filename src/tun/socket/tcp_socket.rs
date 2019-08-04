use crate::tun::socket::to_socket_addr;
use crate::tun::TUN;
use log::debug;
use smoltcp::socket::{SocketHandle, TcpSocket};
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use tokio::prelude::task::current;
use tokio::prelude::{Async, AsyncRead, AsyncWrite};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TunTcpSocket {
    pub(crate) handle: SocketHandle,
}

impl TunTcpSocket {
    pub fn new(handle: SocketHandle) -> Self {
        TunTcpSocket { handle }
    }

    pub fn remote_addr(&self) -> SocketAddr {
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            to_socket_addr(socket.remote_endpoint())
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            to_socket_addr(socket.local_endpoint())
        })
    }
}

impl Read for TunTcpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug!("TunTcpSocket.read");
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            debug!("TunTcpSocket.read socket state: {}", socket.state());
            if socket.may_recv() {
                if socket.can_recv() {
                    let size = socket
                        .recv_slice(buf)
                        .map_err(|_| -> io::Error { io::ErrorKind::Other.into() })?;
                    Ok(size)
                } else {
                    debug!("TunTcpSocket.read will block");
                    let h = socket.handle();
                    t.socket_read_tasks.insert(h, Some(current()));
                    Err(io::ErrorKind::WouldBlock.into())
                }
            } else {
                Ok(0)
            }
        })
    }
}

impl Write for TunTcpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug!("TunTcpSocket.write");
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            if socket.can_send() {
                let size = socket
                    .send_slice(buf)
                    .map_err(|_| -> io::Error { io::ErrorKind::Other.into() })?;
                if let Some(task) = t.tun_write_task.take() {
                    task.notify();
                }
                Ok(size)
            } else {
                let h = socket.handle();
                t.socket_write_tasks.insert(h, Some(current()));
                Err(io::ErrorKind::WouldBlock.into())
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for TunTcpSocket {}
impl AsyncWrite for TunTcpSocket {
    fn shutdown(&mut self) -> Result<Async<()>, io::Error> {
        debug!("shutdown");
        Ok(Async::Ready(()))
    }
}
