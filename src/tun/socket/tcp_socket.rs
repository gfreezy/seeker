use crate::tun::socket::to_socket_addr;
use crate::tun::TUN;
use smoltcp::socket::{SocketHandle, TcpSocket};
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use tokio::prelude::task::current;
use tokio::prelude::{Async, AsyncRead, AsyncWrite};
use tracing::{debug, info};

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct TunTcpSocket {
    pub(crate) handle: SocketHandle,
}

impl TunTcpSocket {
    pub fn new(handle: SocketHandle) -> Self {
        debug!("TunTcpSocket.new: {}", handle);

        TUN.with(|tun| {
            let mut s = tun.borrow_mut();
            let mut_tun = match *s {
                Some(ref mut tun) => tun,
                None => unreachable!(),
            };
            mut_tun.sockets.retain(handle)
        });

        TunTcpSocket { handle }
    }

    pub fn local_addr(&self) -> SocketAddr {
        TUN.with(|tun| {
            let mut s = tun.borrow_mut();
            let mut_tun = match *s {
                Some(ref mut tun) => tun,
                None => unreachable!(),
            };
            let socket = mut_tun.sockets.get::<TcpSocket>(self.handle);
            to_socket_addr(socket.local_endpoint())
        })
    }
}

impl Clone for TunTcpSocket {
    fn clone(&self) -> Self {
        debug!("TunTcpSocket.clone: {}", self.handle);
        TunTcpSocket::new(self.handle)
    }
}

impl Drop for TunTcpSocket {
    fn drop(&mut self) {
        debug!("TunTcpSocket.drop: {}", self.handle);
        TUN.with(|tun| {
            let mut s = tun.borrow_mut();
            let mut_tun = match *s {
                Some(ref mut tun) => tun,
                None => unreachable!(),
            };
            mut_tun.sockets.release(self.handle)
        })
    }
}

impl Read for TunTcpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TUN.with(|tun| {
            let mut s = tun.borrow_mut();
            let mut_tun = match *s {
                Some(ref mut tun) => tun,
                None => unreachable!(),
            };
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
                    Ok(size)
                } else {
                    debug!("TunTcpSocket.read will block");
                    let h = socket.handle();
                    mut_tun.socket_read_tasks.insert(h, Some(current()));
                    Err(io::ErrorKind::WouldBlock.into())
                }
            } else {
                info!("read eof for tcp socket: {}", self.handle);
                Ok(0)
            }
        })
    }
}

impl Write for TunTcpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug!("TunTcpSocket.write");
        TUN.with(|tun| {
            let mut s = tun.borrow_mut();
            let mut_tun = match *s {
                Some(ref mut tun) => tun,
                None => unreachable!(),
            };
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

                    if let Some(task) = mut_tun.tun_write_task.take() {
                        task.notify();
                    }
                    Ok(size)
                } else {
                    debug!("TunTcpSocket.write will block");
                    let h = socket.handle();
                    mut_tun.socket_write_tasks.insert(h, Some(current()));
                    Err(io::ErrorKind::WouldBlock.into())
                }
            } else {
                info!("write eof for tcp socket: {}", self.handle);
                Ok(0)
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
