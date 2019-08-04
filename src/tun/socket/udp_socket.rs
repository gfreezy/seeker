use crate::tun::socket::to_socket_addr;
use crate::tun::TUN;
use log::debug;
use smoltcp::socket::{SocketHandle, UdpSocket};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::{io, mem};
use tokio::prelude::task::current;
use tokio::prelude::{Async, AsyncRead, AsyncWrite, Future, Poll};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TunUdpSocket {
    pub(crate) handle: SocketHandle,
}

impl TunUdpSocket {
    pub fn new(handle: SocketHandle) -> Self {
        TunUdpSocket { handle }
    }

    pub fn poll_recv_from(&mut self, buf: &mut [u8]) -> Poll<(usize, SocketAddr), io::Error> {
        debug!("TunUdpSocket.read");
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<UdpSocket>(self.handle);
            if socket.can_recv() {
                let (size, endpoint) = socket
                    .recv_slice(buf)
                    .map_err(|e| -> io::Error { io::ErrorKind::Other.into() })?;
                Ok(Async::Ready((size, to_socket_addr(endpoint))))
            } else {
                let h = socket.handle();
                t.socket_read_tasks.insert(h, Some(current()));
                Err(io::ErrorKind::WouldBlock.into())
            }
        })
    }

    pub fn poll_send_to(&mut self, buf: &[u8], target: &SocketAddr) -> Poll<(), io::Error> {
        debug!("TunUdpSocket.write");
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<UdpSocket>(self.handle);
            if socket.can_send() {
                let endpoint = match target {
                    SocketAddr::V4(addr) => addr.clone().into(),
                    SocketAddr::V6(_) => unreachable!(),
                };
                socket
                    .send_slice(buf, endpoint)
                    .map_err(|e| -> io::Error { io::ErrorKind::Other.into() })?;
                if let Some(task) = t.tun_write_task.take() {
                    task.notify();
                }
                Ok(Async::Ready(()))
            } else {
                let h = socket.handle();
                t.socket_write_tasks.insert(h, Some(current()));
                Err(io::ErrorKind::WouldBlock.into())
            }
        })
    }

    pub fn recv_dgram<T>(self, buf: T) -> TunRecvDgram<T>
    where
        T: AsMut<[u8]>,
    {
        TunRecvDgram::new(self, buf)
    }

    pub fn send_dgram<T>(self, buf: T, addr: SocketAddr) -> TunSendDgram<T>
    where
        T: AsRef<[u8]>,
    {
        TunSendDgram::new(self, buf, addr)
    }
}

struct InnerTunRecvDgram<T> {
    socket: TunUdpSocket,
    buffer: T,
}

pub struct TunRecvDgram<T> {
    state: Option<InnerTunRecvDgram<T>>,
}

impl<T> TunRecvDgram<T> {
    fn new(socket: TunUdpSocket, buffer: T) -> Self {
        TunRecvDgram {
            state: Some(InnerTunRecvDgram { socket, buffer }),
        }
    }
}

impl<T> Future for TunRecvDgram<T>
where
    T: AsMut<[u8]>,
{
    type Item = (TunUdpSocket, T, usize, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, io::Error> {
        let mut state = self.state.take().expect("take state");
        let (n, addr) = try_ready!(state.socket.poll_recv_from(state.buffer.as_mut()));

        Ok(Async::Ready((state.socket, state.buffer, n, addr)))
    }
}

struct InnerTunSendDgram<T> {
    socket: TunUdpSocket,
    buffer: T,
    addr: SocketAddr,
}

pub struct TunSendDgram<T> {
    state: Option<InnerTunSendDgram<T>>,
}

impl<T> TunSendDgram<T> {
    fn new(socket: TunUdpSocket, buffer: T, addr: SocketAddr) -> Self {
        TunSendDgram {
            state: Some(InnerTunSendDgram {
                socket,
                buffer,
                addr,
            }),
        }
    }
}

impl<T> Future for TunSendDgram<T>
where
    T: AsRef<[u8]>,
{
    type Item = (TunUdpSocket, T);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut state = self.state.take().expect("take state");
        try_ready!(state
            .socket
            .poll_send_to(state.buffer.as_ref(), &state.addr));
        Ok(Async::Ready((state.socket, state.buffer)))
    }
}
