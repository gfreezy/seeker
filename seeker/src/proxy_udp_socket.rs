use async_std::net::{SocketAddr, UdpSocket};
use socks5_client::Socks5UdpSocket;
use ssclient::SSUdpSocket;
use std::io;
use std::sync::Arc;

#[derive(Clone)]
pub enum ProxyUdpSocket {
    Direct(Arc<UdpSocket>),
    Socks5(Arc<Socks5UdpSocket>),
    Shadowsocks(Arc<SSUdpSocket>),
}

impl ProxyUdpSocket {
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match self {
            ProxyUdpSocket::Direct(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocket::Socks5(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocket::Shadowsocks(socket) => socket.send_to(buf, addr).await,
        }
    }
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            ProxyUdpSocket::Direct(socket) => socket.recv_from(buf).await,
            ProxyUdpSocket::Socks5(socket) => socket.recv_from(buf).await,
            ProxyUdpSocket::Shadowsocks(socket) => socket.recv_from(buf).await,
        }
    }
}
