use smoltcp::wire::{IpAddress, IpEndpoint};
use std::net::{Ipv4Addr, SocketAddr};

fn to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    match endpoint.addr {
        IpAddress::Ipv4(addr) => {
            let a: Ipv4Addr = addr.into();
            (a, endpoint.port).into()
        }
        _ => unreachable!(),
    }
}

mod tcp_socket;
mod udp_socket;

use smoltcp::socket::SocketHandle;
use std::fmt;
use std::fmt::Display;
pub use tcp_socket::TunTcpSocket;
pub use udp_socket::TunUdpSocket;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum TunSocket {
    Tcp(TunTcpSocket),
    Udp(TunUdpSocket),
}

impl TunSocket {
    pub unsafe fn new_tcp_socket(handle: SocketHandle) -> TunSocket {
        TunSocket::Tcp(TunTcpSocket::new(handle))
    }

    pub unsafe fn new_udp_socket(handle: SocketHandle) -> TunSocket {
        TunSocket::Udp(TunUdpSocket::new(handle))
    }

    pub fn handle(&self) -> SocketHandle {
        match self {
            TunSocket::Tcp(s) => s.handle(),
            TunSocket::Udp(s) => s.handle(),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        match self {
            TunSocket::Tcp(s) => s.local_addr(),
            TunSocket::Udp(s) => s.local_addr(),
        }
    }
}

impl Display for TunSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
