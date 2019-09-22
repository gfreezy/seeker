//! Relay for UDP implementation
//!
//! ## ShadowSocks UDP protocol
//!
//! SOCKS5 UDP Request
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//!
//! SOCKS5 UDP Response
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//!
//! shadowsocks UDP Request (before encrypted)
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//!
//! shadowsocks UDP Response (before encrypted)
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//!
//! shadowsocks UDP Request and Response (after encrypted)
//! +-------+--------------+
//! |   IV  |    PAYLOAD   |
//! +-------+--------------+
//! | Fixed |   Variable   |
//! +-------+--------------+

use std::{io, net::SocketAddr};

use crate::tun::socket::TunUdpSocket;
use futures::{try_ready, Async, Poll, Stream};

/// The maximum UDP payload size (defined in the original shadowsocks Python)
///
/// *I cannot find any references about why clowwindy used this value as the maximum
/// Socks5 UDP ASSOCIATE packet size. The only thing I can find is
/// [here](http://support.microsoft.com/kb/822061/)*
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

/// UDP `recv_from` stream
pub struct PacketStream {
    udp: TunUdpSocket,
    buf: [u8; MAXIMUM_UDP_PAYLOAD_SIZE],
}

impl PacketStream {
    /// Creates a new `PacketStream`
    pub fn new(udp: TunUdpSocket) -> PacketStream {
        PacketStream {
            udp,
            buf: [0u8; MAXIMUM_UDP_PAYLOAD_SIZE],
        }
    }
}

impl Stream for PacketStream {
    type Item = (Vec<u8>, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let (n, addr) = try_ready!(self.udp.poll_recv_from(&mut self.buf));
        Ok(Async::Ready(Some((self.buf[..n].to_vec(), addr))))
    }
}
