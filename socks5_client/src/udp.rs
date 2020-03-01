use crate::types::{
    Address, Command, HandshakeRequest, HandshakeResponse, Reply, TcpRequestHeader,
    TcpResponseHeader, UdpAssociateHeader, SOCKS5_AUTH_METHOD_NONE,
};
use async_std::io;
use async_std::net::{TcpStream, UdpSocket};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::time::Duration;

pub struct Socks5UdpSocket {
    socket: UdpSocket,
    #[allow(dead_code)]
    associate_conn: TcpStream,
    buffer: Vec<u8>,
}

impl Socks5UdpSocket {
    pub async fn connect(socks5_server: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut conn =
            io::timeout(Duration::from_secs(1), TcpStream::connect(socks5_server)).await?;
        let handshake_req = HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_NONE]);
        handshake_req.write_to(&mut conn).await?;
        let handshake_resp = HandshakeResponse::read_from(&mut conn).await?;
        if handshake_resp.chosen_method != SOCKS5_AUTH_METHOD_NONE {
            return Err(Error::new(ErrorKind::InvalidData, "response methods error"));
        }
        let req_header = TcpRequestHeader::new(
            Command::UdpAssociate,
            Address::SocketAddress("0.0.0.0:0".parse().expect("never error")),
        );
        req_header.write_to(&mut conn).await?;
        let resp_header = TcpResponseHeader::read_from(&mut conn).await?;
        if resp_header.reply != Reply::Succeeded {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("reply error: {:?}", resp_header.reply),
            ));
        }
        let server_bind_addr = match resp_header.address {
            Address::SocketAddress(addr) => addr,
            Address::DomainNameAddress(_, _) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid udp bind addr, domain is not allowed",
                ));
            }
        };
        socket.connect(server_bind_addr).await?;
        Ok(Socks5UdpSocket {
            socket,
            associate_conn: conn,
            buffer: vec![0; 1500],
        })
    }

    pub async fn send_to(&mut self, buf: &[u8], addr: Address) -> Result<usize> {
        let udp_header = UdpAssociateHeader::new(0, addr);
        let mut size = 0;
        udp_header.write_to_buf(&mut self.buffer[size..].as_mut());
        size += udp_header.serialized_len();
        self.buffer[size..size + buf.len()].copy_from_slice(buf);
        size += buf.len();
        let send_size = self.socket.send(&self.buffer[..size]).await?;
        assert_eq!(send_size, size);
        Ok(buf.len())
    }

    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, Address)> {
        let size = self.socket.recv(&mut self.buffer).await?;
        let udp_header = UdpAssociateHeader::read_from(&mut self.buffer.as_slice()).await?;
        if udp_header.frag != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "frag is not allowed"));
        }
        let udp_header_len = udp_header.serialized_len();
        let addr = udp_header.address;
        buf[..size - udp_header_len].copy_from_slice(&self.buffer[udp_header_len..size]);
        Ok((size - udp_header_len, addr))
    }
}
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use async_std::task::block_on;
//     use std::str::FromStr;
//
//     #[test]
//     fn test_udp() -> Result<()> {
//         block_on(async {
//             let server = "127.0.0.1:1086".parse().unwrap();
//             let mut udp = Socks5UdpSocket::connect(server).await?;
//             let mut buf = vec![0; 1500];
//             let to_addr = Address::from_str("127.0.0.1:10240").unwrap();
//             let size = udp.send_to(b"hello", to_addr.clone()).await?;
//             let (s, addr) = udp.recv_from(&mut buf).await?;
//             assert_eq!(s, size);
//             assert_eq!(addr, to_addr);
//             assert_eq!(&buf[..s], b"hello");
//             Ok(())
//         })
//     }
// }
