//! UDP relay client
pub mod crypto_io;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use bytes::{Bytes, BytesMut};
use tracing::debug;

use self::crypto_io::{decrypt_payload, encrypt_payload};

use async_std::net::UdpSocket;
use config::Address;
use crypto::CipherType;

pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 1500;

/// UDP client for communicating with ShadowSocks' server
pub struct SSUdpSocket {
    socket: UdpSocket,
    method: CipherType,
    key: Bytes,
}

impl SSUdpSocket {
    /// Create a client to communicate with Shadowsocks' UDP server
    pub async fn new(
        server_addr: SocketAddr,
        method: CipherType,
        key: Bytes,
    ) -> io::Result<SSUdpSocket> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(server_addr).await?;

        Ok(SSUdpSocket {
            socket,
            method,
            key,
        })
    }

    pub fn bind(socket: UdpSocket, method: CipherType, key: Bytes) -> SSUdpSocket {
        SSUdpSocket {
            socket,
            method,
            key,
        }
    }

    /// Send a UDP packet to addr through proxy
    pub async fn send_to(&self, payload: &[u8], sock_addr: SocketAddr) -> io::Result<usize> {
        let addr: Address = sock_addr.into();
        debug!(
            "UDP server client send to {}, payload length {} bytes",
            addr,
            payload.len()
        );

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::with_capacity(addr.serialized_len() + payload.len());
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        let mut encrypt_buf = BytesMut::with_capacity(MAXIMUM_UDP_PAYLOAD_SIZE);
        encrypt_payload(self.method, &self.key, &send_buf, &mut encrypt_buf)?;

        let send_len = self.socket.send(&encrypt_buf[..]).await?;

        assert_eq!(encrypt_buf.len(), send_len);

        Ok(payload.len())
    }

    /// Receive packet from Shadowsocks' UDP server
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Waiting for response from server SERVER -> CLIENT
        let mut recv_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        let recv_n = self.socket.recv(&mut recv_buf).await?;
        let mut decrypt_buf = BytesMut::with_capacity(MAXIMUM_UDP_PAYLOAD_SIZE);

        let decrypt_size = decrypt_payload(
            self.method,
            &self.key,
            &recv_buf[..recv_n],
            &mut decrypt_buf,
        )?;
        let addr = Address::read_from(&mut decrypt_buf.as_ref()).await?;
        let payload = &decrypt_buf[addr.serialized_len()..decrypt_size];
        buf[..payload.len()].copy_from_slice(payload);

        debug!(
            "UDP server client recv_from {}, payload length {} bytes",
            addr,
            payload.len()
        );

        let sock_addr = match addr {
            Address::SocketAddress(s) => s,
            Address::DomainNameAddress(_, _) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid addr format",
                ))
            }
        };
        Ok((payload.len(), sock_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task::{block_on, sleep, spawn};
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    #[test]
    fn test_read_write() {
        let method = CipherType::ChaCha20Ietf;
        let password = "GwEU01uXWm0Pp6t08";
        let key = method.bytes_to_key(password.as_bytes());
        let server = "127.0.0.1:14188".to_socket_addrs().unwrap().next().unwrap();
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let addr = "127.0.0.1:443".parse().unwrap();
        block_on(async {
            let key_clone = key.clone();
            let h = spawn(async move {
                let u = UdpSocket::bind("0.0.0.0:14188").await.unwrap();
                let udp = SSUdpSocket::bind(u, method, key_clone);
                let mut b = vec![0; 1024];
                let (s, _) = udp.recv_from(&mut b).await.unwrap();
                assert_eq!(&b[..s], data);
            });
            sleep(Duration::from_secs(1)).await;
            let udp = SSUdpSocket::new(server, method, key).await.unwrap();
            udp.send_to(data, addr).await.unwrap();
            h.await;
        });
    }
}
