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
    recv_buf: Vec<u8>,
    decrypt_buf: BytesMut,
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
        let decrypt_buf = BytesMut::with_capacity(MAXIMUM_UDP_PAYLOAD_SIZE);
        let recv_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        Ok(SSUdpSocket {
            decrypt_buf,
            recv_buf,
            socket,
            method,
            key,
        })
    }
    pub fn bind(socket: UdpSocket, method: CipherType, key: Bytes) -> SSUdpSocket {
        let decrypt_buf = BytesMut::with_capacity(MAXIMUM_UDP_PAYLOAD_SIZE);
        let recv_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        SSUdpSocket {
            decrypt_buf,
            recv_buf,
            socket,
            method,
            key,
        }
    }

    /// Send a UDP packet to addr through proxy
    pub async fn send_to(&mut self, addr: &Address, payload: &[u8]) -> io::Result<()> {
        debug!(
            "UDP server client send to {}, payload length {} bytes",
            addr,
            payload.len()
        );

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::new();
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        let mut encrypt_buf = BytesMut::new();
        encrypt_payload(self.method, &self.key, &send_buf, &mut encrypt_buf)?;

        let send_len = self.socket.send(&encrypt_buf[..]).await?;

        assert_eq!(encrypt_buf.len(), send_len);

        Ok(())
    }

    /// Receive packet from Shadowsocks' UDP server
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(Address, usize)> {
        // Waiting for response from server SERVER -> CLIENT
        let recv_n = self.socket.recv(&mut self.recv_buf).await?;

        let decrypt_buf = &mut self.decrypt_buf;
        decrypt_buf.clear();
        let decrypt_size = decrypt_payload(
            self.method,
            &self.key,
            &self.recv_buf[..recv_n],
            decrypt_buf,
        )?;
        let addr = Address::read_from(&mut decrypt_buf.as_ref()).await?;
        let payload = &decrypt_buf[addr.serialized_len()..decrypt_size];
        buf[..payload.len()].copy_from_slice(payload);

        debug!(
            "UDP server client recv_from {}, payload length {} bytes",
            addr,
            payload.len()
        );

        Ok((addr, payload.len()))
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
        let addr = Address::DomainNameAddress("twitter.com".to_string(), 443);
        block_on(async {
            let key_clone = key.clone();
            let h = spawn(async move {
                let u = UdpSocket::bind("0.0.0.0:14188").await.unwrap();
                let mut udp = SSUdpSocket::bind(u, method, key_clone);
                let mut b = vec![0; 1024];
                let (_, s) = udp.recv_from(&mut b).await.unwrap();
                assert_eq!(&b[..s], data);
            });
            sleep(Duration::from_secs(1)).await;
            let mut udp = SSUdpSocket::new(server, method, key).await.unwrap();
            udp.send_to(&addr, data).await.unwrap();
            h.await;
        });
    }
}
