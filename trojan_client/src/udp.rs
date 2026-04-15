use crate::protocol::{
    decode_udp_packet, encode_trojan_request, encode_udp_packet, hash_password, CMD_UDP_ASSOCIATE,
};
use bytes::BytesMut;
use config::Address;
use rustls::pki_types::ServerName;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tcp_connection::tls::get_tls_connector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub struct TrojanUdpSocket {
    conn: Arc<Mutex<TlsStream<TcpStream>>>,
}

impl TrojanUdpSocket {
    pub async fn new(
        server: SocketAddr,
        sni: &str,
        password: &str,
        insecure: bool,
    ) -> Result<Self> {
        let connector = get_tls_connector(insecure);
        Self::new_with_connector(server, sni, password, connector).await
    }

    pub async fn new_with_connector(
        server: SocketAddr,
        sni: &str,
        password: &str,
        connector: TlsConnector,
    ) -> Result<Self> {
        let tcp_stream = TcpStream::connect(server).await?;
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid SNI: {e}")))?;
        let mut tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(Error::other)?;

        // Send UDP ASSOCIATE request with dummy address 0.0.0.0:0
        let password_hash = hash_password(password);
        let dummy_addr = Address::SocketAddress(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
        ));
        let mut buf = BytesMut::with_capacity(128);
        encode_trojan_request(&password_hash, CMD_UDP_ASSOCIATE, &dummy_addr, &mut buf);
        tls_stream.write_all(&buf).await?;

        Ok(TrojanUdpSocket {
            conn: Arc::new(Mutex::new(tls_stream)),
        })
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        let mut packet = BytesMut::new();
        encode_udp_packet(&Address::SocketAddress(addr), buf, &mut packet);
        let mut conn = self.conn.lock().await;
        conn.write_all(&packet).await?;
        conn.flush().await?;
        Ok(buf.len())
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut conn = self.conn.lock().await;
        let mut read_buf = vec![0u8; 4096];
        let n = conn.read(&mut read_buf).await?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "connection closed"));
        }

        let (addr, payload, _consumed) = decode_udp_packet(&read_buf[..n])?;
        let copy_len = payload.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&payload[..copy_len]);

        let socket_addr = match addr {
            Address::SocketAddress(sa) => sa,
            Address::DomainNameAddress(_, _) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "expected socket address in UDP response",
                ));
            }
        };

        Ok((copy_len, socket_addr))
    }
}
