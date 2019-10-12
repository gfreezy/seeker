const MAX_PACKET_SIZE: usize = 0x3FFF;

mod ahead;

use crate::ahead::{aead_decrypted_read, aead_encrypted_write};
use async_std::future;
use async_std::io::timeout;
use async_std::net::TcpStream;
use bytes::{Bytes, BytesMut};
use config::{Address, ServerAddr, ServerConfig};
use crypto::{CipherCategory, CryptoMode};
use futures::io::ErrorKind;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
use std::io;
use std::io::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;
use tun::socket::TunUdpSocket;

#[derive(Clone)]
pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    dns_server: (String, u16),
    resolver: Arc<DnsNetworkClient>,
}

impl SSClient {
    pub async fn new(server_config: Arc<ServerConfig>, dns_server: (String, u16)) -> SSClient {
        SSClient {
            srv_cfg: server_config,
            resolver: Arc::new(DnsNetworkClient::new(0).await),
            dns_server,
        }
    }

    async fn handle_aead_recv<T: AsyncRead + Clone + Unpin>(
        &self,
        mut conn: &TcpStream,
        mut socket: T,
        addr: Address,
    ) -> Result<()> {
        let cipher_type = self.srv_cfg.method();
        let key = self.srv_cfg.key();
        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut dst = vec![0; MAX_PACKET_SIZE];

        let iv = send_iv(conn, self.srv_cfg.clone()).await?;
        let mut cipher = crypto::new_aead_encryptor(cipher_type, key, &iv);

        let mut addr_bytes = BytesMut::with_capacity(100);
        addr.write_to_buf(&mut addr_bytes);
        let mut offset = addr_bytes.len();
        buf[..offset].copy_from_slice(&addr_bytes);
        loop {
            let size = socket.read(&mut buf[offset..]).await?;
            if size == 0 {
                break;
            }
            let s =
                aead_encrypted_write(&mut cipher, &buf[..offset + size], &mut dst, cipher_type)?;
            conn.write_all(&dst[..s]).await?;
            offset = 0;
        }
        Ok(())
    }

    async fn handle_aead_send<T: AsyncWrite + Clone + Unpin>(
        &self,
        conn: &TcpStream,
        mut socket: T,
        _addr: Address,
    ) -> Result<()> {
        let cipher_type = self.srv_cfg.method();
        let key = self.srv_cfg.key();

        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut output = vec![0; MAX_PACKET_SIZE];
        let iv = recv_iv(conn, self.srv_cfg.clone()).await?;
        let mut cipher = crypto::new_aead_decryptor(cipher_type, key, &iv);

        loop {
            let size =
                aead_decrypted_read(&mut cipher, conn, &mut buf, &mut output, cipher_type).await?;
            if size == 0 {
                break;
            }
            socket.write_all(&output[..size]).await?;
        }
        Ok(())
    }

    async fn handle_stream_send<T: AsyncRead + Clone + Unpin>(
        &self,
        mut conn: &TcpStream,
        mut socket: T,
        addr: Address,
    ) -> Result<()> {
        let cipher_type = self.srv_cfg.method();
        let key = self.srv_cfg.key();
        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut dst = BytesMut::with_capacity(MAX_PACKET_SIZE);

        let iv = send_iv(conn, self.srv_cfg.clone()).await?;
        let mut cipher = crypto::new_stream(cipher_type, key, &iv, CryptoMode::Encrypt);

        let mut addr_bytes = BytesMut::with_capacity(100);
        addr.write_to_buf(&mut addr_bytes);
        let mut offset = addr_bytes.len();
        buf[..offset].copy_from_slice(&addr_bytes);
        loop {
            let size = timeout(Duration::from_secs(1), socket.read(&mut buf[offset..])).await?;
            if size == 0 {
                break;
            }
            dst.clear();
            dst.reserve(cipher.buffer_size(&buf[..offset + size]));

            cipher.update(&buf[..offset + size], &mut dst)?;
            timeout(Duration::from_secs(1), conn.write_all(&dst)).await?;
            offset = 0;
        }
        Ok(())
    }

    async fn handle_stream_recv<T: AsyncWrite + Clone + Unpin>(
        &self,
        mut conn: &TcpStream,
        mut socket: T,
        _addr: Address,
    ) -> Result<()> {
        let cipher_type = self.srv_cfg.method();
        let key = self.srv_cfg.key();
        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut output = BytesMut::with_capacity(MAX_PACKET_SIZE);
        let iv = recv_iv(conn, self.srv_cfg.clone()).await?;
        let mut cipher = crypto::new_stream(cipher_type, key, &iv, CryptoMode::Decrypt);

        loop {
            let size = timeout(Duration::from_secs(1), conn.read(&mut buf)).await?;
            let buffer_size = cipher.buffer_size(&buf[..size]);
            output.clear();
            output.reserve(buffer_size);

            if size > 0 {
                cipher.update(&buf[..size], &mut output)?;
                timeout(Duration::from_secs(1), socket.write_all(&output)).await?;
            } else {
                cipher.finalize(&mut output)?;
                timeout(Duration::from_secs(1), socket.write_all(&output)).await?;
                break;
            }
        }
        Ok(())
    }

    pub async fn handle_connect<T: AsyncRead + AsyncWrite + Clone + Unpin>(
        &self,
        socket: T,
        addr: Address,
    ) -> Result<()> {
        let ssserver = get_remote_ssserver_addr(
            &*self.resolver,
            self.srv_cfg.clone(),
            (&self.dns_server.0, self.dns_server.1),
        )
        .await?;
        let conn = TcpStream::connect(ssserver).await?;
        match self.srv_cfg.method().category() {
            CipherCategory::Stream => {
                let send = self.handle_stream_send(&conn, socket.clone(), addr.clone());
                let recv = self.handle_stream_recv(&conn, socket.clone(), addr);
                let _ = future::join!(send, recv).await;
            }
            CipherCategory::Aead => {
                let send = self.handle_aead_send(&conn, socket.clone(), addr.clone());
                let recv = self.handle_aead_recv(&conn, socket.clone(), addr);
                let _ = future::join!(send, recv).await;
            }
        }
        Ok(())
    }

    pub async fn handle_packets(&self, _socket: TunUdpSocket, _addr: Address) -> Result<()> {
        Ok(())
    }
}

async fn send_iv(mut conn: &TcpStream, srv_cfg: Arc<ServerConfig>) -> Result<Bytes> {
    let method = srv_cfg.method();
    let iv = match method.category() {
        CipherCategory::Stream => {
            let local_iv = method.gen_init_vec();
            debug!("Going to send initialize vector: {:?}", local_iv);
            local_iv
        }
        CipherCategory::Aead => {
            let local_salt = method.gen_salt();
            debug!("Going to send salt: {:?}", local_salt);
            local_salt
        }
    };

    timeout(Duration::from_secs(1), conn.write_all(&iv)).await?;

    Ok(iv)
}

async fn recv_iv(mut conn: &TcpStream, srv_cfg: Arc<ServerConfig>) -> Result<Vec<u8>> {
    let method = srv_cfg.method();
    let iv_size = match method.category() {
        CipherCategory::Stream => method.iv_size(),
        CipherCategory::Aead => method.salt_size(),
    };

    let mut iv = vec![0; iv_size];
    timeout(Duration::from_secs(1), conn.read_exact(&mut iv)).await?;
    debug!("Recv initialize vector: {:?}", &iv);
    Ok(iv)
}

async fn resolve_domain<T: DnsClient>(
    resolver: &T,
    server: (&str, u16),
    domain: &str,
) -> Result<Option<IpAddr>> {
    let packet = timeout(
        Duration::from_secs(1),
        resolver.send_query(domain, QueryType::A, server, true),
    )
    .await?;
    packet
        .get_random_a()
        .map(|ip| {
            ip.parse::<IpAddr>()
                .map_err(|e| io::Error::new(ErrorKind::Other, e))
        })
        .transpose()
}

async fn get_remote_ssserver_addr(
    resolver: &impl DnsClient,
    cfg: Arc<ServerConfig>,
    dns_server: (&str, u16),
) -> Result<SocketAddr> {
    let addr = match cfg.addr() {
        ServerAddr::SocketAddr(addr) => *addr,
        ServerAddr::DomainName(domain, port) => {
            let ip = resolve_domain(resolver, (&dns_server.0, dns_server.1), &domain).await?;
            let ip = match ip {
                Some(i) => i,
                None => {
                    return Err(Error::new(
                        ErrorKind::NotFound,
                        "Domain can not be resolved",
                    ));
                }
            };
            SocketAddr::new(ip, *port)
        }
    };
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use crypto::CipherType;

    #[test]
    fn test_get_remote_ssserver_domain() {
        task::block_on(async {
            let dns_client = DnsNetworkClient::new(0).await;
            let cfg = Arc::new(ServerConfig::new(
                ServerAddr::DomainName("localtest.me".to_string(), 7789),
                "pass".to_string(),
                CipherType::ChaCha20Ietf,
                None,
            ));
            let addr = get_remote_ssserver_addr(&dns_client, cfg, ("114.114.114.114", 53)).await;
            assert_eq!(addr.unwrap(), "127.0.0.1:7789".parse().unwrap());
        })
    }

    #[test]
    fn test_get_remote_ssserver_ip() {
        task::block_on(async {
            let dns_client = DnsNetworkClient::new(0).await;
            let cfg = Arc::new(ServerConfig::new(
                ServerAddr::SocketAddr("1.2.3.4:7789".parse().unwrap()),
                "pass".to_string(),
                CipherType::ChaCha20Ietf,
                None,
            ));
            let addr = get_remote_ssserver_addr(&dns_client, cfg, ("114.114.114.114", 53)).await;
            assert_eq!(addr.unwrap(), "1.2.3.4:7789".parse().unwrap());
        })
    }
}
