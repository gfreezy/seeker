mod connection_pool;
mod encrypted_stream;
mod tcp_io;
mod udp_io;

use std::collections::HashMap;
use std::io;
use std::io::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use async_std::io::timeout;
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::FutureExt as _;
use async_std::task;
use async_std::task::JoinHandle;
use bytes::{Bytes, BytesMut};
use futures::io::ErrorKind;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, FutureExt};
use tracing::trace;

use config::{Address, ServerAddr, ServerConfig};
use crypto::CipherCategory;
use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
use tun::socket::TunUdpSocket;

use crate::connection_pool::{EncryptedStremBox, Pool};
use crate::encrypted_stream::{AeadEncryptedTcpStream, StreamEncryptedTcpStream};
use crate::udp_io::{decrypt_payload, encrypt_payload};

const MAX_PACKET_SIZE: usize = 0x3FFF;

#[derive(Clone)]
pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    dns_server: (String, u16),
    resolver: Arc<DnsNetworkClient>,
    pool: Pool,
    to_terminate: Arc<AtomicBool>,
}

impl SSClient {
    pub async fn new(
        server_config: Arc<ServerConfig>,
        dns_server: (String, u16),
        to_terminate: Arc<AtomicBool>,
    ) -> SSClient {
        let resolver = Arc::new(DnsNetworkClient::new(0, server_config.read_timeout()).await);
        let srv_cfg_clone = server_config.clone();
        let resolver_clone = resolver.clone();
        let dns_server_clone = dns_server.clone();
        let pool = Pool::new(
            srv_cfg_clone.idle_connections(),
            Arc::new(move || {
                let srv_cfg = srv_cfg_clone.clone();
                let resolver = resolver_clone.clone();
                let dns_server = dns_server_clone.clone();

                async move {
                    let ssserver = get_remote_ssserver_addr(
                        &*resolver,
                        srv_cfg.clone(),
                        (&dns_server.0, dns_server.1),
                    )
                    .await?;

                    let conn: EncryptedStremBox = match srv_cfg.method().category() {
                        CipherCategory::Stream => Box::new(
                            StreamEncryptedTcpStream::new(srv_cfg.clone(), ssserver).await?,
                        ),
                        CipherCategory::Aead => {
                            Box::new(AeadEncryptedTcpStream::new(srv_cfg.clone(), ssserver).await?)
                        }
                    };
                    Ok(conn)
                }
                    .boxed()
            }),
        );

        let pool_clone = pool.clone();
        let _ = task::spawn(async move {
            pool_clone.run_connection_pool().await;
        });
        SSClient {
            srv_cfg: server_config.clone(),
            resolver,
            dns_server,
            pool,
            to_terminate,
        }
    }

    async fn handle_encrypted_tcp_stream<T: AsyncRead + AsyncWrite + Clone + Unpin>(
        &self,
        mut socket: T,
        addr: Address,
        conn: EncryptedStremBox,
    ) -> Result<()> {
        let conn1 = &conn;
        let conn2 = &conn;
        let mut socket_clone = socket.clone();

        let send_task = async move {
            let mut writer = conn1.get_writer().await?;
            let now = Instant::now();
            writer.send_addr(&addr).await?;
            let duration = now.elapsed();
            trace!(duration = ?duration, addr = %addr, "send addr to ssserver");

            let mut buf = vec![0; MAX_PACKET_SIZE];
            loop {
                let now = Instant::now();
                let size =
                    timeout(self.srv_cfg.read_timeout(), socket_clone.read(&mut buf)).await?;
                let duration = now.elapsed();
                trace!(duration = ?duration, size = size, "read from tun socket");

                if size == 0 {
                    break;
                }

                writer.send_all(&buf[..size]).await?;
            }
            Ok(())
        };

        let recv_task = async move {
            let mut reader = conn2.get_reader().await?;
            let mut buf = vec![0; MAX_PACKET_SIZE];
            loop {
                let size = reader.recv(&mut buf).await?;
                if size == 0 {
                    break;
                }
                let now = Instant::now();
                timeout(self.srv_cfg.write_timeout(), socket.write_all(&buf[..size])).await?;
                let duration = now.elapsed();
                trace!(duration = ?duration, size = size, "write to tun socket");
            }
            Ok(())
        };

        let _: (Result<()>, Result<()>) = send_task.join(recv_task).await;
        Ok(())
    }

    pub async fn handle_tcp_connection<T: AsyncRead + AsyncWrite + Clone + Unpin>(
        &self,
        socket: T,
        addr: Address,
    ) -> Result<()> {
        let conn = self.pool.get_connection().await?;
        self.handle_encrypted_tcp_stream(socket, addr, conn).await?;
        Ok(())
    }

    pub async fn handle_udp_connection(
        &self,
        tun_socket: TunUdpSocket,
        addr: Address,
    ) -> Result<()> {
        let ssserver = get_remote_ssserver_addr(
            &*self.resolver,
            self.srv_cfg.clone(),
            (&self.dns_server.0, self.dns_server.1),
        )
        .await?;
        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut encrypt_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
        let mut udp_map = HashMap::new();
        let cipher_type = self.srv_cfg.method();
        let key = self.srv_cfg.key().to_vec();

        loop {
            encrypt_buf.clear();
            buf[..addr.serialized_len()].copy_from_slice(&addr.to_bytes());
            let now = Instant::now();
            let (recv_from_tun_size, local_src) = tun_socket
                .recv_from(&mut buf[addr.serialized_len()..])
                .await?;
            let duration = now.elapsed();
            let encrypt_size = encrypt_payload(
                cipher_type,
                &key,
                &buf[..addr.serialized_len() + recv_from_tun_size],
                &mut encrypt_buf,
            )?;

            let udp_socket = match udp_map.get(&local_src).cloned() {
                Some(socket) => socket,
                None => {
                    let new_udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                    let bind_addr = new_udp.local_addr()?;
                    trace!(addr = %bind_addr, "bind new udp socket");
                    udp_map.insert(local_src, new_udp.clone());

                    let cloned_socket = tun_socket.clone();
                    let cloned_new_udp = new_udp.clone();
                    let key_cloned = key.clone();
                    let _handle: JoinHandle<Result<()>> = task::spawn(async move {
                        let mut recv_buf = vec![0; MAX_PACKET_SIZE];
                        let mut decrypt_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
                        loop {
                            decrypt_buf.clear();
                            let now = Instant::now();
                            let (recv_from_ss_size, udp_ss_addr) =
                                cloned_new_udp.recv_from(&mut recv_buf).await?;
                            let duration = now.elapsed();
                            trace!(duration = ?duration, size = recv_from_ss_size, src_addr = %udp_ss_addr, local_udp_socket = ?bind_addr, "recv from ss server");
                            let decrypt_size = decrypt_payload(
                                cipher_type,
                                &key_cloned,
                                &recv_buf[..recv_from_ss_size],
                                &mut decrypt_buf,
                            )?;
                            trace!(
                                "decrypt {} bytes with {} to {} bytes",
                                recv_from_ss_size,
                                cipher_type,
                                decrypt_size
                            );
                            let addr = Address::read_from(&mut decrypt_buf.as_ref())?;
                            let now = Instant::now();
                            let send_local_size = cloned_socket
                                .send_to(
                                    &decrypt_buf[addr.serialized_len()..decrypt_size],
                                    &local_src,
                                )
                                .await?;
                            let duration = now.elapsed();
                            trace!(duration = ?duration, size = send_local_size, dst_addr = %local_src, local_udp_socket = ?bind_addr, "send to tun socket");
                        }
                    });
                    new_udp
                }
            };
            let bind_addr = udp_socket.local_addr()?;
            trace!(duration = ?duration, size = recv_from_tun_size, src_addr = %local_src, local_udp_socket = ?bind_addr, "recv from tun socket");
            trace!(
                "encrypt {} bytes with {} to {} bytes",
                addr.serialized_len() + recv_from_tun_size,
                cipher_type,
                encrypt_size
            );
            let now = Instant::now();
            let send_ss_size = udp_socket
                .send_to(&encrypt_buf[..encrypt_size], ssserver)
                .await?;
            let duration = now.elapsed();
            trace!(duration = ?duration, size = send_ss_size, dst_addr = %ssserver, local_udp_socket = ?bind_addr, "send to ss server");
        }
    }
}

async fn send_iv(mut conn: &TcpStream, srv_cfg: Arc<ServerConfig>) -> Result<Bytes> {
    let method = srv_cfg.method();
    let iv = match method.category() {
        CipherCategory::Stream => method.gen_init_vec(),
        CipherCategory::Aead => method.gen_salt(),
    };

    let now = Instant::now();
    timeout(srv_cfg.write_timeout(), conn.write_all(&iv)).await?;
    let duration = now.elapsed();
    trace!(duration = ?duration, "send iv");

    Ok(iv)
}

async fn recv_iv(mut conn: &TcpStream, srv_cfg: Arc<ServerConfig>) -> Result<Vec<u8>> {
    let method = srv_cfg.method();
    let iv_size = match method.category() {
        CipherCategory::Stream => method.iv_size(),
        CipherCategory::Aead => method.salt_size(),
    };

    let mut iv = vec![0; iv_size];

    let now = Instant::now();
    timeout(srv_cfg.read_timeout(), conn.read_exact(&mut iv)).await?;
    let duration = now.elapsed();
    trace!(duration = ?duration, "recv iv");

    Ok(iv)
}

pub async fn resolve_domain<T: DnsClient>(
    resolver: &T,
    server: (&str, u16),
    domain: &str,
) -> Result<Option<IpAddr>> {
    trace!(dns_server = ?server, domain, "begin resolve domain");
    let now = Instant::now();
    let packet = resolver
        .send_query(domain, QueryType::A, server, true)
        .await?;
    let elapsed = now.elapsed();
    let ip = packet
        .get_first_a()
        .map(|ip| {
            ip.parse::<IpAddr>()
                .map_err(|e| io::Error::new(ErrorKind::Other, e))
        })
        .transpose();
    trace!(duration = ?elapsed, dns_server = ?server, domain, ip = ?ip, "resolve_domain");
    ip
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
    use std::time::Duration;

    use async_std::task;

    use crypto::CipherType;

    use super::*;

    #[test]
    fn test_get_remote_ssserver_domain() {
        let dns = std::env::var("DNS").unwrap_or_else(|_| "223.5.5.5".to_string());
        task::block_on(async {
            let dns_client = DnsNetworkClient::new(0, Duration::from_secs(3)).await;
            let cfg = Arc::new(ServerConfig::new(
                ServerAddr::DomainName("local.allsunday.in".to_string(), 7789),
                "pass".to_string(),
                CipherType::ChaCha20Ietf,
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(10),
                10,
            ));
            let addr = get_remote_ssserver_addr(&dns_client, cfg, (&dns, 53)).await;
            assert_eq!(addr.unwrap(), "127.0.0.1:7789".parse().unwrap());
        });
    }

    #[test]
    fn test_get_remote_ssserver_ip() {
        task::block_on(async {
            let dns_client = DnsNetworkClient::new(0, Duration::from_secs(3)).await;
            let cfg = Arc::new(ServerConfig::new(
                ServerAddr::SocketAddr("1.2.3.4:7789".parse().unwrap()),
                "pass".to_string(),
                CipherType::ChaCha20Ietf,
                Duration::from_secs(3),
                Duration::from_secs(3),
                Duration::from_secs(3),
                10,
            ));
            let addr = get_remote_ssserver_addr(&dns_client, cfg, ("208.67.222.222", 53)).await;
            assert_eq!(addr.unwrap(), "1.2.3.4:7789".parse().unwrap());
        });
    }
}
