use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::io::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_std::io::{timeout, Read, Write};
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;
use async_std::sync::RwLock;
use async_std::task;
use async_std::task::JoinHandle;
use bytes::{Bytes, BytesMut};
use tracing::{trace, trace_span};
use tracing_futures::Instrument;

use crate::client_stats::ClientStats;
use crate::connection_pool::{EncryptedStremBox, Pool};
use crate::encrypted_stream::{AeadEncryptedTcpStream, StreamEncryptedTcpStream};
use crate::udp_io::{decrypt_payload, encrypt_payload};
use chrono::Local;
use config::rule::Action;
use config::{Address, ServerAddr, ShadowsocksServerConfig};
use crypto::{CipherCategory, CipherType};
use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
use std::future::Future;
use std::pin::Pin;
use tun::socket::TunUdpSocket;

pub mod client_stats;
mod connection_pool;
mod encrypted_stream;
mod tcp_io;
mod udp_io;

const MAX_PACKET_SIZE: usize = 0x3FFF;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a + Send>>;

pub struct SSClient {
    srv_cfg: Arc<RwLock<ShadowsocksServerConfig>>,
    dns_server: (String, u16),
    resolver: Arc<DnsNetworkClient>,
    pool: Pool,
    connect_errors: Arc<AtomicUsize>,
    stats: ClientStats,
}

impl SSClient {
    pub async fn new(
        server_config: Arc<RwLock<ShadowsocksServerConfig>>,
        dns_server: (String, u16),
    ) -> SSClient {
        let server_config_clone = server_config.clone();
        let idle_connections = server_config.read().await.idle_connections();
        let connect_timeout = server_config.read().await.connect_timeout();
        let resolver =
            Arc::new(DnsNetworkClient::new(0, server_config.read().await.read_timeout()).await);
        let resolver_clone = resolver.clone();
        let dns_server_clone = dns_server.clone();
        let connect_errors = Arc::new(AtomicUsize::new(0));
        let connect_errors_clone = connect_errors.clone();
        let pool = Pool::new(
            Arc::new(move || {
                let srv_cfg = server_config_clone.clone();
                let resolver = resolver_clone.clone();
                let dns_server = dns_server_clone.clone();
                let connect_errors = connect_errors_clone.clone();

                Box::pin(async move {
                    let ret = async move {
                        let srv_cfg = srv_cfg.read().await;
                        let read_timeout = srv_cfg.read_timeout();
                        let write_timeout = srv_cfg.write_timeout();
                        let connect_timeout = srv_cfg.connect_timeout();
                        let key = srv_cfg.key();
                        let method = srv_cfg.method();
                        let server_addr = srv_cfg.addr().clone();
                        drop(srv_cfg);

                        trace!(server_addr=?server_addr, "connect to ssserver");
                        let ssserver = get_remote_ssserver_addr(
                            &*resolver,
                            &server_addr,
                            (&dns_server.0, dns_server.1),
                        )
                        .await?;

                        let conn: EncryptedStremBox = match method.category() {
                            CipherCategory::Stream => Box::new(
                                StreamEncryptedTcpStream::new(
                                    ssserver,
                                    method,
                                    key,
                                    connect_timeout,
                                    read_timeout,
                                    write_timeout,
                                )
                                .await?,
                            ),
                            CipherCategory::Aead => Box::new(
                                AeadEncryptedTcpStream::new(
                                    ssserver,
                                    method,
                                    key,
                                    connect_timeout,
                                    read_timeout,
                                    write_timeout,
                                )
                                .await?,
                            ),
                        };
                        Ok(conn)
                    }
                    .await;
                    if ret.is_err() {
                        connect_errors.fetch_add(1, Ordering::SeqCst);
                    }
                    ret
                })
            }),
            idle_connections,
            connect_timeout,
        );

        let pool_clone = pool.clone();
        let _ = task::spawn(
            async move {
                pool_clone.run_connection_pool().await;
            }
            .instrument(trace_span!("background connection pool")),
        );
        SSClient {
            srv_cfg: server_config.clone(),
            connect_errors,
            resolver,
            dns_server,
            pool,
            stats: ClientStats::new(),
        }
    }

    pub async fn name(&self) -> String {
        self.srv_cfg.read().await.name().to_string()
    }

    pub fn connect_errors(&self) -> usize {
        self.connect_errors.load(Ordering::SeqCst)
    }

    pub async fn change_conf(&self, conf: ShadowsocksServerConfig) {
        *self.srv_cfg.write().await = conf;
        let _ = self.connect_errors.swap(0, Ordering::SeqCst);
    }

    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    #[allow(clippy::cognitive_complexity)]
    async fn handle_encrypted_tcp_stream<T: Read + Write + Clone + Unpin>(
        &self,
        idx: u64,
        mut tun_socket: T,
        addr: Address,
        conn: EncryptedStremBox,
    ) -> Result<()> {
        let conn1 = &conn;
        let conn2 = &conn;
        let mut tun_socket_clone = tun_socket.clone();
        let (read_timeout, write_timeout) = {
            let srv_cfg = self.srv_cfg.read().await;
            (srv_cfg.read_timeout(), srv_cfg.write_timeout())
        };

        let send_task = async move {
            let mut writer = conn1
                .get_writer()
                .instrument(trace_span!("get writer"))
                .await?;
            let now = Instant::now();
            writer
                .send_addr(&addr)
                .instrument(trace_span!("send addr"))
                .await?;
            let duration = now.elapsed();
            trace!(duration = ?duration, addr = %addr, "send addr to ssserver");

            let mut buf = vec![0; MAX_PACKET_SIZE];
            loop {
                let now = Instant::now();
                let size = timeout(read_timeout, tun_socket_clone.read(&mut buf))
                    .instrument(trace_span!("read from tun socket"))
                    .await?;
                let duration = now.elapsed();
                trace!(duration = ?duration, size = size, "read from tun socket");

                if size == 0 {
                    break;
                }

                writer
                    .send_all(&buf[..size])
                    .instrument(trace_span!("send all to remote socket"))
                    .await?;

                self.stats
                    .update_connection_stats(idx, |stats| {
                        stats.sent_bytes += size as u64;
                    })
                    .await;
            }
            Ok::<(), io::Error>(())
        }
        .instrument(trace_span!(
            "SSClient.handle_encrypted_tcp_stream[send_task]"
        ));

        let recv_task = async move {
            let mut reader = conn2
                .get_reader()
                .instrument(trace_span!("get reader"))
                .await?;
            let mut buf = vec![0; MAX_PACKET_SIZE];
            loop {
                let size = reader
                    .recv(&mut buf)
                    .instrument(trace_span!("recv from remote socket"))
                    .await?;
                if size == 0 {
                    break;
                }
                let now = Instant::now();
                timeout(write_timeout, tun_socket.write_all(&buf[..size]))
                    .instrument(trace_span!("write all to tun socket"))
                    .await?;
                let duration = now.elapsed();
                trace!(duration = ?duration, size = size, "write to tun socket");

                self.stats
                    .update_connection_stats(idx, |stats| {
                        stats.recv_bytes += size as u64;
                    })
                    .await;
            }
            Ok::<(), io::Error>(())
        }
        .instrument(trace_span!(
            "SSClient.handle_encrypted_tcp_stream[recv_task]"
        ));

        send_task
            .race(recv_task)
            .instrument(trace_span!("race send task and recv task"))
            .await?;
        Ok(())
    }

    pub async fn handle_tcp_connection<T: Read + Write + Clone + Unpin>(
        &self,
        socket: T,
        addr: Address,
    ) -> Result<()> {
        let now = Instant::now();
        let conn = self
            .pool
            .get_connection()
            .instrument(trace_span!("pool.get_connection"))
            .await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, "get connection from pool");
        let idx = self.stats.add_connection(addr.clone(), Action::Proxy).await;

        let ret = self
            .handle_encrypted_tcp_stream(idx, socket, addr, conn)
            .instrument(trace_span!("SSClient.handle_encrypted_tcp_stream"))
            .await;
        self.stats
            .update_connection_stats(idx, |stats| {
                stats.close_time = Local::now();
            })
            .await;

        match ret {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::TimedOut => Err(e),
            Err(e) => {
                self.connect_errors.fetch_add(1, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    pub async fn handle_udp_connection(
        &self,
        tun_socket: TunUdpSocket,
        addr: Address,
    ) -> Result<()> {
        let (key, method, server_addr, read_timeout, write_timeout) = {
            let srv_cfg = self.srv_cfg.read().await;
            let key = srv_cfg.key();
            let method = srv_cfg.method();
            let server_addr = srv_cfg.addr().clone();
            let read_timeout = srv_cfg.read_timeout();
            let write_timeout = srv_cfg.write_timeout();
            (key, method, server_addr, read_timeout, write_timeout)
        };
        let ssserver = get_remote_ssserver_addr(
            &*self.resolver,
            &server_addr,
            (&self.dns_server.0, self.dns_server.1),
        )
        .await?;
        let mut buf = vec![0; MAX_PACKET_SIZE];
        let mut encrypt_buf = BytesMut::with_capacity(MAX_PACKET_SIZE);
        let mut udp_map = HashMap::new();
        let cipher_type = method;
        let key = key.to_vec();

        loop {
            encrypt_buf.clear();
            addr.write_to_buf(&mut buf);

            let now = Instant::now();
            let (recv_from_tun_size, local_src) = timeout(
                read_timeout,
                tun_socket.recv_from(&mut buf[addr.serialized_len()..]),
            )
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
                                timeout(read_timeout, cloned_new_udp.recv_from(&mut recv_buf))
                                    .await?;
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
                            let addr = Address::read_from(&mut decrypt_buf.as_ref()).await?;
                            let now = Instant::now();
                            let send_local_size = timeout(
                                write_timeout,
                                cloned_socket.send_to(
                                    &decrypt_buf[addr.serialized_len()..decrypt_size],
                                    &local_src,
                                ),
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
            let send_ss_size = timeout(
                write_timeout,
                udp_socket.send_to(&encrypt_buf[..encrypt_size], ssserver),
            )
            .await?;
            let duration = now.elapsed();
            trace!(duration = ?duration, size = send_ss_size, dst_addr = %ssserver, local_udp_socket = ?bind_addr, "send to ss server");
        }
    }
}

async fn send_iv(
    mut conn: &TcpStream,
    method: CipherType,
    write_timeout: Duration,
) -> Result<Bytes> {
    let iv = match method.category() {
        CipherCategory::Stream => method.gen_init_vec(),
        CipherCategory::Aead => method.gen_salt(),
    };

    let now = Instant::now();
    timeout(write_timeout, conn.write_all(&iv)).await?;
    let duration = now.elapsed();
    trace!(duration = ?duration, "send iv");

    Ok(iv)
}

async fn recv_iv(
    mut conn: &TcpStream,
    method: CipherType,
    read_timeout: Duration,
) -> Result<Vec<u8>> {
    let iv_size = match method.category() {
        CipherCategory::Stream => method.iv_size(),
        CipherCategory::Aead => method.salt_size(),
    };

    let mut iv = vec![0; iv_size];

    let now = Instant::now();
    timeout(read_timeout, conn.read_exact(&mut iv)).await?;
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
    server_addr: &ServerAddr,
    dns_server: (&str, u16),
) -> Result<SocketAddr> {
    let addr = match server_addr {
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
        let dns = std::env::var("DNS").unwrap_or_else(|_| "114.114.114.114".to_string());
        task::block_on(async {
            let dns_client = DnsNetworkClient::new(0, Duration::from_secs(5)).await;
            let cfg = Arc::new(ShadowsocksServerConfig::new(
                "servername".to_string(),
                ServerAddr::DomainName("local.allsunday.in".to_string(), 7789),
                "pass".to_string(),
                CipherType::ChaCha20Ietf,
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(10),
                10,
            ));
            let addr = get_remote_ssserver_addr(&dns_client, cfg.addr(), (&dns, 53)).await;
            assert_eq!(addr.unwrap(), "127.0.0.1:7789".parse().unwrap());
        });
    }

    #[test]
    fn test_get_remote_ssserver_ip() {
        task::block_on(async {
            let dns_client = DnsNetworkClient::new(0, Duration::from_secs(3)).await;
            let cfg = Arc::new(ShadowsocksServerConfig::new(
                "servername".to_string(),
                ServerAddr::SocketAddr("1.2.3.4:7789".parse().unwrap()),
                "pass".to_string(),
                CipherType::ChaCha20Ietf,
                Duration::from_secs(3),
                Duration::from_secs(3),
                Duration::from_secs(3),
                10,
            ));
            let addr =
                get_remote_ssserver_addr(&dns_client, cfg.addr(), ("208.67.222.222", 53)).await;
            assert_eq!(addr.unwrap(), "1.2.3.4:7789".parse().unwrap());
        });
    }
}
