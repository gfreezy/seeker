use crate::client::Client;
use async_std::io;
use async_std::io::prelude::{ReadExt, WriteExt};
use async_std::net::{SocketAddr, TcpStream};
use async_std::prelude::FutureExt;
use chrono::Local;
use config::{Address, ServerAddr};
use hermesdns::DnsNetworkClient;
use ssclient::client_stats::ClientStats;
use ssclient::resolve_domain;
use std::io::Result;
use std::net::IpAddr;
use std::time::Duration;
use tracing::trace;
use tun::socket::{TunTcpSocket, TunUdpSocket};

pub struct Socks5Client {
    resolver: DnsNetworkClient,
    dns_server: (String, u16),
    socks5_server: ServerAddr,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    stats: ClientStats,
}

impl Socks5Client {
    pub async fn new(
        dns_server: (String, u16),
        socks5_server: ServerAddr,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Socks5Client {
            resolver: DnsNetworkClient::new(0, connect_timeout).await,
            dns_server,
            socks5_server,
            connect_timeout,
            read_timeout,
            write_timeout,
            stats: ClientStats::new(),
        }
    }

    fn dns_server(&self) -> (&str, u16) {
        (&self.dns_server.0, self.dns_server.1)
    }

    async fn resolve_domain(&self, domain: &str) -> Result<Option<IpAddr>> {
        resolve_domain(&self.resolver, self.dns_server(), domain).await
    }

    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    async fn get_server_addr(&self) -> Result<SocketAddr> {
        Ok(match &self.socks5_server {
            ServerAddr::SocketAddr(addr) => *addr,
            ServerAddr::DomainName(domain, port) => {
                let ip = self.resolve_domain(&domain).await?;
                match ip {
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("domain {} not found", &domain),
                        ))
                    }
                    Some(ip) => SocketAddr::new(ip, *port),
                }
            }
        })
    }
}

#[async_trait::async_trait]
impl Client for Socks5Client {
    #[allow(unreachable_code)]
    async fn handle_tcp(&self, tun_socket: TunTcpSocket, addr: Address) -> Result<()> {
        let mut conn = io::timeout(
            self.connect_timeout,
            TcpStream::connect(self.get_server_addr().await?),
        )
        .await?;
        const SOCKS5: u8 = 0x05;
        const NMETHODS: u8 = 1;
        const NOAUTH: u8 = 0;

        const CONNECT: u8 = 0x01;

        let auth_req = [SOCKS5, NMETHODS, NOAUTH];
        conn.write_all(&auth_req).await?;
        let mut auth_req = [0; 2];
        conn.read_exact(&mut auth_req).await?;
        if auth_req != [SOCKS5, NOAUTH] {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        let mut conn_req = vec![SOCKS5, CONNECT, 0];
        addr.write_to_buf(&mut conn_req);
        conn.write_all(&conn_req).await?;

        let mut buf = vec![0; conn_req.len()];
        let size = conn.read(&mut buf).await?;
        assert!(size > 4);
        assert_eq!(buf[1], 0x00);

        let mut tun_socket_clone = tun_socket.clone();
        let mut tun_socket_clone2 = tun_socket.clone();
        let mut ref_conn = &conn;
        let mut ref_conn2 = &conn;
        let idx = self.stats.add_connection(addr).await;
        let a = async {
            let mut buf = vec![0; 10240];
            loop {
                let rs = io::timeout(self.read_timeout, tun_socket_clone.read(&mut buf)).await?;
                trace!(read_size = rs, "DirectClient::handle_tcp: read from tun");
                if rs == 0 {
                    break;
                }
                io::timeout(self.write_timeout, ref_conn.write_all(&buf[..rs])).await?;
                trace!(write_size = rs, "DirectClient::handle_tcp: write to remote");
                self.stats
                    .update_connection_stats(idx, |stats| {
                        stats.sent_bytes += rs as u64;
                    })
                    .await;
            }
            Ok::<(), io::Error>(())
        };
        let b = async {
            let mut buf = vec![0; 10240];
            loop {
                let rs = io::timeout(self.read_timeout, ref_conn2.read(&mut buf)).await?;
                trace!(read_size = rs, "DirectClient::handle_tcp: read from remote");
                if rs == 0 {
                    break;
                }
                io::timeout(self.write_timeout, tun_socket_clone2.write_all(&buf[..rs])).await?;
                trace!(write_size = rs, "DirectClient::handle_tcp: write to tun");
                self.stats
                    .update_connection_stats(idx, |stats| {
                        stats.recv_bytes += rs as u64;
                    })
                    .await;
            }
            Ok::<(), io::Error>(())
        };
        let ret = a.race(b).await;
        self.stats
            .update_connection_stats(idx, |stats| {
                stats.close_time = Local::now();
            })
            .await;
        ret?;
        Ok(())
    }

    #[allow(unreachable_code)]
    async fn handle_udp(&self, _socket: TunUdpSocket, _addr: Address) -> Result<()> {
        Ok(())
    }
}
