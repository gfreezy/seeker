use crate::client::Client;
use async_std::io;
use async_std::prelude::*;
use async_std::task;
use async_std::task::JoinHandle;
use chrono::Local;
use config::rule::Action;
use config::{Address, ServerAddr};
use hermesdns::DnsNetworkClient;
use socks5_client::{Socks5TcpStream, Socks5UdpSocket};
use ssclient::client_stats::ClientStats;
use ssclient::resolve_domain;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{trace, trace_span};
use tracing_futures::Instrument;
use tun::socket::{TunTcpSocket, TunUdpSocket};

pub(crate) struct Socks5Client {
    resolver: DnsNetworkClient,
    dns_server: (String, u16),
    socks5_server: SocketAddr,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    stats: ClientStats,
}

impl Socks5Client {
    pub async fn new(
        (dns_server, dns_port): (String, u16),
        socks5_server: ServerAddr,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        let resolver = DnsNetworkClient::new(0, connect_timeout).await;
        let addr = match socks5_server {
            ServerAddr::SocketAddr(addr) => addr,
            ServerAddr::DomainName(domain, port) => {
                let ip = resolve_domain(&resolver, (&dns_server, dns_port), &domain)
                    .await
                    .expect("resolve socks5 server domain error")
                    .expect("no ip found");
                SocketAddr::new(ip, port)
            }
        };
        Socks5Client {
            resolver,
            dns_server: (dns_server, dns_port),
            socks5_server: addr,
            connect_timeout,
            read_timeout,
            write_timeout,
            stats: ClientStats::new(),
        }
    }

    pub fn stats(&self) -> &ClientStats {
        &self.stats
    }

    async fn connect(&self, addr: Address, timeout: Duration) -> Result<Socks5TcpStream> {
        let now = Instant::now();
        let conn = io::timeout(timeout, Socks5TcpStream::connect(self.socks5_server, addr)).await?;
        let elapsed = now.elapsed();
        trace!(duration = ?elapsed, "TcpStream::connect");
        Ok(conn)
    }

    async fn resolve_addr(&self, addr: &Address) -> Result<SocketAddr> {
        let sock_addr = match addr {
            Address::SocketAddress(addr) => *addr,
            Address::DomainNameAddress(domain, port) => {
                let ip = resolve_domain(
                    &self.resolver,
                    (&self.dns_server.0, self.dns_server.1),
                    &domain,
                )
                .await?;
                match ip {
                    None => {
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            format!("domain {} not found", &domain),
                        ))
                    }
                    Some(ip) => SocketAddr::new(ip, *port),
                }
            }
        };
        Ok(sock_addr)
    }
}

#[async_trait::async_trait]
impl Client for Socks5Client {
    #[allow(unreachable_code)]
    async fn handle_tcp(&self, tun_socket: TunTcpSocket, addr: Address) -> Result<()> {
        let conn = self.connect(addr.clone(), self.connect_timeout).await?;
        let mut tun_socket_clone = tun_socket.clone();
        let mut tun_socket_clone2 = tun_socket.clone();
        let mut ref_conn = &conn;
        let mut ref_conn2 = &conn;
        let idx = self.stats.add_connection(addr, Action::Proxy).await;
        let a = async {
            let mut buf = vec![0; 10240];
            loop {
                let rs = io::timeout(self.read_timeout, tun_socket_clone.read(&mut buf)).await?;
                trace!(read_size = rs, "Socks5Client::handle_tcp: read from tun");
                if rs == 0 {
                    break;
                }
                io::timeout(self.write_timeout, ref_conn.write_all(&buf[..rs])).await?;
                trace!(write_size = rs, "Socks5Client::handle_tcp: write to remote");
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
                trace!(read_size = rs, "Socks5Client::handle_tcp: read from remote");
                if rs == 0 {
                    break;
                }
                io::timeout(self.write_timeout, tun_socket_clone2.write_all(&buf[..rs])).await?;
                trace!(write_size = rs, "Socks5Client::handle_tcp: write to tun");
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
    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()> {
        let mut buf = vec![0; 1500];
        let mut udp_map = HashMap::new();

        let addr = self.resolve_addr(&addr).await?;

        loop {
            let now = Instant::now();
            let (recv_from_local_size, local_src) =
                io::timeout(self.read_timeout, socket.recv_from(&mut buf)).await?;
            let local_addr = socket.local_addr();
            let duration = now.elapsed();
            trace!(size = recv_from_local_size, local_src = ?local_src, local_addr = ?local_addr, duration = ?duration, "read from tun server");
            let udp_socket = match udp_map.get(&local_src).cloned() {
                Some(socket) => socket,
                None => {
                    let new_udp = Arc::new(Socks5UdpSocket::connect(self.socks5_server).await?);
                    let bind_addr = new_udp.local_addr()?;
                    trace!(addr = %bind_addr, "bind new udp socket");
                    udp_map.insert(local_src, new_udp.clone());

                    let cloned_socket = socket.clone();
                    let cloned_new_udp = new_udp.clone();
                    let read_timeout = self.read_timeout;
                    let write_timeout = self.write_timeout;
                    let _handle: JoinHandle<Result<_>> = task::spawn(async move {
                        let mut recv_buf = vec![0; 1500];
                        loop {
                            let now = Instant::now();
                            let (recv_from_ss_size, udp_ss_addr) =
                                io::timeout(read_timeout, cloned_new_udp.recv_from(&mut recv_buf)).await?;
                            let duration = now.elapsed();
                            trace!(duration = ?duration, size = recv_from_ss_size, src_addr = %udp_ss_addr, local_udp_socket = ?bind_addr, "recv from socks5 server");
                            let now = Instant::now();
                            let send_local_size = io::timeout(write_timeout, cloned_socket
                                .send_to(&recv_buf[..recv_from_ss_size], &local_src))
                                .await?;
                            let duration = now.elapsed();
                            trace!(duration = ?duration, size = send_local_size, dst_addr = %local_src, local_udp_socket = ?bind_addr, "send to tun socket");
                        }
                        Ok(())
                    }.instrument(trace_span!("socks5 server to tun socket", socket = %bind_addr)));
                    new_udp
                }
            };
            let now = Instant::now();
            let send_ss_size = io::timeout(
                self.write_timeout,
                udp_socket.send_to(&buf[..recv_from_local_size], addr.clone()),
            )
            .await?;
            let duration = now.elapsed();
            trace!(duration = ?duration, size = send_ss_size, dst_addr = %addr.clone(), "send to socks5 server");
        }

        Ok(())
    }
}
