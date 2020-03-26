use crate::client::Client;
use async_std::io;
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;
use async_std::sync::Mutex;
use async_std::task;
use async_std::task::JoinHandle;
use chrono::{DateTime, Local};
use config::rule::Action;
use config::Address;
use hermesdns::DnsNetworkClient;
use ssclient::client_stats::ClientStats;
use ssclient::resolve_domain;
use std::collections::HashMap;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{trace, trace_span};
use tracing_futures::Instrument;
use tun::socket::TunUdpSocket;

pub(crate) struct DirectClient {
    resolver: DnsNetworkClient,
    dns_server: (String, u16),
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    probe_timeout: Duration,
    stats: ClientStats,
    prob_cache: Mutex<HashMap<Address, (bool, DateTime<Local>)>>,
}

impl DirectClient {
    pub async fn new(
        dns_server: (String, u16),
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
        probe_timeout: Duration,
    ) -> Self {
        DirectClient {
            resolver: DnsNetworkClient::new(0, connect_timeout).await,
            dns_server,
            connect_timeout,
            read_timeout,
            write_timeout,
            probe_timeout,
            stats: ClientStats::new(),
            prob_cache: Mutex::new(HashMap::new()),
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

    pub(crate) async fn probe_connectivity(&self, addr: Address) -> bool {
        let mut guard = self.prob_cache.lock().await;
        if let Some((connectable, expire)) = guard.get(&addr) {
            if expire > &Local::now() {
                return *connectable;
            } else {
                guard.remove(&addr);
            }
        };

        let connectable = self.connect(&addr, self.probe_timeout).await.is_ok();
        guard.insert(
            addr,
            (connectable, Local::now().add(chrono::Duration::minutes(5))),
        );
        connectable
    }

    async fn connect(&self, addr: &Address, timeout: Duration) -> Result<TcpStream> {
        let sock_addr = match addr {
            Address::SocketAddress(addr) => *addr,
            Address::DomainNameAddress(domain, port) => {
                let ip = self.resolve_domain(&domain).await?;
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
        let now = Instant::now();
        let conn = io::timeout(timeout, TcpStream::connect(sock_addr)).await?;
        let elapsed = now.elapsed();
        trace!(duration = ?elapsed, "TcpStream::connect");
        Ok(conn)
    }
}

#[async_trait::async_trait]
impl Client for DirectClient {
    #[allow(unreachable_code)]
    async fn handle_tcp(&self, socket: TcpStream, addr: Address) -> Result<()> {
        let conn = self.connect(&addr, self.connect_timeout).await?;
        let mut socket_clone = socket.clone();
        let mut socket_clone2 = socket.clone();
        let mut ref_conn = &conn;
        let mut ref_conn2 = &conn;
        let idx = self.stats.add_connection(addr, Action::Direct).await;
        let a = async {
            let mut buf = vec![0; 10240];
            loop {
                let rs = io::timeout(self.read_timeout, socket_clone.read(&mut buf)).await?;
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
                io::timeout(self.write_timeout, socket_clone2.write_all(&buf[..rs])).await?;
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
    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()> {
        let sock_addr = match addr.clone() {
            Address::SocketAddress(addr) => addr,
            Address::DomainNameAddress(domain, port) => {
                let ip = self.resolve_domain(&domain).await?;
                match ip {
                    None => {
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            format!("domain {} not found", &domain),
                        ))
                    }
                    Some(ip) => SocketAddr::new(ip, port),
                }
            }
        };

        let mut buf = vec![0; 1500];
        let mut udp_map = HashMap::new();

        loop {
            let now = Instant::now();
            let (recv_from_local_size, local_src) =
                io::timeout(self.read_timeout, socket.recv_from(&mut buf)).await?;
            let duration = now.elapsed();
            let udp_socket = match udp_map.get(&local_src).cloned() {
                Some(socket) => socket,
                None => {
                    let new_udp = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                    let bind_addr = new_udp.local_addr()?;
                    trace!(addr = %bind_addr, "bind new udp socket");
                    udp_map.insert(local_src, new_udp.clone());

                    let cloned_socket = socket.clone();
                    let cloned_new_udp = new_udp.clone();
                    let read_timeout = self.read_timeout;
                    let write_timeout = self.write_timeout;
                    let _handle: JoinHandle<Result<_>> = task::spawn(async move {
                        let mut recv_buf = vec![0; 1024];
                        loop {
                            let now = Instant::now();
                            let (recv_from_ss_size, udp_ss_addr) =
                                io::timeout(read_timeout, cloned_new_udp.recv_from(&mut recv_buf)).await?;
                            let duration = now.elapsed();
                            trace!(duration = ?duration, size = recv_from_ss_size, src_addr = %udp_ss_addr, local_udp_socket = ?bind_addr, "recv from ss server");
                            let now = Instant::now();
                            let send_local_size = io::timeout(write_timeout, cloned_socket
                                .send_to(&recv_buf[..recv_from_ss_size], &local_src))
                                .await?;
                            let duration = now.elapsed();
                            trace!(duration = ?duration, size = send_local_size, dst_addr = %local_src, local_udp_socket = ?bind_addr, "send to tun socket");
                        }
                        Ok(())
                    }.instrument(trace_span!("ss server to tun socket", socket = %bind_addr)));
                    new_udp
                }
            };
            let bind_addr = udp_socket.local_addr()?;
            trace!(duration = ?duration, size = recv_from_local_size, src_addr = %local_src, local_udp_socket = ?bind_addr, "recv from tun socket");
            let now = Instant::now();
            let send_ss_size = io::timeout(
                self.write_timeout,
                udp_socket.send_to(&buf[..recv_from_local_size], sock_addr),
            )
            .await?;
            let duration = now.elapsed();
            trace!(duration = ?duration, size = send_ss_size, dst_addr = %sock_addr, local_udp_socket = ?bind_addr, "send to ss server");
        }

        Ok(())
    }
}
