use crate::client::Client;
use async_std::io;
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;
use async_std::task;
use async_std::task::JoinHandle;
use config::Address;
use hermesdns::DnsNetworkClient;
use ssclient::resolve_domain;
use std::collections::HashMap;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{trace, trace_span};
use tracing_futures::Instrument;
use tun::socket::{TunTcpSocket, TunUdpSocket};

pub(crate) struct DirectClient {
    resolver: DnsNetworkClient,
    dns_server: (String, u16),
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    probe_timeout: Duration,
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
        }
    }

    fn dns_server(&self) -> (&str, u16) {
        (&self.dns_server.0, self.dns_server.1)
    }

    async fn resolve_domain(&self, domain: &str) -> Result<Option<IpAddr>> {
        resolve_domain(&self.resolver, self.dns_server(), domain).await
    }

    pub(crate) async fn probe_connectivity(&self, addr: Address) -> bool {
        self.connect(addr, self.probe_timeout).await.is_ok()
    }

    async fn connect(&self, addr: Address, timeout: Duration) -> Result<TcpStream> {
        let sock_addr = match addr {
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
    async fn handle_tcp(&self, tun_socket: TunTcpSocket, addr: Address) -> Result<()> {
        let conn = self.connect(addr, self.connect_timeout).await?;
        let mut tun_socket_clone = tun_socket.clone();
        let mut tun_socket_clone2 = tun_socket.clone();
        let mut ref_conn = &conn;
        let mut ref_conn2 = &conn;
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
            }
            Ok::<(), io::Error>(())
        };
        a.race(b).await?;
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

        let mut buf = vec![0; 1024];
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
