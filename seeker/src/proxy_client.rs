use crate::dns_client::DnsClient;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use crate::server_chooser::ServerChooser;
use async_std::io::{timeout, Read, Write};
use async_std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use async_std::prelude::*;
use async_std::task::spawn;
use async_std_resolver::AsyncStdResolver;
use config::rule::Action;
use config::{Address, Config};
use dnsserver::create_dns_server;
use dnsserver::resolver::RuleBasedDnsResolver;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::io::Result;
use std::sync::Arc;
use tracing::{error, trace, trace_span};
use tracing_futures::Instrument;
use tun_nat::{run_nat, SessionManager};

pub struct ProxyClient {
    config: Config,
    uid: Option<u32>,
    session_manager: SessionManager,
    udp_manager: Arc<RwLock<HashMap<u16, (ProxyUdpSocket, SocketAddr)>>>,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsClient,
    extra_directly_servers: Vec<String>,
    server_chooser: Arc<ServerChooser>,
}

impl ProxyClient {
    pub async fn new(config: Config, uid: Option<u32>) -> Self {
        let session_manager =
            run_nat(&config.tun_name, config.tun_ip, config.tun_cidr, 1300).expect("run nat");
        let dns_client = DnsClient::new(&config.dns_servers, config.dns_timeout).await;

        let resolver = run_dns_resolver(&config, dns_client.resolver()).await;

        let extra_directly_servers = config
            .servers
            .iter()
            .map(|s| s.addr().to_string())
            .collect();

        let ping_url = vec![
            (
                Address::DomainNameAddress("google.com".to_string(), 80),
                "/".to_string(),
            ),
            (
                Address::DomainNameAddress("twitter.com".to_string(), 80),
                "/".to_string(),
            ),
            (
                Address::DomainNameAddress("github.com".to_string(), 80),
                "/".to_string(),
            ),
            (
                Address::DomainNameAddress("youtube.com".to_string(), 80),
                "/".to_string(),
            ),
        ];
        let chooser = Arc::new(
            ServerChooser::new(
                config.servers.clone(),
                dns_client.clone(),
                ping_url,
                config.ping_timeout,
            )
            .await,
        );
        let chooser_clone = chooser.clone();
        if config.servers.len() > 1 {
            let _ = spawn(async move { chooser_clone.ping_servers_forever().await.unwrap() });
        }

        Self {
            resolver,
            extra_directly_servers,
            udp_manager: Arc::new(RwLock::new(HashMap::new())),
            dns_client,
            config,
            uid,
            session_manager,
            server_chooser: chooser,
        }
    }

    async fn get_action_for_addr(
        &self,
        original_addr: SocketAddr,
        socket_addr: SocketAddr,
        addr: &Address,
    ) -> Result<Action> {
        let mut pass_proxy = false;
        let domain = match &addr {
            // 如果是 IP 说明是用户手动改了路由表，必须要走代理。
            Address::SocketAddress(_) => {
                return Ok(Action::Proxy);
            }
            Address::DomainNameAddress(domain, _port) => domain.to_string(),
        };
        if self.extra_directly_servers.contains(&domain) {
            pass_proxy = true;
        }
        if let Some(uid) = self.uid {
            if !socket_addr_belong_to_user(original_addr, uid)? {
                pass_proxy = true;
            }
        }
        let mut action = if pass_proxy {
            Action::Direct
        } else {
            self.config
                .rules
                .action_for_domain(&domain)
                .unwrap_or_else(|| self.config.rules.default_action())
        };

        if action == Action::Probe {
            if self.probe_connectivity(socket_addr).await {
                action = Action::Direct;
            } else {
                action = Action::Proxy;
            }
        }

        Ok(action)
    }

    async fn choose_proxy_tcp_stream(
        &self,
        original_addr: SocketAddr,
        sock_addr: SocketAddr,
        remote_addr: &Address,
    ) -> Result<ProxyTcpStream> {
        let action = self
            .get_action_for_addr(original_addr, sock_addr, &remote_addr)
            .await?;
        trace!(?action, "selected action");
        retry_timeout!(
            self.config.connect_timeout,
            self.config.max_connect_errors,
            self.server_chooser
                .candidate_tcp_stream(remote_addr.clone(), action)
        )
        .await
    }

    async fn choose_proxy_udp_socket(
        &self,
        original_addr: SocketAddr,
        sock_addr: SocketAddr,
        remote_addr: &Address,
    ) -> Result<ProxyUdpSocket> {
        let action = self
            .get_action_for_addr(original_addr, sock_addr, &remote_addr)
            .await?;

        retry_timeout!(
            self.config.connect_timeout,
            self.config.max_connect_errors,
            self.server_chooser.candidate_udp_socket(action)
        )
        .await
    }

    async fn probe_connectivity(&self, addr: SocketAddr) -> bool {
        timeout(self.config.probe_timeout, TcpStream::connect(addr))
            .await
            .is_ok()
    }

    async fn run_tcp_relay_server(&self) -> Result<()> {
        let listener = TcpListener::bind((self.config.tun_ip, 1300)).await?;
        let mut incoming = listener.incoming();
        while let Some(Ok(conn)) = incoming.next().await {
            let peer_addr = conn.peer_addr()?;
            let (real_src, real_dest) = match self.session_manager.get_by_port(peer_addr.port()) {
                Some(s) => s,
                None => continue,
            };

            async {
                let ip = real_dest.ip().to_string();
                let host = self
                    .resolver
                    .lookup_host(&ip)
                    .map(|s| Address::DomainNameAddress(s, real_dest.port()))
                    .unwrap_or_else(|| Address::SocketAddress(real_dest));

                trace!(dest_host = ?host, "new relay connection");

                let sock_addr = match self.dns_client.lookup_address(&host).await {
                    Ok(a) => a,
                    Err(e) => {
                        error!(?e, ?host, "error resolve dns");
                        return;
                    }
                };

                trace!(ip = ?ip, host = ?host, "lookup host");

                match self
                    .choose_proxy_tcp_stream(real_src, sock_addr, &host)
                    .await
                {
                    Ok(remote_conn) => {
                        trace!("connect successfully");
                        spawn(async move { tunnel_tcp_stream(conn, remote_conn).await });
                    }
                    Err(e) => {
                        error!(?e, "connect error");
                    }
                };
            }
            .instrument(trace_span!(
                "tcp connection",
                ?peer_addr,
                ?real_src,
                ?real_dest
            ))
            .await
        }
        Ok::<(), io::Error>(())
    }

    pub async fn run(&self) {
        self.run_tcp_relay_server()
            .race(self.run_udp_relay_server())
            .await
            .unwrap();
    }

    fn get_udp_socket_and_dest_addr(&self, port: u16) -> Option<(ProxyUdpSocket, SocketAddr)> {
        let (real_src, real_dest) = self.session_manager.get_by_port(port)?;
        trace!(?real_src, ?real_dest, "new udp relay packet");

        self.udp_manager.read().get(&port).cloned()
    }

    async fn new_udp_socket(&self, port: u16) -> Result<(ProxyUdpSocket, SocketAddr)> {
        let (real_src, real_dest) = match self.session_manager.get_by_port(port) {
            Some(s) => s,
            None => return Err(io::ErrorKind::AddrNotAvailable.into()),
        };

        trace!(?real_src, ?real_dest, "new udp relay packet");

        if let Some(r) = self.udp_manager.read().get(&port) {
            return Ok(r.clone());
        }

        let ip = real_dest.ip().to_string();
        let host = self
            .resolver
            .lookup_host(&ip)
            .map(|s| Address::DomainNameAddress(s, real_dest.port()))
            .unwrap_or_else(|| Address::SocketAddress(real_dest));
        let sock_addr = self.dns_client.lookup_address(&host).await?;
        let socket = self
            .choose_proxy_udp_socket(real_src, sock_addr, &host)
            .await?;
        self.udp_manager
            .write()
            .insert(port, (socket.clone(), sock_addr));
        Ok((socket, sock_addr))
    }

    async fn run_udp_relay_server(&self) -> Result<()> {
        let udp_listener = Arc::new(UdpSocket::bind("0.0.0.0:1300").await?);
        let recv_timeout = self.config.read_timeout;
        let write_timeout = self.config.write_timeout;
        let mut buf = vec![0; 2000];
        loop {
            let (size, peer_addr) = udp_listener.recv_from(&mut buf).await?;
            assert!(size < 2000);
            let (socket, dest_addr) = match self.get_udp_socket_and_dest_addr(peer_addr.port()) {
                None => {
                    let (socket, dest_addr) = match self.new_udp_socket(peer_addr.port()).await {
                        Ok(r) => r,
                        Err(e) => {
                            error!(?e, "new udp socket");
                            continue;
                        }
                    };
                    let socket_clone = socket.clone();
                    let udp_listener_clone = udp_listener.clone();

                    let udp_manager = self.udp_manager.clone();
                    spawn(async move {
                        let _: Result<()> = async {
                            let mut buf = vec![0; 2000];
                            loop {
                                let (recv_size, _peer) =
                                    timeout(recv_timeout, socket_clone.recv_from(&mut buf)).await?;
                                assert!(recv_size < 2000);
                                let send_size = timeout(
                                    write_timeout,
                                    udp_listener_clone.send_to(&buf[..size], peer_addr),
                                )
                                .await?;
                                assert_eq!(send_size, size);
                            }
                        }
                        .await;
                        let _ = udp_manager.write().remove(&peer_addr.port());
                    });
                    (socket, dest_addr)
                }
                Some(r) => r,
            };
            match timeout(write_timeout, socket.send_to(&buf[..size], dest_addr)).await {
                Ok(send_size) => {
                    assert_eq!(size, send_size);
                }
                Err(e) => error!(?e, "send to {}", dest_addr),
            };
        }
    }
}

async fn tunnel_tcp_stream<T1: Read + Write + Unpin + Clone, T2: Read + Write + Unpin + Clone>(
    mut conn1: T1,
    mut conn2: T2,
) -> Result<()> {
    let mut conn1_clone = conn1.clone();
    let mut conn2_clone = conn2.clone();
    let f1 = async {
        let mut buf = vec![0; 1500];
        loop {
            let size = conn1.read(&mut buf).await?;
            if size == 0 {
                break Ok(());
            }
            conn2.write_all(&buf[..size]).await?;
        }
    };
    let f2 = async {
        let mut buf = vec![0; 1500];
        loop {
            let size = conn2_clone.read(&mut buf).await?;
            if size == 0 {
                break Ok(());
            }
            conn1_clone.write_all(&buf[..size]).await?;
        }
    };
    f1.race(f2).await
}

async fn run_dns_resolver(config: &Config, resolver: AsyncStdResolver) -> RuleBasedDnsResolver {
    let (dns_server, resolver) = create_dns_server(
        "dns.db",
        config.dns_listen.clone(),
        config.dns_start_ip,
        config.rules.clone(),
        resolver,
    )
    .await;
    println!("Spawn DNS server");
    spawn(
        dns_server
            .run_server()
            .instrument(trace_span!("dns_server.run_server")),
    );
    resolver
}

#[cfg(target_arch = "x86_64")]
fn socket_addr_belong_to_user(addr: SocketAddr, uid: u32) -> Result<bool> {
    use sysconfig::SocketInfo;
    let user_socks: HashMap<i32, Vec<SocketInfo>> = sysconfig::list_user_proc_socks(uid)?;
    Ok(user_socks
        .values()
        .any(|sockets| sockets.iter().any(|s| s.local == addr)))
}

#[cfg(not(target_arch = "x86_64"))]
fn socket_addr_belong_to_user(_addr: SocketAddr, _uid: u32) -> Result<bool> {
    Ok(true)
}
