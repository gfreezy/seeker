use async_std::io;
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::FutureExt;
use async_std::sync::RwLock;
use async_std::task;
use async_std::task::JoinHandle;
use config::rule::{Action, ProxyRules};
use config::{Address, Config};
use futures::io::Error;
use hermesdns::DnsNetworkClient;
use ssclient::{resolve_domain, SSClient};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysconfig::{list_user_proc_socks, SocketInfo};
use tracing::{error, info, trace, trace_span};
use tracing_futures::Instrument;
use tun::socket::{TunTcpSocket, TunUdpSocket};

#[async_trait::async_trait]
pub trait Client {
    async fn handle_tcp(&self, socket: TunTcpSocket, addr: Address) -> Result<()>;
    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()>;
}

#[async_trait::async_trait]
impl Client for SSClient {
    async fn handle_tcp(&self, socket: TunTcpSocket, addr: Address) -> Result<()> {
        self.handle_tcp_connection(socket, addr).await
    }

    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()> {
        self.handle_udp_connection(socket, addr).await
    }
}

struct DirectClient {
    resolver: DnsNetworkClient,
    dns_server: (String, u16),
    connect_timeout: Duration,
    probe_timeout: Duration,
}

impl DirectClient {
    pub async fn new(
        dns_server: (String, u16),
        connect_timeout: Duration,
        probe_timeout: Duration,
    ) -> Self {
        DirectClient {
            resolver: DnsNetworkClient::new(0, connect_timeout).await,
            dns_server,
            connect_timeout,
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
        return Ok(conn);
    }
}

#[async_trait::async_trait]
impl Client for DirectClient {
    async fn handle_tcp(&self, mut socket: TunTcpSocket, addr: Address) -> Result<()> {
        let conn = self.connect(addr, self.connect_timeout).await?;
        let mut socket_clone = socket.clone();
        let mut ref_conn = &conn;
        let mut ref_conn2 = &conn;
        let a = io::copy(&mut socket_clone, &mut ref_conn);
        let b = io::copy(&mut ref_conn2, &mut socket);
        let (ret_a, ret_b) = a.join(b).await;
        ret_a?;
        ret_b?;
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
            let (recv_from_local_size, local_src) = socket.recv_from(&mut buf).await?;
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
                    let _handle: JoinHandle<Result<_>> = task::spawn(async move {
                        let mut recv_buf = vec![0; 1024];
                        loop {
                            let now = Instant::now();
                            let (recv_from_ss_size, udp_ss_addr) =
                                cloned_new_udp.recv_from(&mut recv_buf).await?;
                            let duration = now.elapsed();
                            trace!(duration = ?duration, size = recv_from_ss_size, src_addr = %udp_ss_addr, local_udp_socket = ?bind_addr, "recv from ss server");
                            let now = Instant::now();
                            let send_local_size = cloned_socket
                                .send_to(&recv_buf[..recv_from_ss_size], &local_src)
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
            let send_ss_size = udp_socket
                .send_to(&buf[..recv_from_local_size], sock_addr)
                .await?;
            let duration = now.elapsed();
            trace!(duration = ?duration, size = send_ss_size, dst_addr = %sock_addr, local_udp_socket = ?bind_addr, "send to ss server");
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RuledClient {
    conf: Config,
    rule: ProxyRules,
    ssclient: Arc<RwLock<SSClient>>,
    direct_client: Arc<DirectClient>,
    proxy_uid: Option<u32>,
    term: Arc<AtomicBool>,
}

async fn new_ssclient(conf: &Config, conf_index: usize) -> SSClient {
    let dns = conf.dns_server;
    let dns_server_addr = (dns.ip().to_string(), dns.port());

    SSClient::new(
        Arc::new(
            conf.server_configs
                .get(conf_index)
                .expect("no config at index")
                .clone(),
        ),
        dns_server_addr.clone(),
    )
    .await
}

async fn new_direct_client(conf: &Config) -> DirectClient {
    let dns = conf.dns_server;
    let dns_server_addr = (dns.ip().to_string(), dns.port());
    DirectClient::new(
        dns_server_addr,
        conf.direct_connect_timeout,
        conf.probe_timeout,
    )
    .await
}

impl RuledClient {
    pub async fn new(conf: Config, proxy_uid: Option<u32>, to_terminate: Arc<AtomicBool>) -> Self {
        RuledClient {
            term: to_terminate.clone(),
            rule: conf.rules.clone(),
            ssclient: Arc::new(RwLock::new(new_ssclient(&conf, 0).await)),
            direct_client: Arc::new(new_direct_client(&conf).await),
            conf: conf,
            proxy_uid,
        }
    }

    async fn get_action_for_addr(&self, remote_addr: SocketAddr, addr: &Address) -> Result<Action> {
        let domain = match &addr {
            Address::SocketAddress(a) => a.to_string(),
            Address::DomainNameAddress(domain, _port) => domain.to_string(),
        };
        let mut pass_proxy = false;
        if let Some(uid) = self.proxy_uid {
            if !socket_addr_belong_to_user(remote_addr, uid)? {
                pass_proxy = true;
            }
        }
        let mut action = if pass_proxy {
            Action::Direct
        } else {
            self.rule
                .action_for_domain(&domain)
                .unwrap_or_else(|| self.rule.default_action())
        };

        if action == Action::Probe {
            if self.direct_client.probe_connectivity(addr.clone()).await {
                action = Action::Direct;
            } else {
                action = Action::Proxy;
            }
            info!(addr = %addr, action = ?action, "Probe action");
        } else {
            info!(addr = %addr, action = ?action, "Rule action");
        }

        Ok(action)
    }
}

#[async_trait::async_trait]
impl Client for RuledClient {
    async fn handle_tcp(&self, socket: TunTcpSocket, addr: Address) -> Result<()> {
        let action = self
            .get_action_for_addr(socket.remote_addr(), &addr)
            .await?;

        match action {
            Action::Reject => Ok(()),
            Action::Direct => {
                self.direct_client
                    .handle_tcp(socket, addr.clone())
                    .instrument(trace_span!("DirectClient.handle_tcp", addr = %addr))
                    .await
            }
            Action::Proxy => {
                let old_client = self.ssclient.read().await;
                let connect_errors = old_client.connect_errors();
                let old_conf_index = self
                    .conf
                    .server_configs
                    .iter()
                    .position(|s| s.name() == old_client.srv_cfg.name())
                    .unwrap_or(0);
                if connect_errors > self.conf.max_connect_errors {
                    let next_conf_index = (old_conf_index + 1) % self.conf.server_configs.len();
                    error!(
                        "SSClient '{}' reached max connect errors, change to another server '{}'",
                        self.conf.server_configs[old_conf_index].name(),
                        self.conf.server_configs[next_conf_index].name()
                    );
                    *self.ssclient.write().await = new_ssclient(&self.conf, next_conf_index).await;
                }
                self.ssclient
                    .read()
                    .await
                    .handle_tcp(socket, addr.clone())
                    .instrument(trace_span!("SSClient.handle_tcp", addr = %addr))
                    .await
            }
            Action::Probe => unreachable!(),
        }
    }

    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()> {
        // FIXME: `socket.local_addr` is not right
        let action = self.get_action_for_addr(socket.local_addr(), &addr).await?;

        match action {
            Action::Reject => Ok(()),
            Action::Direct => self.direct_client.handle_udp(socket, addr).await,
            Action::Proxy => self.ssclient.read().await.handle_udp(socket, addr).await,
            Action::Probe => unreachable!(),
        }
    }
}

fn socket_addr_belong_to_user(addr: SocketAddr, uid: u32) -> Result<bool> {
    let user_socks: HashMap<i32, Vec<SocketInfo>> = list_user_proc_socks(uid)?;
    Ok(user_socks
        .values()
        .any(|sockets| sockets.iter().any(|s| s.local == addr)))
}
