use async_std::future;
use async_std::io::copy;
use async_std::net::TcpStream;
use config::rule::{Action, ProxyRules};
use config::{Address, Config};
use futures::io::Error;
use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
use ssclient::SSClient;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use sysconfig::{list_user_proc_socks, SocketInfo};
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
}

impl DirectClient {
    pub async fn new(dns_server: (String, u16)) -> Self {
        DirectClient {
            resolver: DnsNetworkClient::new(0).await,
            dns_server,
        }
    }

    fn dns_server(&self) -> (&str, u16) {
        (&self.dns_server.0, self.dns_server.1)
    }

    async fn lookup_ip(&self, domain: &str) -> Result<Option<String>> {
        let packet = self
            .resolver
            .send_query(domain, QueryType::A, self.dns_server(), true)
            .await?;
        Ok(packet.get_random_a())
    }
}

#[async_trait::async_trait]
impl Client for DirectClient {
    async fn handle_tcp(&self, mut socket: TunTcpSocket, addr: Address) -> Result<()> {
        let sock_addr = match addr {
            Address::SocketAddress(addr) => addr,
            Address::DomainNameAddress(domain, port) => {
                let ip = self.lookup_ip(&domain).await?;
                match ip {
                    None => {
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            format!("domain {} not found", &domain),
                        ))
                    }
                    Some(ip) => SocketAddr::new(ip.parse().expect("not valid ip addr"), port),
                }
            }
        };
        let conn = TcpStream::connect(sock_addr).await?;
        let mut socket_clone = socket.clone();
        let mut ref_conn = &conn;
        let mut ref_conn2 = &conn;
        let a = copy(&mut socket_clone, &mut ref_conn);
        let b = copy(&mut ref_conn2, &mut socket);
        let (ret_a, ret_b) = future::join!(a, b).await;
        ret_a?;
        ret_b?;
        Ok(())
    }

    async fn handle_udp(&self, _socket: TunUdpSocket, _addr: Address) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct RuledClient {
    rule: ProxyRules,
    ssclient: SSClient,
    direct_client: Arc<DirectClient>,
    proxy_uid: Option<u32>,
}

impl RuledClient {
    pub async fn new(conf: Config, proxy_uid: Option<u32>, to_terminal: Arc<AtomicBool>) -> Self {
        let dns = conf.dns_server;
        let dns_server_addr = (dns.ip().to_string(), dns.port());

        let ssclient = SSClient::new(
            conf.server_config.clone(),
            dns_server_addr.clone(),
            to_terminal,
        )
        .await;
        let direct_client = DirectClient::new(dns_server_addr).await;
        RuledClient {
            rule: conf.rules.clone(),
            ssclient,
            direct_client: Arc::new(direct_client),
            proxy_uid,
        }
    }
}

#[async_trait::async_trait]
impl Client for RuledClient {
    async fn handle_tcp(&self, socket: TunTcpSocket, addr: Address) -> Result<()> {
        let domain = match &addr {
            Address::SocketAddress(a) => a.to_string(),
            Address::DomainNameAddress(domain, _port) => domain.to_string(),
        };
        let mut pass_proxy = false;
        if let Some(uid) = self.proxy_uid {
            if !socket_addr_belong_to_user(socket.remote_addr(), uid)? {
                pass_proxy = true;
            }
        }
        let action = if pass_proxy {
            Action::Direct
        } else {
            self.rule
                .action_for_domain(&domain)
                .unwrap_or_else(|| self.rule.default_action())
        };
        match action {
            Action::Reject => Ok(()),
            Action::Direct => self.direct_client.handle_tcp(socket, addr).await,
            Action::Proxy => self.ssclient.handle_tcp(socket, addr).await,
        }
    }

    async fn handle_udp(&self, _socket: TunUdpSocket, _addr: Address) -> Result<()> {
        Ok(())
    }
}

fn socket_addr_belong_to_user(addr: SocketAddr, uid: u32) -> Result<bool> {
    let user_socks: HashMap<i32, Vec<SocketInfo>> = list_user_proc_socks(uid)?;
    Ok(user_socks
        .values()
        .any(|sockets| sockets.iter().any(|s| s.local == addr)))
}
