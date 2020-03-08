use std::collections::HashMap;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_std::sync::RwLock;
use async_std::task;
use chrono::{DateTime, Local};
use tracing::{error, info, trace, trace_span};
use tracing_futures::Instrument;

use config::rule::{Action, ProxyRules};
use config::{Address, Config};
use ssclient::SSClient;
use sysconfig::{list_user_proc_socks, SocketInfo};
use tun::socket::{TunTcpSocket, TunUdpSocket};

use crate::client::Client;

use super::direct_client::DirectClient;
use crate::client::socks5_client::Socks5Client;

#[derive(Hash, Debug, Eq, PartialEq)]
struct Connection {
    address: Address,
    connect_time: DateTime<Local>,
    sent_bytes: u64,
    recv_bytes: u64,
    action: Action,
}

#[derive(Clone)]
pub struct RuledClient {
    conf: Config,
    rule: ProxyRules,
    extra_directly_servers: Arc<Vec<String>>,
    ssclient: Option<Arc<SSClient>>,
    socks5_client: Option<Arc<Socks5Client>>,
    direct_client: Arc<DirectClient>,
    proxy_uid: Option<u32>,
    term: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
    connections: Arc<Mutex<HashMap<u64, Connection>>>,
}

async fn new_ssclient(conf: &Config, conf_index: usize) -> Option<SSClient> {
    let dns = conf.dns_server;
    let dns_server_addr = (dns.ip().to_string(), dns.port());

    info!("new_ssclient: {}", conf_index);
    let server = conf
        .shadowsocks_servers
        .as_ref()?
        .get(conf_index)
        .expect("no config at index")
        .clone();

    Some(SSClient::new(Arc::new(RwLock::new(server)), dns_server_addr.clone()).await)
}

async fn new_direct_client(conf: &Config) -> DirectClient {
    let dns = conf.dns_server;
    let dns_server_addr = (dns.ip().to_string(), dns.port());
    DirectClient::new(
        dns_server_addr,
        conf.direct_connect_timeout,
        conf.direct_read_timeout,
        conf.direct_write_timeout,
        conf.probe_timeout,
    )
    .await
}

async fn new_socks5_client(conf: &Config) -> Option<Socks5Client> {
    let dns = conf.dns_server;
    let dns_server_addr = (dns.ip().to_string(), dns.port());
    let socks_config = conf.socks5_server.clone()?;
    Some(
        Socks5Client::new(
            dns_server_addr,
            socks_config.addr,
            socks_config.connect_timeout,
            socks_config.read_timeout,
            socks_config.write_timeout,
        )
        .await,
    )
}

impl RuledClient {
    pub async fn new(
        conf: Config,
        proxy_uid: Option<u32>,
        to_terminate: Arc<AtomicBool>,
    ) -> RuledClient {
        let mut extra_directly_servers = vec![];

        // always pass proxy for socks5 server
        if let Some(socks5_addr) = &conf.socks5_server {
            extra_directly_servers.push(socks5_addr.addr.to_string());
        }

        if let Some(shadowsocks_servers) = &conf.shadowsocks_servers {
            for shadowsocks_server in shadowsocks_servers.iter() {
                extra_directly_servers.push(shadowsocks_server.addr().to_string());
            }
        }

        let socks5_client = new_socks5_client(&conf).await.map(Arc::new);
        let ssclient = if socks5_client.is_none() {
            new_ssclient(&conf, 0).await.map(Arc::new)
        } else {
            None
        };
        let verbose = conf.verbose;
        let c = RuledClient {
            term: to_terminate.clone(),
            extra_directly_servers: Arc::new(extra_directly_servers),
            rule: conf.rules.clone(),
            ssclient,
            socks5_client,
            direct_client: Arc::new(new_direct_client(&conf).await),
            conf,
            proxy_uid,
            counter: Arc::new(AtomicU64::new(0)),
            connections: Arc::new(Mutex::new(HashMap::new())),
        };
        if verbose {
            let client = c.clone();
            let _ = task::spawn(async move {
                loop {
                    println!("\nConnections:");
                    if let Some(ssclient) = &client.ssclient {
                        ssclient.stats().print_stats().await;
                    }
                    client.direct_client.stats().print_stats().await;
                    if let Some(socks5_client) = &client.socks5_client {
                        socks5_client.stats().print_stats().await;
                    }
                    println!();
                    if let Some(ssclient) = &client.ssclient {
                        ssclient.stats().recycle_stats().await;
                    }
                    client.direct_client.stats().recycle_stats().await;
                    if let Some(socks5_client) = &client.socks5_client {
                        socks5_client.stats().recycle_stats().await;
                    }
                    task::sleep(Duration::from_secs(5)).await;
                }
            });
        }
        c
    }

    #[allow(clippy::useless_let_if_seq)]
    async fn get_action_for_addr(&self, remote_addr: SocketAddr, addr: &Address) -> Result<Action> {
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

    async fn shadowsocks_handle_tcp(&self, socket: TunTcpSocket, addr: Address) -> Result<()> {
        let (ssclient, shadowsocks_servers) = match (&self.ssclient, &self.conf.shadowsocks_servers)
        {
            (Some(ssclient), Some(shadowsocks_servers)) => (ssclient.clone(), shadowsocks_servers),
            _ => {
                return Ok(());
            }
        };
        let connect_errors = ssclient.connect_errors();
        let old_server_name = ssclient.name().await;
        if connect_errors > self.conf.max_connect_errors {
            let old_conf_index = shadowsocks_servers
                .iter()
                .position(|s| s.name() == old_server_name)
                .unwrap_or(0);
            let next_conf_index = (old_conf_index + 1) % shadowsocks_servers.len();
            error!(
                "SSClient '{}' reached max connect errors, change to another server '{}'",
                shadowsocks_servers[old_conf_index].name(),
                shadowsocks_servers[next_conf_index].name()
            );
            let new_conf = shadowsocks_servers
                .get(next_conf_index)
                .expect("no config at index")
                .clone();
            ssclient.change_conf(new_conf).await;
            error!("new ssclient with new conf");
        }
        ssclient
            .handle_tcp(socket, addr.clone())
            .instrument(trace_span!("SSClient.handle_tcp", addr = %addr))
            .await
    }
}

#[async_trait::async_trait]
impl Client for RuledClient {
    async fn handle_tcp(&self, socket: TunTcpSocket, addr: Address) -> Result<()> {
        let action = self
            .get_action_for_addr(socket.remote_addr(), &addr)
            .instrument(trace_span!("get action for addr",))
            .await?;

        trace!(action = ?action, "get action for addr");

        let index = self.counter.fetch_add(1, SeqCst);
        {
            let mut conn = self.connections.lock().unwrap();
            conn.insert(
                index,
                Connection {
                    address: addr.clone(),
                    connect_time: Local::now(),
                    sent_bytes: 0,
                    recv_bytes: 0,
                    action,
                },
            );
        }

        let ret = match action {
            Action::Reject => Ok(()),
            Action::Direct => {
                self.direct_client
                    .handle_tcp(socket, addr.clone())
                    .instrument(trace_span!("DirectClient.handle_tcp", addr = %addr))
                    .await
            }
            Action::Proxy => {
                if let Some(socks5_client) = &self.socks5_client {
                    socks5_client.handle_tcp(socket, addr.clone()).await
                } else {
                    self.shadowsocks_handle_tcp(socket, addr.clone()).await
                }
            }
            Action::Probe => unreachable!(),
        };
        {
            let conn = self.connections.lock().unwrap().remove(&index);
            if let Some(conn) = conn {
                if let Err(e) = &ret {
                    trace!("Interrupt connection {}: {:?}, connect time: {}, duration: {}s, addr: {}, action: {:?}", e, index, conn.connect_time.format("%Y-%m-%d %H:%M:%S").to_string(), (Local::now() - conn.connect_time).num_seconds(), conn.address, conn.action);
                } else {
                    trace!("Close connection {}, connect time: {}, duration: {}s, addr: {}, action: {:?}", index, conn.connect_time.format("%Y-%m-%d %H:%M:%S").to_string(), (Local::now() - conn.connect_time).num_seconds(), conn.address, conn.action);
                }
            }
        }
        ret
    }

    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()> {
        // FIXME: `socket.local_addr` is not right, should be socket.remote_addr(). However, Udp socket doesn't have a `remote_addr`
        let action = self.get_action_for_addr(socket.local_addr(), &addr).await?;

        match action {
            Action::Reject => Ok(()),
            Action::Direct => {
                self.direct_client
                    .handle_udp(socket, addr)
                    .instrument(trace_span!("handl_direct_udp"))
                    .await
            }
            Action::Proxy => {
                if let Some(socks5_client) = &self.socks5_client {
                    socks5_client
                        .handle_udp(socket, addr)
                        .instrument(trace_span!("handle_socks_udp"))
                        .await
                } else if let Some(client) = &self.ssclient {
                    client
                        .handle_udp(socket, addr)
                        .instrument(trace_span!("handl_shadowsocks_udp"))
                        .await
                } else {
                    Ok(())
                }
            }
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
