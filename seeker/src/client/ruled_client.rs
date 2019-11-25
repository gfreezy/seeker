use super::direct_client::DirectClient;
use crate::client::Client;
use async_std::sync::RwLock;
use config::rule::{Action, ProxyRules};
use config::{Address, Config};
use ssclient::SSClient;
use std::collections::HashMap;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use sysconfig::{list_user_proc_socks, SocketInfo};
use tracing::{error, info, trace_span};
use tracing_futures::Instrument;
use tun::socket::{TunTcpSocket, TunUdpSocket};

#[derive(Clone)]
pub struct RuledClient {
    conf: Config,
    rule: ProxyRules,
    ssclient: Arc<SSClient>,
    direct_client: Arc<DirectClient>,
    proxy_uid: Option<u32>,
    term: Arc<AtomicBool>,
}

async fn new_ssclient(conf: &Config, conf_index: usize) -> SSClient {
    let dns = conf.dns_server;
    let dns_server_addr = (dns.ip().to_string(), dns.port());

    info!("new_ssclient: {}", conf_index);
    SSClient::new(
        Arc::new(RwLock::new(
            conf.server_configs
                .get(conf_index)
                .expect("no config at index")
                .clone(),
        )),
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
            ssclient: Arc::new(new_ssclient(&conf, 0).await),
            direct_client: Arc::new(new_direct_client(&conf).await),
            conf,
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
                let client = self.ssclient.clone();
                let connect_errors = client.connect_errors();
                let old_server_name = client.name().await;
                if connect_errors > self.conf.max_connect_errors {
                    let old_conf_index = self
                        .conf
                        .server_configs
                        .iter()
                        .position(|s| s.name() == old_server_name)
                        .unwrap_or(0);
                    let next_conf_index = (old_conf_index + 1) % self.conf.server_configs.len();
                    error!(
                        "SSClient '{}' reached max connect errors, change to another server '{}'",
                        self.conf.server_configs[old_conf_index].name(),
                        self.conf.server_configs[next_conf_index].name()
                    );
                    let new_conf = self
                        .conf
                        .server_configs
                        .get(next_conf_index)
                        .expect("no config at index")
                        .clone();
                    client.change_conf(new_conf).await;
                    error!("new ssclient with new conf");
                }
                self.ssclient
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
            Action::Proxy => self.ssclient.handle_udp(socket, addr).await,
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
