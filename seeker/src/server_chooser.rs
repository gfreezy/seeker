use crate::dns_client::DnsClient;
use crate::group_servers_chooser::GroupServersChooser;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use crate::server_performance::ServerPerformanceTracker;
use anyhow::Result;
use async_std::task::spawn;
use config::rule::Action;
use config::{Address, Config, ServerConfig};
use futures_util::future::join_all;
use std::collections::HashMap;

#[derive(Clone)]
pub struct ServerChooser {
    dns_client: DnsClient,
    group_servers_chooser: HashMap<String, GroupServersChooser>,
}

#[derive(Clone)]
pub(crate) struct CandidateTcpStream {
    pub stream: ProxyTcpStream,
    pub proxy_group_name: String,
    pub server_config: Option<ServerConfig>,
}

#[derive(Clone)]
pub(crate) struct CandidateUdpSocket {
    pub socket: ProxyUdpSocket,
    pub proxy_group_name: String,
    pub server_config: Option<ServerConfig>,
}

impl ServerChooser {
    pub async fn new(config: Config, dns_client: DnsClient, show_stats: bool) -> Self {
        let mut group_servers_chooser = HashMap::new();
        for group in config.proxy_groups.iter() {
            let ping_urls = if group.ping_urls.is_empty() {
                config.ping_urls.clone()
            } else {
                group.ping_urls.clone()
            };
            let ping_timeout = if let Some(ping_timeout) = group.ping_timeout {
                ping_timeout
            } else {
                config.ping_timeout
            };
            let servers = config.get_servers_by_name(&group.name);
            group_servers_chooser.insert(
                group.name.clone(),
                GroupServersChooser::new(
                    group.name.clone(),
                    servers,
                    dns_client.clone(),
                    ping_urls,
                    ping_timeout,
                    show_stats,
                )
                .await,
            );
        }
        Self {
            dns_client,
            group_servers_chooser,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn candidate_tcp_stream(
        &self,
        remote_addr: Address,
        action: Action,
    ) -> std::io::Result<CandidateTcpStream> {
        let candidate_tcp_stream = match action {
            Action::Proxy(proxy_group_name) => {
                self.proxy_connect(&remote_addr, &proxy_group_name).await?
            }
            Action::Direct => self.direct_connect(&remote_addr).await?,
            _ => unreachable!(),
        };

        Ok(candidate_tcp_stream)
    }

    pub async fn proxy_connect(
        &self,
        remote_addr: &Address,
        proxy_group_name: &str,
    ) -> std::io::Result<CandidateTcpStream> {
        let Some(chooser) = self.group_servers_chooser.get(proxy_group_name) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("proxy group {proxy_group_name} not found"),
            ));
        };
        chooser.proxy_connect(remote_addr).await
    }

    async fn direct_connect(&self, remote_addr: &Address) -> std::io::Result<CandidateTcpStream> {
        let ret = ProxyTcpStream::connect(remote_addr.clone(), None, self.dns_client.clone()).await;
        if ret.is_err() {
            tracing::error!(?remote_addr, action = ?Action::Direct, "Failed to connect to server");
        }
        Ok(CandidateTcpStream {
            stream: ret?,
            proxy_group_name: "".to_string(),
            server_config: None,
        })
    }

    pub async fn candidate_udp_socket(
        &self,
        action: Action,
    ) -> std::io::Result<CandidateUdpSocket> {
        let socket = match &action {
            Action::Direct => {
                let udp_socket = ProxyUdpSocket::new(None, self.dns_client.clone()).await?;
                CandidateUdpSocket {
                    socket: udp_socket,
                    proxy_group_name: "".to_string(),
                    server_config: None,
                }
            }
            Action::Proxy(proxy_group_name) => {
                let Some(chooser) = self.group_servers_chooser.get(proxy_group_name) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("proxy group {proxy_group_name} not found"),
                    ));
                };

                chooser.candidate_udp_socket(action.clone()).await?
            }
            _ => unreachable!(),
        };
        Ok(socket)
    }

    pub async fn run_background_tasks(&self) -> Result<()> {
        let mut handles = Vec::new();
        for chooser in self.group_servers_chooser.values() {
            let chooser = chooser.clone();
            handles.push(spawn(async move { chooser.run_background_tasks().await }));
        }
        join_all(handles).await.into_iter().collect()
    }

    pub fn get_performance_tracker(
        &self,
        proxy_group_name: &str,
    ) -> Option<ServerPerformanceTracker> {
        self.group_servers_chooser
            .get(proxy_group_name)
            .map(|chooser| chooser.get_performance_tracker())
    }
}
