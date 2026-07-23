use crate::dns_client::DnsClient;
use crate::group_servers_chooser::GroupServersChooser;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use crate::server_performance::{ServerPerformanceStats, ServerPerformanceTracker};

/// (selected_server_name, selected_server_addr, selected_protocol, Vec<(server_addr, server_name, protocol, stats)>)
type GroupPerformanceStats = (
    String,
    String,
    String,
    Vec<(String, String, String, ServerPerformanceStats)>,
);
use anyhow::Result;
use config::rule::Action;
use config::{Address, Config, ProxyGroup, ServerConfig};
use futures_util::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task;

#[derive(Clone)]
pub struct ServerChooser {
    dns_client: DnsClient,
    group_servers_chooser: HashMap<String, GroupServersChooser>,
}

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
            let ping_timeout = group.ping_timeout.unwrap_or(config.ping_timeout);
            let servers = config.get_servers_by_name(&group.name);
            group_servers_chooser.insert(
                group.name.clone(),
                GroupServersChooser::new(
                    group.name.clone(),
                    group.group_type,
                    group.default_selected.clone(),
                    servers,
                    dns_client.clone(),
                    ping_urls,
                    ping_timeout,
                    config.connect_timeout,
                    config.read_timeout,
                    config.write_timeout,
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
            handles.push(task::spawn(
                async move { chooser.run_background_tasks().await },
            ));
        }
        let results: Vec<_> = join_all(handles).await;
        for result in results {
            result??;
        }
        Ok(())
    }

    pub fn get_performance_tracker(
        &self,
        proxy_group_name: &str,
    ) -> Option<ServerPerformanceTracker> {
        self.group_servers_chooser
            .get(proxy_group_name)
            .map(|chooser| chooser.get_performance_tracker())
    }

    /// Returns a map of group_name -> (selected_server_addr, Vec<(server_addr, server_name, stats)>)
    pub fn get_all_performance_stats(&self) -> HashMap<String, GroupPerformanceStats> {
        let mut result = HashMap::new();
        for (group_name, chooser) in &self.group_servers_chooser {
            let tracker = chooser.get_performance_tracker();
            let (name, addr, protocol) = match chooser.get_selected_server() {
                Some(s) => (
                    s.name().to_string(),
                    s.addr().to_string(),
                    s.protocol().to_string(),
                ),
                None => (String::new(), String::new(), String::new()),
            };
            result.insert(
                group_name.clone(),
                (name, addr, protocol, tracker.get_all_server_stats()),
            );
        }
        result
    }

    /// Replace each group's server list, resolving from the new flat `servers`
    /// list via `proxy_groups[].proxies` (server names).
    ///
    /// Dangling names (referenced by a group but not present in `servers`) are
    /// dropped with a warning. Groups can end up with zero servers — subsequent
    /// `proxy_connect` calls against such groups will return an error until the
    /// next refresh.
    pub fn update_servers_for_groups(&self, servers: &[ServerConfig], proxy_groups: &[ProxyGroup]) {
        let by_name: HashMap<&str, &ServerConfig> = servers.iter().map(|s| (s.name(), s)).collect();

        for group in proxy_groups {
            let Some(chooser) = self.group_servers_chooser.get(&group.name) else {
                tracing::warn!(
                    group = group.name,
                    "Refresh: group not registered in chooser; skipping"
                );
                continue;
            };

            // The auto-injected anonymous default group tracks the full server
            // list rather than a fixed name list, so any newly-added remote
            // servers automatically join it.
            let resolved: Vec<ServerConfig> = if group.name.is_empty() {
                servers.to_vec()
            } else {
                let mut acc = Vec::with_capacity(group.proxies.len());
                for proxy_name in &group.proxies {
                    match by_name.get(proxy_name.as_str()) {
                        Some(server) => acc.push((*server).clone()),
                        None => tracing::warn!(
                            group = group.name,
                            proxy = proxy_name,
                            "Refresh: proxy name referenced by group is no longer in the server list; dropping"
                        ),
                    }
                }
                acc
            };

            chooser.update_servers(Arc::new(resolved));
        }
    }

    /// Reset all group servers choosers
    pub fn reset_all(&self) {
        tracing::info!("Resetting all server choosers");
        for (name, chooser) in &self.group_servers_chooser {
            tracing::info!(group = name, "Resetting group");
            chooser.reset();
        }
        tracing::info!("All server choosers reset completed");
    }
}
