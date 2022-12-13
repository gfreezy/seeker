use crate::dns_client::DnsClient;
use crate::proxy_connection::ProxyConnection;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use anyhow::Result;
use async_std::io::timeout;
use async_std::prelude::*;
use async_std::task::{sleep, spawn};
use config::rule::Action;
use config::{Address, PingURL, ServerConfig};
use futures_util::stream::FuturesUnordered;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Clone)]
pub struct ServerChooser {
    ping_urls: Vec<PingURL>,
    ping_timeout: Duration,
    servers: Arc<Vec<ServerConfig>>,
    candidates: Arc<Mutex<Vec<ServerConfig>>>,
    dns_client: DnsClient,
    live_connections: Arc<RwLock<Vec<Box<dyn ProxyConnection + Send + Sync>>>>,
}

impl ServerChooser {
    pub async fn new(
        servers: Arc<Vec<ServerConfig>>,
        dns_client: DnsClient,
        ping_urls: Vec<PingURL>,
        ping_timeout: Duration,
    ) -> Self {
        let chooser = ServerChooser {
            ping_urls,
            ping_timeout,
            candidates: Arc::new(Mutex::new(servers.iter().cloned().collect())),
            servers,
            dns_client,
            live_connections: Arc::new(RwLock::new(vec![])),
        };
        chooser.ping_servers().await;
        chooser
    }

    fn set_server_down(&self, config: &ServerConfig) {
        let live_connections = self.live_connections.write();
        live_connections
            .iter()
            .filter(|stream| stream.has_config(Some(config)))
            .for_each(|stream| stream.shutdown());
    }

    fn recycle_live_connections(&self) {
        self.live_connections
            .write()
            .retain(|stream| stream.strong_count() > 1);
    }

    #[tracing::instrument(skip(self))]
    pub async fn candidate_tcp_stream(
        &self,
        remote_addr: Address,
        action: Action,
    ) -> std::io::Result<ProxyTcpStream> {
        let stream = match action {
            Action::Proxy => {
                let config = self.candidates.lock().first().cloned().unwrap();
                let stream = ProxyTcpStream::connect(
                    remote_addr.clone(),
                    Some(&config),
                    self.dns_client.clone(),
                )
                .await;
                if stream.is_err() {
                    tracing::error!(
                        ?remote_addr,
                        ?action,
                        "Failed to connect to server: {}",
                        config.addr()
                    );
                    self.take_down_server_and_move_next(&config);
                }
                stream?
            }
            Action::Direct => {
                let ret =
                    ProxyTcpStream::connect(remote_addr.clone(), None, self.dns_client.clone())
                        .await;
                if ret.is_err() {
                    tracing::error!(?remote_addr, ?action, "Failed to connect to server");
                }
                ret?
            }
            _ => unreachable!(),
        };

        // store all on-fly connections
        let stream_clone = stream.clone();
        self.live_connections.write().push(Box::new(stream_clone));

        Ok(stream)
    }

    pub async fn candidate_udp_socket(&self, action: Action) -> std::io::Result<ProxyUdpSocket> {
        let socket = match action {
            Action::Direct => ProxyUdpSocket::new(None, self.dns_client.clone()).await?,
            Action::Proxy => {
                let config = self.candidates.lock().first().cloned().unwrap();
                let socket = ProxyUdpSocket::new(Some(&config), self.dns_client.clone()).await;
                if socket.is_err() {
                    self.take_down_server_and_move_next(&config);
                }
                socket?
            }
            _ => unreachable!(),
        };
        let socket_clone = socket.clone();
        self.live_connections.write().push(Box::new(socket_clone));
        Ok(socket)
    }

    pub fn take_down_server_and_move_next(&self, server: &ServerConfig) {
        // make sure `candidates` drop after block ends to avoid deadlock.
        let mut candidates = self.candidates.lock();
        if candidates.len() <= 1 {
            tracing::error!("Only 1 shadowsocks server available, all servers are down");
            return;
        }
        candidates.retain_mut(|c| c != server);
        self.set_server_down(server);
        let new = &candidates[0];
        info!(
            old_name = server.name(),
            old_server = ?server.addr(),
            new_name = new.name(),
            new_server = ?new.addr(),
            "Change shadowsocks server"
        );
    }

    pub async fn run_background_tasks(&self) -> Result<()> {
        loop {
            self.ping_servers().await;
            self.print_connection_stats();
            self.recycle_live_connections();
            sleep(Duration::from_secs(30)).await;
        }
    }

    fn print_connection_stats(&self) {
        #[derive(Default)]
        struct Stats {
            count: usize,
            send: usize,
            recv: usize,
            max_duration: Duration,
            action: Action,
        }
        let mut map: HashMap<String, Stats> = HashMap::new();
        for conn in self.live_connections.read().iter() {
            if let Some(addr) = conn.remote_addr() {
                let entry = map.entry(addr.to_string()).or_default();
                entry.action = conn.action();
                entry.count += 1;
                let traffic = conn.traffic();
                entry.send += traffic.sent_bytes();
                entry.recv += traffic.received_bytes();
                entry.max_duration = traffic.duration().max(entry.max_duration);
            }
        }
        println!("Connections:");
        let mut v: Vec<_> = map.into_iter().collect();
        v.sort_unstable_by(|(addr1, _), (addr2, _)| addr1.cmp(addr2));
        for (remote_addr, stats) in v {
            println!(
                "[{}] {}, conns: {}, max_duration: {}, sent_bytes: {}, recv_bytes: {}",
                stats.action,
                remote_addr,
                stats.count,
                stats.max_duration.as_secs(),
                stats.send,
                stats.recv
            );
        }
        println!();
    }

    pub async fn ping_servers(&self) {
        if self.ping_urls.is_empty() || self.servers.len() <= 1 {
            return;
        }

        let mut candidates = vec![];
        let mut fut: FuturesUnordered<_> = self
            .servers
            .iter()
            .map(|config| {
                let self_clone = self.clone();
                let config_clone = config.clone();
                spawn(async move {
                    let duration = self_clone
                        .ping_server(config_clone.clone())
                        .await
                        .map_err(|_| config_clone.clone())?;
                    Ok::<_, ServerConfig>((config_clone, duration))
                })
            })
            .collect();
        while let Some(ret) = fut.next().await {
            match ret {
                Ok((config, duration)) => {
                    info!(
                        name = config.name(),
                        server = ?config.addr(),
                        latency = %duration.as_millis(),
                        "Ping shadowsocks server"
                    );
                    candidates.push((config, duration));
                }
                Err(config) => {
                    info!(
                        name = config.name(),
                        server = ?config.addr(),
                        "Ping shadowsocks server error"
                    );
                }
            }
        }
        if !candidates.is_empty() {
            // sort by duration, shorter first.
            candidates.sort_by_key(|(_, duration)| *duration);
            *self.candidates.lock() = candidates.into_iter().map(|(config, _)| config).collect();
        }
    }

    async fn ping_server(&self, config: ServerConfig) -> std::io::Result<Duration> {
        let instant = Instant::now();
        for ping_url in &self.ping_urls {
            let addr = ping_url.address();
            let path = ping_url.path();
            let ret: std::io::Result<_> = timeout(self.ping_timeout, async {
                let mut conn =
                    ProxyTcpStream::connect(addr, Some(&config), self.dns_client.clone()).await?;
                conn.write_all(format!("GET {} HTTP/1.1\r\n\r\n", path).as_bytes())
                    .await?;
                let mut buf = vec![0; 1024];
                let _size = conn.read(&mut buf).await?;
                Ok(())
            })
            .await;
            if let Err(e) = ret {
                self.set_server_down(&config);
                return Err(e);
            }
        }
        Ok(instant.elapsed())
    }
}
