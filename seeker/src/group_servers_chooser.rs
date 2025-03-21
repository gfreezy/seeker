use crate::dns_client::DnsClient;
use crate::proxy_connection::ProxyConnection;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use anyhow::Result;
use async_std::io::timeout;
use async_std::prelude::*;
use async_std::task::{sleep, spawn};
use async_tls::TlsConnector;
use config::rule::Action;
use config::{Address, PingURL, ServerConfig};
use futures_util::stream::FuturesUnordered;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Clone)]
pub struct GroupServersChooser {
    name: String,
    ping_urls: Vec<PingURL>,
    ping_timeout: Duration,
    servers: Arc<Vec<ServerConfig>>,
    candidates: Arc<Mutex<Vec<ServerConfig>>>,
    selected_server: Arc<Mutex<ServerConfig>>,
    dns_client: DnsClient,
    live_connections: Arc<RwLock<Vec<Box<dyn ProxyConnection + Send + Sync>>>>,
    show_stats: bool,
}

impl GroupServersChooser {
    pub async fn new(
        name: String,
        servers: Arc<Vec<ServerConfig>>,
        dns_client: DnsClient,
        ping_urls: Vec<PingURL>,
        ping_timeout: Duration,
        show_stats: bool,
    ) -> Self {
        let selected = servers.first().cloned().expect("no server available");
        let chooser = GroupServersChooser {
            name,
            ping_urls,
            ping_timeout,
            candidates: Arc::new(Mutex::new(servers.iter().cloned().collect())),
            servers,
            dns_client,
            live_connections: Arc::new(RwLock::new(vec![])),
            selected_server: Arc::new(Mutex::new(selected)),
            show_stats,
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
            .retain(|stream| stream.is_alive());
    }

    fn insert_live_connections(&self, conn: Box<dyn ProxyConnection + Send + Sync>) {
        self.live_connections.write().push(conn);
    }

    #[tracing::instrument(skip(self))]
    pub async fn candidate_tcp_stream(
        &self,
        remote_addr: Address,
        action: Action,
    ) -> std::io::Result<ProxyTcpStream> {
        let stream = match action {
            Action::Proxy(_) => self.proxy_connect(&remote_addr).await?,
            Action::Direct => self.direct_connect(&remote_addr).await?,
            _ => unreachable!(),
        };

        // store all on-fly connections
        let stream_clone = stream.clone();
        self.insert_live_connections(Box::new(stream_clone));

        Ok(stream)
    }

    pub async fn proxy_connect(&self, remote_addr: &Address) -> std::io::Result<ProxyTcpStream> {
        let config = self.selected_server.lock().clone();
        let stream =
            ProxyTcpStream::connect(remote_addr.clone(), Some(&config), self.dns_client.clone())
                .await;
        if stream.is_err() {
            tracing::error!(
                group = self.name,
                ?remote_addr,
                action = ?Action::Proxy(self.name.clone()),
                "Failed to connect to server: {}",
                config.addr()
            );
            self.move_to_next_server();
        }
        stream
    }

    pub async fn direct_connect(&self, remote_addr: &Address) -> std::io::Result<ProxyTcpStream> {
        let ret = ProxyTcpStream::connect(remote_addr.clone(), None, self.dns_client.clone()).await;
        if ret.is_err() {
            tracing::error!(
                group = self.name,
                ?remote_addr,
                action = ?Action::Direct,
                "Failed to connect to server"
            );
        }
        ret
    }

    pub async fn candidate_udp_socket(&self, action: Action) -> std::io::Result<ProxyUdpSocket> {
        let socket = match action {
            Action::Direct => ProxyUdpSocket::new(None, self.dns_client.clone()).await?,
            Action::Proxy(_) => {
                let config = self.selected_server.lock().clone();
                tracing::info!(group = self.name, "Using server: {}", config.addr());
                let socket = ProxyUdpSocket::new(Some(&config), self.dns_client.clone()).await;
                if socket.is_err() {
                    tracing::info!(
                        group = self.name,
                        "Failed to connect to server: {}",
                        config.addr()
                    );
                    self.move_to_next_server();
                }
                socket?
            }
            _ => unreachable!(),
        };
        let socket_clone = socket.clone();
        self.insert_live_connections(Box::new(socket_clone));
        Ok(socket)
    }

    pub fn move_to_next_server(&self) {
        // make sure `candidates` drop after block ends to avoid deadlock.
        let candidates = self.candidates.lock();
        if candidates.is_empty() {
            tracing::error!(
                group = self.name,
                "No server available, all servers are down"
            );
            return;
        }
        let old = self.selected_server.lock().clone();
        self.set_server_down(&old);
        let new = &candidates[0];
        info!(
            group = self.name,
            old_name = old.name(),
            old_server = ?old.addr(),
            new_name = new.name(),
            new_server = ?new.addr(),
            "Change shadowsocks server"
        );
        // use the first server of candidates
        *self.selected_server.lock() = new.clone();
    }

    pub async fn run_background_tasks(&self) -> Result<()> {
        let mut last_updated = Instant::now();
        loop {
            if last_updated.elapsed() > Duration::from_secs(10) {
                self.ping_servers().await;
                if self.show_stats {
                    self.print_connection_stats();
                }
                last_updated = Instant::now();
            }
            self.recycle_live_connections();
            sleep(Duration::from_secs(1)).await;
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
                        group = self.name,
                        name = config.name(),
                        server = ?config.addr(),
                        latency = %duration.as_millis(),
                        "Ping shadowsocks server"
                    );
                    candidates.push((config, duration));
                }
                Err(config) => {
                    info!(
                        group = self.name,
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

        if !self
            .candidates
            .lock()
            .contains(&*self.selected_server.lock())
        {
            // current server is down, move to next server.
            self.move_to_next_server();
        }
    }

    async fn ping_server(&self, server_config: ServerConfig) -> std::io::Result<Duration> {
        let instant = Instant::now();
        for ping_url in &self.ping_urls {
            let ret = ping_server(
                server_config.clone(),
                ping_url,
                self.ping_timeout,
                self.dns_client.clone(),
            )
            .await;

            if let Err(e) = ret {
                self.set_server_down(&server_config);
                return Err(e);
            }
        }
        Ok(instant.elapsed())
    }
}

async fn ping_server(
    server_config: ServerConfig,
    ping_url: &PingURL,
    ping_timeout: Duration,
    dns_client: DnsClient,
) -> std::io::Result<()> {
    let addr = ping_url.address();
    let path = ping_url.path();
    timeout(ping_timeout, async {
        let stream =
            ProxyTcpStream::connect(addr.clone(), Some(&server_config), dns_client).await?;
        let resp_buf = if ping_url.port() == 443 {
            let connector = TlsConnector::default();
            let mut conn = connector.connect(ping_url.host(), stream).await?;
            conn.write_all(format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .await?;
            let mut buf = vec![0; 1024];
            let size = conn.read(&mut buf).await?;
            buf[..size].to_vec()
        } else {
            let mut conn = stream;
            conn.write_all(format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes())
                .await?;
            let mut buf = vec![0; 1024];
            let size = conn.read(&mut buf).await?;
            buf[..size].to_vec()
        };
        // Check if HTTP status code starts with 2 or 3
        let response = String::from_utf8_lossy(&resp_buf);
        if let Some(status_line) = response.lines().next() {
            if let Some(status_code) = status_line.split_whitespace().nth(1) {
                if !status_code.starts_with('2') && !status_code.starts_with('3') {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("HTTP status code not 2xx or 3xx: {}", status_code),
                    ));
                }
            }
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[async_std::test]
    #[ignore]
    async fn test_ping_server() -> Result<()> {
        store::Store::setup_global_for_test();
        let url = "ss://YWVzLTI1Ni1nY206MTE0NTE0@1eae257e44aa9d5b.jijifun.com:30002/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dc61be5399e.microsoft.com#%E9%A6%99%E6%B8%AF-ByWave+01";
        let server_config = ServerConfig::from_str(url)?;
        let dns_client = DnsClient::new(
            &[config::DnsServerAddr::UdpSocketAddr(
                "114.114.114.114:53".parse().unwrap(),
            )],
            Duration::from_secs(1),
        )
        .await;
        ping_server(
            server_config,
            &PingURL::new("github.com".to_string(), 443, "/".to_string()),
            Duration::from_secs(5),
            dns_client,
        )
        .await?;
        Ok(())
    }
}
