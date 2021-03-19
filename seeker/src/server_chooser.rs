use crate::dns_client::DnsClient;
use crate::proxy_connection::ProxyConnection;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use async_std::io::timeout;
use async_std::prelude::*;
use async_std::task::{sleep, spawn};
use config::rule::Action;
use config::{Address, ServerConfig};
use futures_util::stream::FuturesUnordered;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Clone)]
pub struct ServerChooser {
    ping_url: Vec<(Address, String)>,
    ping_timeout: Duration,
    servers: Arc<Vec<ServerConfig>>,
    candidates: Arc<Mutex<Vec<ServerConfig>>>,
    dns_client: DnsClient,
    live_connections: Arc<RwLock<Vec<Box<dyn ProxyConnection + Sync + Send>>>>,
}

impl ServerChooser {
    pub async fn new(
        servers: Arc<Vec<ServerConfig>>,
        dns_client: DnsClient,
        ping_url: Vec<(Address, String)>,
        ping_timeout: Duration,
    ) -> Self {
        let chooser = ServerChooser {
            ping_url,
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
        let mut live_connections = self.live_connections.write();
        live_connections
            .iter()
            .filter(|stream| stream.has_config(Some(&config)))
            .for_each(|stream| stream.shutdown());
        live_connections.retain(|stream| stream.strong_count() > 1);
    }

    pub async fn candidate_tcp_stream(
        &self,
        remote_addr: Address,
        action: Action,
    ) -> Result<ProxyTcpStream> {
        let stream = match action {
            Action::Proxy => {
                let config = self.candidates.lock().first().cloned().unwrap();
                let stream =
                    ProxyTcpStream::connect(remote_addr, Some(&config), self.dns_client.clone())
                        .await;
                if stream.is_err() {
                    self.take_down_current_and_move_next();
                }
                stream?
            }
            Action::Direct => {
                ProxyTcpStream::connect(remote_addr, None, self.dns_client.clone()).await?
            }
            _ => unreachable!(),
        };

        // store all on-fly connections
        let stream_clone = stream.clone();
        self.live_connections.write().push(Box::new(stream_clone));

        Ok(stream)
    }

    pub async fn candidate_udp_socket(&self, action: Action) -> Result<ProxyUdpSocket> {
        let socket = match action {
            Action::Direct => ProxyUdpSocket::new(None, self.dns_client.clone()).await?,
            Action::Proxy => {
                let config = self.candidates.lock().first().cloned().unwrap();
                let socket = ProxyUdpSocket::new(Some(&config), self.dns_client.clone()).await;
                if socket.is_err() {
                    self.take_down_current_and_move_next();
                }
                socket?
            }
            _ => unreachable!(),
        };
        let socket_clone = socket.clone();
        self.live_connections.write().push(Box::new(socket_clone));
        Ok(socket)
    }

    pub fn take_down_current_and_move_next(&self) {
        // make sure `candidates` drop after block ends to avoid deadlock.
        let mut candidates = self.candidates.lock();
        if candidates.len() <= 1 {
            return;
        }
        let removed = candidates.remove(0);
        self.set_server_down(&removed);
        let new = &candidates[0];
        info!(
            old_name = removed.name(),
            old_server = ?removed.addr(),
            new_name = new.name(),
            new_server = ?new.addr(),
            "Change shadowsocks server"
        );
    }

    pub async fn ping_servers_forever(&self) -> Result<()> {
        loop {
            self.ping_servers().await;
            self.print_connection_stats();
            sleep(Duration::from_secs(30)).await;
        }
    }

    fn print_connection_stats(&self) {
        #[derive(Default)]
        struct Stats {
            count: usize,
            send: usize,
            recv: usize,
        }
        let mut map: HashMap<String, Stats> = HashMap::new();
        for conn in self.live_connections.read().iter() {
            if let Some(config) = conn.config() {
                let entry = map.entry(config.addr().to_string()).or_default();
                entry.count += 1;
                let traffic = conn.traffic();
                entry.send += traffic.sent_bytes();
                entry.recv += traffic.received_bytes();
            }
        }
        println!("Connections:");
        for (remote_addr, stats) in map.iter() {
            println!(
                "{}: {}, sent_bytes: {}, recv_bytes: {}",
                remote_addr, stats.count, stats.send, stats.recv
            );
        }
        println!();
    }

    pub async fn ping_servers(&self) {
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
                    candidates.push(config);
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
            *self.candidates.lock() = candidates;
        }
    }

    async fn ping_server(&self, config: ServerConfig) -> Result<Duration> {
        let instant = Instant::now();
        for (host, path) in &self.ping_url {
            let ret: Result<_> = timeout(self.ping_timeout, async {
                let mut conn =
                    ProxyTcpStream::connect(host.clone(), Some(&config), self.dns_client.clone())
                        .await?;
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
