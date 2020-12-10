use crate::dns_client::DnsClient;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use async_std::io::timeout;
use async_std::prelude::*;
use async_std::task::{sleep, spawn};
use config::{Address, ServerConfig};
use futures_util::stream::FuturesUnordered;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::Result;
use std::sync::atomic::{AtomicBool, Ordering};
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
    server_aliveness: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
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
            server_aliveness: Arc::new(Mutex::new(HashMap::new())),
        };
        chooser.ping_servers().await;
        chooser
    }

    fn get_server_aliveness(&self, config: &ServerConfig) -> Arc<AtomicBool> {
        let mut server_aliveness = self.server_aliveness.lock();
        let entry = server_aliveness
            .entry(config.name().to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)));
        entry.clone()
    }

    fn set_server_down(&self, config: &ServerConfig) {
        let mut server_aliveness = self.server_aliveness.lock();
        let entry = server_aliveness
            .entry(config.name().to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)));
        entry.store(false, Ordering::SeqCst);
    }

    fn set_server_alive(&self, config: &ServerConfig) {
        let mut server_aliveness = self.server_aliveness.lock();
        let entry = server_aliveness
            .entry(config.name().to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)));
        entry.store(true, Ordering::SeqCst);
    }

    pub async fn candidate_tcp_stream(&self, remote_addr: Address) -> Result<ProxyTcpStream> {
        let config = self.candidates.lock().first().cloned().unwrap();
        let alive = self.get_server_aliveness(&config);
        let stream =
            ProxyTcpStream::connect(remote_addr, Some(&config), alive, self.dns_client.clone())
                .await;
        if stream.is_err() {
            self.take_down_current_and_move_next();
        }
        stream
    }

    pub async fn candidate_udp_socket(&self) -> Result<ProxyUdpSocket> {
        let config = self.candidates.lock().first().cloned().unwrap();
        let alive = self.get_server_aliveness(&config);
        let socket = ProxyUdpSocket::new(Some(&config), alive, self.dns_client.clone()).await;
        if socket.is_err() {
            self.take_down_current_and_move_next();
        }
        socket
    }

    pub fn take_down_current_and_move_next(&self) {
        // make sure `candidates` drop after block ends to avoid deadlock.
        let mut candidates = self.candidates.lock();
        if candidates.len() > 1 {
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
    }

    pub async fn ping_servers_forever(&self) -> Result<()> {
        loop {
            self.ping_servers().await;
            sleep(Duration::from_secs(30)).await;
        }
    }

    pub async fn ping_servers(&self) {
        let mut candidates = vec![];
        let candidate_config = self.candidates.lock().first().cloned();
        if let Some(current_config) = candidate_config {
            if self.ping_server(current_config.clone()).await.is_ok() {
                candidates.push(current_config);
            }
        }

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
                let mut conn = ProxyTcpStream::connect(
                    host.clone(),
                    Some(&config),
                    Arc::new(AtomicBool::new(true)),
                    self.dns_client.clone(),
                )
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
        self.set_server_alive(&config);
        Ok(instant.elapsed())
    }
}
