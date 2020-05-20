use crate::dns_client::DnsClient;
use async_std::io::timeout;
use async_std::prelude::*;
use async_std::task::{sleep, spawn};
use config::{Address, ShadowsocksServerConfig};
use futures::stream::FuturesUnordered;
use parking_lot::Mutex;
use ssclient::SSTcpStream;
use std::collections::HashMap;
use std::io;
use std::io::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info};

#[derive(Clone)]
pub struct ShadowsocksServerChooser {
    ping_url: Vec<(Address, String)>,
    ping_timeout: Duration,
    servers: Arc<Vec<ShadowsocksServerConfig>>,
    candidates: Arc<Mutex<Vec<ShadowsocksServerConfig>>>,
    dns_client: DnsClient,
    server_aliveness: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl ShadowsocksServerChooser {
    pub async fn new(
        servers: Arc<Vec<ShadowsocksServerConfig>>,
        dns_client: DnsClient,
        ping_url: Vec<(Address, String)>,
        ping_timeout: Duration,
    ) -> Self {
        let chooser = ShadowsocksServerChooser {
            ping_url,
            ping_timeout,
            candidates: Arc::new(Mutex::new(vec![])),
            servers,
            dns_client,
            server_aliveness: Arc::new(Mutex::new(HashMap::new())),
        };
        chooser.ping_servers().await;
        chooser
    }

    fn get_server_aliveness(&self, config: &ShadowsocksServerConfig) -> Arc<AtomicBool> {
        let mut server_aliveness = self.server_aliveness.lock();
        let entry = server_aliveness
            .entry(config.name().to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)));
        entry.clone()
    }

    fn set_server_down(&self, config: &ShadowsocksServerConfig) {
        let mut server_aliveness = self.server_aliveness.lock();
        let entry = server_aliveness
            .entry(config.name().to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)));
        entry.store(false, Ordering::SeqCst);
    }

    fn set_server_alive(&self, config: &ShadowsocksServerConfig) {
        let mut server_aliveness = self.server_aliveness.lock();
        let entry = server_aliveness
            .entry(config.name().to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(true)));
        entry.store(true, Ordering::SeqCst);
    }

    pub fn candidate(&self) -> Option<(ShadowsocksServerConfig, Arc<AtomicBool>)> {
        let config = self.candidates.lock().first().cloned()?;
        let alive = self.get_server_aliveness(&config);
        Some((config, alive))
    }

    pub async fn take_down_current_and_move_next(&self) {
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

            return;
        }
        error!("No shadowsocks servers available, ping servers again");
        self.ping_servers().await;
    }

    pub async fn ping_servers_forever(&self) -> Result<()> {
        loop {
            self.ping_servers().await;
            sleep(Duration::from_secs(300)).await;
        }
    }

    async fn ping_servers(&self) {
        let mut candidates = vec![];
        if let Some((current_config, _)) = self.candidate() {
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
                    let duration = self_clone.ping_server(config_clone.clone()).await?;
                    Ok::<_, io::Error>((config_clone, duration))
                })
            })
            .collect();
        while let Some(ret) = fut.next().await {
            if let Ok((config, duration)) = ret {
                info!(
                    name = config.name(),
                    server = ?config.addr(),
                    latency = %duration.as_millis(),
                    "Ping shadowsocks server"
                );
                candidates.push(config);
            }
        }
        if !candidates.is_empty() {
            *self.candidates.lock() = candidates;
        }
    }

    async fn ping_server(&self, config: ShadowsocksServerConfig) -> Result<Duration> {
        let instant = Instant::now();
        for (host, path) in &self.ping_url {
            let ret: Result<_> = timeout(self.ping_timeout, async {
                let resolved_addr = self.dns_client.lookup_address(config.addr()).await?;
                let mut conn = SSTcpStream::connect(
                    host.clone(),
                    resolved_addr,
                    Arc::new(AtomicBool::new(true)),
                    config.method(),
                    config.key(),
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
