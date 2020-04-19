use crate::dns_client::DnsClient;
use async_std::io::timeout;
use async_std::prelude::*;
use async_std::task::{sleep, spawn};
use config::{Address, ShadowsocksServerConfig};
use futures::stream::FuturesUnordered;
use parking_lot::Mutex;
use ssclient::SSTcpStream;
use std::io;
use std::io::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Clone)]
pub struct ShadowsocksServerChooser {
    ping_url: Vec<(Address, String)>,
    ping_timeout: Duration,
    servers: Arc<Vec<ShadowsocksServerConfig>>,
    candidates: Arc<Mutex<Vec<ShadowsocksServerConfig>>>,
    dns_client: DnsClient,
}

impl ShadowsocksServerChooser {
    pub async fn new(
        servers: Arc<Vec<ShadowsocksServerConfig>>,
        dns_client: DnsClient,
        ping_url: Vec<(Address, String)>,
        ping_timeout: Duration,
    ) -> Result<Self> {
        let chooser = ShadowsocksServerChooser {
            ping_url,
            ping_timeout,
            candidates: Arc::new(Mutex::new(vec![])),
            servers,
            dns_client,
        };
        chooser.ping_servers().await?;
        Ok(chooser)
    }

    pub fn candidate(&self) -> Option<ShadowsocksServerConfig> {
        self.candidates.lock().first().cloned()
    }

    pub fn next_candidate(&self) -> Option<()> {
        let mut candidates = self.candidates.lock();
        if candidates.len() > 1 {
            let removed = candidates.remove(0);
            let new = &candidates[0];
            info!(
                old_name = removed.name(),
                old_server = ?removed.addr(),
                new_name = new.name(),
                new_server = ?new.addr(),
                "Change shadowsocks server"
            );

            Some(())
        } else {
            None
        }
    }

    pub async fn ping_servers_forever(&self) -> Result<()> {
        loop {
            self.ping_servers().await?;
            sleep(Duration::from_secs(10)).await;
        }
    }

    async fn ping_servers(&self) -> Result<()> {
        let mut candidates = vec![];
        if let Some(current_config) = self.candidate() {
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
        Ok(())
    }

    async fn ping_server(&self, config: ShadowsocksServerConfig) -> Result<Duration> {
        let instant = Instant::now();
        for (host, path) in &self.ping_url {
            timeout(self.ping_timeout, async {
                let resolved_addr = self.dns_client.lookup_address(config.addr()).await?;
                let mut conn = SSTcpStream::connect(
                    host.clone(),
                    resolved_addr,
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
            .await?;
        }
        Ok(instant.elapsed())
    }
}
