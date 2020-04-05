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
    ping_host: Address,
    ping_path: String,
    ping_timeout: Duration,
    servers: Arc<Vec<ShadowsocksServerConfig>>,
    candidate: Arc<Mutex<ShadowsocksServerConfig>>,
    dns_client: DnsClient,
}

impl ShadowsocksServerChooser {
    pub fn new(
        servers: Arc<Vec<ShadowsocksServerConfig>>,
        dns_client: DnsClient,
        ping_host: Address,
        ping_path: String,
        ping_timeout: Duration,
    ) -> Self {
        ShadowsocksServerChooser {
            ping_host,
            ping_path,
            ping_timeout,
            candidate: Arc::new(Mutex::new(servers[0].clone())),
            servers,
            dns_client,
        }
    }

    pub fn candidate(&self) -> ShadowsocksServerConfig {
        (*self.candidate.lock()).clone()
    }

    pub async fn ping_servers(&self) -> Result<()> {
        loop {
            let mut fut: FuturesUnordered<_> = self
                .servers
                .iter()
                .map(|config| {
                    let self_clone = self.clone();
                    let config_clone = config.clone();
                    spawn(async move {
                        let _ = self_clone.ping_server(config_clone.clone()).await?;
                        Ok::<_, io::Error>(config_clone)
                    })
                })
                .collect();
            while let Some(ret) = fut.next().await {
                match ret {
                    Ok(config) => {
                        info!(
                            name = config.name(),
                            server = ?config.addr(),
                            "Choose shadowsocks server"
                        );
                        *self.candidate.lock() = config;
                        break;
                    }
                    Err(_) => continue,
                }
            }
            sleep(Duration::from_secs(10)).await;
        }
    }

    async fn ping_server(&self, config: ShadowsocksServerConfig) -> Result<Duration> {
        timeout(self.ping_timeout, async {
            let resolved_addr = self.dns_client.lookup_address(config.addr()).await?;
            let instant = Instant::now();
            let mut conn = SSTcpStream::connect(
                self.ping_host.clone(),
                resolved_addr,
                config.method(),
                config.key(),
            )
            .await?;
            conn.write_all(format!("GET {} HTTP/1.1\r\n\r\n", &self.ping_path).as_bytes())
                .await?;
            let mut buf = vec![0; 1024];
            let _size = conn.read(&mut buf).await?;
            Ok(instant.elapsed())
        })
        .await
    }
}
