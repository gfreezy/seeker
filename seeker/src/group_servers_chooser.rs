use crate::dns_client::DnsClient;
use crate::proxy_connection::ProxyConnection;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::proxy_udp_socket::ProxyUdpSocket;
use crate::server_chooser::{CandidateTcpStream, CandidateUdpSocket};
use crate::server_performance::{PingUrlResult, ServerPerformanceTracker};
use anyhow::Result;
use config::rule::Action;
use config::{Address, PingURL, ServerConfig};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task;
use tokio::time::sleep;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;
use tracing::info;

// 切换阈值：新服务器分数需比当前低 10% 以上才切换
const SWITCH_THRESHOLD_RATIO: f64 = 0.9;
// 最小切换间隔：60秒
const MIN_SWITCH_INTERVAL: Duration = Duration::from_secs(60);
// 连续失败次数阈值：连续失败 3 次才触发切换
const CONSECUTIVE_FAILURES_THRESHOLD: u32 = 3;

#[derive(Clone)]
pub struct GroupServersChooser {
    name: String,
    ping_urls: Vec<PingURL>,
    ping_timeout: Duration,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    servers: Arc<Vec<ServerConfig>>,
    selected_server: Arc<Mutex<ServerConfig>>,
    dns_client: DnsClient,
    live_connections: Arc<RwLock<Vec<Box<dyn ProxyConnection + Send + Sync>>>>,
    show_stats: bool,
    performance_tracker: ServerPerformanceTracker,
    // 上次切换时间
    last_switch_time: Arc<Mutex<Instant>>,
    // 连续失败计数
    consecutive_failures: Arc<AtomicU32>,
}

impl GroupServersChooser {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        name: String,
        servers: Arc<Vec<ServerConfig>>,
        dns_client: DnsClient,
        ping_urls: Vec<PingURL>,
        ping_timeout: Duration,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
        show_stats: bool,
    ) -> Self {
        let selected = servers.first().cloned().expect("no server available");
        let chooser = GroupServersChooser {
            name,
            ping_urls,
            ping_timeout,
            connect_timeout,
            read_timeout,
            write_timeout,
            servers,
            dns_client,
            live_connections: Arc::new(RwLock::new(vec![])),
            selected_server: Arc::new(Mutex::new(selected)),
            show_stats,
            performance_tracker: ServerPerformanceTracker::new(100, Duration::from_secs(300)),
            last_switch_time: Arc::new(Mutex::new(Instant::now() - MIN_SWITCH_INTERVAL)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
        };
        chooser.ping_servers(false).await;
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

    pub async fn proxy_connect(
        &self,
        remote_addr: &Address,
    ) -> std::io::Result<CandidateTcpStream> {
        let config = self.selected_server.lock().clone();
        let stream =
            ProxyTcpStream::connect(remote_addr.clone(), Some(&config), self.dns_client.clone())
                .await;
        if stream.is_err() {
            let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
            tracing::error!(
                group = self.name,
                ?remote_addr,
                action = ?Action::Proxy(self.name.clone()),
                consecutive_failures = failures,
                "Failed to connect to server: {}",
                config.addr()
            );
            // 只有连续失败超过阈值才切换
            if failures >= CONSECUTIVE_FAILURES_THRESHOLD {
                self.move_to_next_server(true);
            }
        } else {
            // 连接成功，重置失败计数
            self.consecutive_failures.store(0, Ordering::SeqCst);
        }
        Ok(CandidateTcpStream {
            stream: stream?,
            proxy_group_name: self.name.clone(),
            server_config: Some(config),
        })
    }

    pub async fn candidate_udp_socket(
        &self,
        action: Action,
    ) -> std::io::Result<CandidateUdpSocket> {
        let (socket, proxy_group_name, server_config) = match action {
            Action::Direct => (
                ProxyUdpSocket::new(None, self.dns_client.clone()).await?,
                "".to_string(),
                None,
            ),
            Action::Proxy(_) => {
                let config = self.selected_server.lock().clone();
                tracing::info!(group = self.name, "Using server: {}", config.addr());
                let socket = ProxyUdpSocket::new(Some(&config), self.dns_client.clone()).await;
                if socket.is_err() {
                    let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                    tracing::info!(
                        group = self.name,
                        consecutive_failures = failures,
                        "Failed to connect to server: {}",
                        config.addr()
                    );
                    if failures >= CONSECUTIVE_FAILURES_THRESHOLD {
                        self.move_to_next_server(true);
                    }
                } else {
                    self.consecutive_failures.store(0, Ordering::SeqCst);
                }
                (socket?, self.name.clone(), Some(config))
            }
            _ => unreachable!(),
        };
        let socket_clone = socket.clone();
        self.insert_live_connections(Box::new(socket_clone));
        Ok(CandidateUdpSocket {
            socket,
            proxy_group_name,
            server_config,
        })
    }

    /// 切换到下一个最佳服务器
    /// force: 是否强制切换（连续失败时使用），强制切换时跳过阈值检查但仍检查间隔时间
    pub fn move_to_next_server(&self, force: bool) {
        let now = Instant::now();

        // 检查最小切换间隔
        {
            let last_switch = self.last_switch_time.lock();
            let elapsed = now.duration_since(*last_switch);
            if elapsed < MIN_SWITCH_INTERVAL {
                tracing::debug!(
                    group = self.name,
                    elapsed_secs = elapsed.as_secs(),
                    min_interval_secs = MIN_SWITCH_INTERVAL.as_secs(),
                    "Skipping server switch: minimum interval not reached"
                );
                return;
            }
        }

        let current_server = self.selected_server.lock().clone();
        let current_score = self
            .performance_tracker
            .get_server_score(&current_server, now);

        let mut best_score = f64::MAX;
        let mut best_server = None;

        // Find the server with the best performance score
        for server in self.servers.iter() {
            let score = self.performance_tracker.get_server_score(server, now);
            if score < best_score {
                best_score = score;
                best_server = Some(server.clone());
            }
        }

        if let Some(new_server) = best_server {
            // 如果最佳服务器就是当前服务器，不切换
            if new_server.addr() == current_server.addr() {
                return;
            }

            // 非强制切换时，检查阈值：新服务器分数需要比当前低 10% 以上才切换
            if !force {
                let threshold = current_score * SWITCH_THRESHOLD_RATIO;
                if best_score >= threshold {
                    tracing::debug!(
                        group = self.name,
                        current_score = current_score,
                        best_score = best_score,
                        threshold = threshold,
                        "Skipping server switch: score improvement not significant enough"
                    );
                    return;
                }
            }

            self.set_server_down(&current_server);
            info!(
                group = self.name,
                old_name = current_server.name(),
                old_server = ?current_server.addr(),
                old_score = current_score,
                new_name = new_server.name(),
                new_server = ?new_server.addr(),
                new_score = best_score,
                force = force,
                "Change shadowsocks server"
            );
            *self.selected_server.lock() = new_server;
            *self.last_switch_time.lock() = now;
            // 切换后重置失败计数
            self.consecutive_failures.store(0, Ordering::SeqCst);
        } else {
            tracing::error!(
                group = self.name,
                "No server available, all servers are down"
            );
        }
    }

    pub async fn run_background_tasks(&self) -> Result<()> {
        let mut last_updated = Instant::now();
        loop {
            if last_updated.elapsed() > Duration::from_secs(10) {
                self.ping_servers(true).await;
                self.print_connection_stats(self.show_stats);
                last_updated = Instant::now();
            }
            self.recycle_live_connections();
            sleep(Duration::from_secs(1)).await;
        }
    }

    fn print_connection_stats(&self, show_stats: bool) {
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

        info!("Group \"{}\", Connections:", self.name);
        if show_stats {
            println!(
                "╔══════════════════════════════════════════════════════════════════════════════╗"
            );
            println!("Group \"{}\", Connections:", self.name);
        }
        let mut v: Vec<_> = map.into_iter().collect();
        v.sort_unstable_by(|(addr1, _), (addr2, _)| addr1.cmp(addr2));
        for (remote_addr, stats) in v {
            if show_stats {
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
            info!(
                "[{}] {}, conns: {}, max_duration: {}, sent_bytes: {}, recv_bytes: {}",
                stats.action,
                remote_addr,
                stats.count,
                stats.max_duration.as_secs(),
                stats.send,
                stats.recv
            );
        }

        if show_stats {
            println!("\nGroup \"{}\", Server Performance:", self.name);
        }
        info!("\nGroup \"{}\", Server Performance:", self.name);
        let server_stats = self.performance_tracker.get_all_server_stats();
        for (addr, _name, _protocol, stats) in server_stats {
            if show_stats {
                println!(
                    "{}: score={:.2} latency={:.1}ms, success_rate={:.2}%, success={}, failure={}",
                    addr,
                    stats.score,
                    stats.latency,
                    stats.success_rate * 100.0,
                    stats.success,
                    stats.failure
                );
            }
            info!(
                "{}: score={:.2} latency={:.1}ms, success_rate={:.2}%, success={}, failure={}",
                addr,
                stats.score,
                stats.latency,
                stats.success_rate * 100.0,
                stats.success,
                stats.failure
            );
        }
        if show_stats {
            println!(
                "╚══════════════════════════════════════════════════════════════════════════════╝"
            );
        }
    }

    pub async fn ping_servers(&self, wait_for_all: bool) {
        if self.ping_urls.is_empty() || self.servers.len() <= 1 {
            return;
        }

        let mut fut: FuturesUnordered<_> = self
            .servers
            .iter()
            .map(|config| {
                let self_clone = self.clone();
                let config_clone = config.clone();
                task::spawn(async move {
                    let (result, ping_results) = self_clone.ping_server(config_clone.clone()).await;
                    let is_success = result.is_ok();
                    self_clone.performance_tracker.add_result(
                        &config_clone,
                        result.ok(),
                        is_success,
                        ping_results,
                    );
                    is_success
                })
            })
            .collect();

        if wait_for_all {
            while fut.next().await.is_some() {}
        } else {
            while let Some(ret) = fut.next().await {
                if let Ok(true) = ret {
                    break;
                }
            }
        }

        // ping 后的切换不是强制切换，需要满足阈值条件
        self.move_to_next_server(!wait_for_all);
    }

    async fn ping_server(
        &self,
        server_config: ServerConfig,
    ) -> (std::io::Result<Duration>, Vec<PingUrlResult>) {
        // Ping all URLs concurrently
        let futs: Vec<_> = self.ping_urls.iter().map(|ping_url| {
            let server_config = server_config.clone();
            let dns_client = self.dns_client.clone();
            let ping_timeout = self.ping_timeout;
            let connect_timeout = self.connect_timeout;
            let read_timeout = self.read_timeout;
            let write_timeout = self.write_timeout;
            let url_str = ping_url.to_string();
            let ping_url = ping_url.clone();
            async move {
                let url_start = Instant::now();
                let ret = timeout(
                    ping_timeout,
                    ping_server(server_config.clone(), &ping_url, connect_timeout, read_timeout, write_timeout, dns_client),
                ).await;
                let elapsed = url_start.elapsed();
                match ret {
                    Ok(Ok(())) => PingUrlResult {
                        url: url_str,
                        latency_ms: Some(elapsed.as_secs_f64() * 1000.0),
                        success: true,
                        error: None,
                    },
                    Ok(Err(err)) => PingUrlResult {
                        url: url_str,
                        latency_ms: Some(elapsed.as_secs_f64() * 1000.0),
                        success: false,
                        error: Some(err.to_string()),
                    },
                    Err(_) => PingUrlResult {
                        url: url_str,
                        latency_ms: Some(elapsed.as_secs_f64() * 1000.0),
                        success: false,
                        error: Some(format!(
                            "server={}({}), url={}, stage=total, error: ping timeout after {ping_timeout:?}",
                            server_config.name(), server_config.addr(), ping_url,
                        )),
                    },
                }
            }
        }).collect();

        let ping_results = futures_util::future::join_all(futs).await;

        for r in &ping_results {
            if !r.success {
                tracing::error!(
                    "ping server: {}, url: {}, err: {:?}",
                    server_config.name(),
                    r.url,
                    r.error
                );
            }
        }

        use crate::server_performance::FAILURE_LATENCY;

        let success_count = ping_results.iter().filter(|r| r.success).count();
        let failure_latency_ms = FAILURE_LATENCY.as_secs_f64() * 1000.0;

        let result = if success_count > 0 {
            // Average latency across all URLs: successful ones use real latency,
            // failed ones use FAILURE_LATENCY as penalty.
            let total_latency_ms: f64 = ping_results
                .iter()
                .map(|r| {
                    if r.success {
                        r.latency_ms.unwrap_or(failure_latency_ms)
                    } else {
                        failure_latency_ms
                    }
                })
                .sum();
            let avg_ms = total_latency_ms / ping_results.len() as f64;
            Ok(Duration::from_secs_f64(avg_ms / 1000.0))
        } else {
            let first_err = ping_results
                .iter()
                .find(|r| !r.success)
                .and_then(|r| r.error.clone())
                .unwrap_or_else(|| "ping failed".to_string());
            Err(std::io::Error::other(first_err))
        };
        (result, ping_results)
    }

    pub fn get_performance_tracker(&self) -> ServerPerformanceTracker {
        self.performance_tracker.clone()
    }

    pub fn get_selected_server(&self) -> ServerConfig {
        self.selected_server.lock().clone()
    }

    /// Reset all connections and performance data
    pub fn reset(&self) {
        info!(group = self.name, "Resetting group servers chooser");

        // Shutdown all live connections
        let mut live_connections = self.live_connections.write();
        for conn in live_connections.iter() {
            conn.shutdown();
        }

        // Clear all connections
        live_connections.clear();

        // Reset performance tracker
        self.performance_tracker.reset();

        info!(group = self.name, "Group servers chooser reset completed");
    }
}

async fn ping_server(
    server_config: ServerConfig,
    ping_url: &PingURL,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    dns_client: DnsClient,
) -> std::io::Result<()> {
    let addr = ping_url.address();
    let path: &str = ping_url.path();
    let server_name = server_config.name().to_string();
    let server_addr = server_config.addr().to_string();
    let url_str = ping_url.to_string();

    let stream = timeout(connect_timeout, ProxyTcpStream::connect(addr.clone(), Some(&server_config), dns_client))
        .await
        .map_err(|_| std::io::Error::other(format!(
            "server={server_name}({server_addr}), url={url_str}, stage=connect, error: timeout after {connect_timeout:?}"
        )))?
        .map_err(|e| std::io::Error::other(format!(
            "server={server_name}({server_addr}), url={url_str}, stage=connect, error: {e}"
        )))?;

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
            Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n\
            Accept-Encoding: gzip, deflate, br, zstd\r\n\
            Accept-Language: en-US,en;q=0.9\r\n\
            Cache-Control: no-cache\r\n\
            Connection: keep-alive\r\n\
            DNT: 1\r\n\
            Host: {}\r\n\
            Pragma: no-cache\r\n\
            Sec-Fetch-Dest: document\r\n\
            Sec-Fetch-Mode: navigate\r\n\
            Sec-Fetch-Site: none\r\n\
            Sec-Fetch-User: ?1\r\n\
            Upgrade-Insecure-Requests: 1\r\n\
            User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36\r\n\
            sec-ch-ua: \"Google Chrome\";v=\"137\", \"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\"\r\n\
            sec-ch-ua-mobile: ?0\r\n\
            sec-ch-ua-platform: \"macOS\"\r\n\
            \r\n",
        ping_url.host()
    );

    let resp_buf = if ping_url.port() == 443 {
        let cx = native_tls::TlsConnector::builder().build().unwrap();
        let connector = TlsConnector::from(cx);
        let mut conn = timeout(connect_timeout, connector.connect(ping_url.host(), stream))
            .await
            .map_err(|_| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=tls_handshake, error: timeout after {connect_timeout:?}"
            )))?
            .map_err(|e| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=tls_handshake, error: {e}"
            )))?;
        timeout(write_timeout, conn.write_all(req.as_bytes()))
            .await
            .map_err(|_| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=send_request, error: write timeout after {write_timeout:?}"
            )))?
            .map_err(|e| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=send_request, error: {e}"
            )))?;
        let mut buf = vec![0; 1024];
        let size = timeout(read_timeout, conn.read(&mut buf))
            .await
            .map_err(|_| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=read_response, error: read timeout after {read_timeout:?}"
            )))?
            .map_err(|e| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=read_response, error: {e}"
            )))?;
        buf[..size].to_vec()
    } else {
        let mut conn = stream;
        timeout(write_timeout, conn.write_all(req.as_bytes()))
            .await
            .map_err(|_| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=send_request, error: write timeout after {write_timeout:?}"
            )))?
            .map_err(|e| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=send_request, error: {e}"
            )))?;
        let mut buf = vec![0; 1024];
        let size = timeout(read_timeout, conn.read(&mut buf))
            .await
            .map_err(|_| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=read_response, error: read timeout after {read_timeout:?}"
            )))?
            .map_err(|e| std::io::Error::other(format!(
                "server={server_name}({server_addr}), url={url_str}, stage=read_response, error: {e}"
            )))?;
        buf[..size].to_vec()
    };
    // Check if HTTP status code starts with 2 or 3
    let response = String::from_utf8_lossy(&resp_buf);
    if let Some(status_line) = response.lines().next()
        && let Some(status_code) = status_line.split_whitespace().nth(1)
        && !status_code.starts_with('2')
        && !status_code.starts_with('3')
    {
        return Err(std::io::Error::other(format!(
            "server={server_name}({server_addr}), url={url_str}, stage=status_check, status_code={status_code}"
        )));
    }
    Ok(())
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use config::ServerProtocol;
    use crypto::CipherType;
    use std::sync::atomic::{AtomicU16, Ordering};
    use testcontainers::core::WaitFor;
    use testcontainers::runners::SyncRunner;
    use testcontainers::{Container, GenericImage, ImageExt};

    use super::*;

    static NEXT_PORT: AtomicU16 = AtomicU16::new(28388);

    fn next_port() -> u16 {
        NEXT_PORT.fetch_add(1, Ordering::Relaxed)
    }

    struct TestContainer(Option<Container<GenericImage>>);

    impl TestContainer {
        fn new(c: Container<GenericImage>) -> Self {
            Self(Some(c))
        }

        async fn cleanup(mut self) {
            if let Some(c) = self.0.take() {
                tokio::task::spawn_blocking(move || drop(c)).await.ok();
            }
        }
    }

    impl Drop for TestContainer {
        fn drop(&mut self) {
            if let Some(c) = self.0.take() {
                std::mem::forget(c);
            }
        }
    }

    const TEST_PASSWORD: &str = "test-password";
    const TEST_METHOD: &str = "aes-256-gcm";

    fn start_ss_server(port: u16) -> Container<GenericImage> {
        GenericImage::new("shadowsocks/shadowsocks-libev", "latest")
            .with_wait_for(WaitFor::message_on_stdout("listening"))
            .with_startup_timeout(Duration::from_secs(30))
            .with_network("host")
            .with_cmd([
                "ss-server",
                "-s",
                "0.0.0.0",
                "-p",
                &port.to_string(),
                "-k",
                TEST_PASSWORD,
                "-m",
                TEST_METHOD,
                "-v",
            ])
            .start()
            .expect("failed to start shadowsocks container")
    }

    async fn start_ss_server_async(port: u16) -> TestContainer {
        let container = tokio::task::spawn_blocking(move || start_ss_server(port))
            .await
            .expect("failed to spawn blocking task for container start");
        // Brief delay to ensure the server is fully accepting connections
        sleep(Duration::from_millis(500)).await;
        TestContainer::new(container)
    }

    #[tokio::test]
    async fn test_ping_server() {
        store::Store::setup_global_for_test();
        tracing_subscriber::fmt()
            // .with_env_filter("seeker=debug")
            .try_init()
            .ok();

        let port = next_port();
        let container = start_ss_server_async(port).await;

        let server_config = ServerConfig::new(
            "test-ss".to_string(),
            format!("127.0.0.1:{port}").parse().unwrap(),
            ServerProtocol::Shadowsocks,
            None,
            Some(TEST_PASSWORD.to_string()),
            Some(CipherType::Aes256Gcm),
            None,
        );

        let dns_client = DnsClient::new(
            &[config::DnsServerAddr::UdpSocketAddr(
                "8.8.8.8:53".parse().unwrap(),
            )],
            Duration::from_secs(5),
        )
        .await;

        let result = ping_server(
            server_config,
            &PingURL::new("httpbin.org".to_string(), 80, "/ip".to_string()),
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(10),
            dns_client,
        )
        .await;

        assert!(result.is_ok(), "ping_server failed: {:?}", result.err());

        container.cleanup().await;
    }
}
