use config::ServerConfig;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

// 未测试或全部失败的服务器返回的哨兵分数/延迟，取一个远大于任何真实分数的有限值以便 JSON 序列化
pub const DEFAULT_SCORE: f64 = 1e12;
pub const DEFAULT_LATENCY: f64 = 1e12;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PingUrlResult {
    pub url: String,
    pub latency_ms: Option<f64>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerPerformanceStats {
    pub score: f64,
    pub latency: f64,
    pub success_rate: f64,
    pub success: u32,
    pub failure: u32,
    pub ping_results: Vec<PingUrlResult>,
}

#[derive(Clone)]
struct PingRecord {
    timestamp: Instant,
    latency: Duration,
    success_ratio: f64,
}

#[derive(Clone)]
pub struct ServerPerformance {
    name: String,
    protocol: String,
    history: Vec<PingRecord>,
    success_count: u32,
    failure_count: u32,
    last_update: Instant,
    max_history_size: usize,
    half_life: Duration,
    last_ping_results: Vec<PingUrlResult>,
}

impl ServerPerformance {
    pub fn new(
        name: String,
        protocol: String,
        max_history_size: usize,
        half_life: Duration,
    ) -> Self {
        Self {
            name,
            protocol,
            history: Vec::new(),
            success_count: 0,
            failure_count: 0,
            last_update: Instant::now(),
            max_history_size,
            half_life,
            last_ping_results: Vec::new(),
        }
    }

    pub fn add_result(
        &mut self,
        latency: Duration,
        success_ratio: f64,
        ping_results: Vec<PingUrlResult>,
    ) {
        let url_successes = ping_results.iter().filter(|r| r.success).count() as u32;
        let url_failures = ping_results.len() as u32 - url_successes;
        self.success_count += url_successes;
        self.failure_count += url_failures;
        self.last_ping_results = ping_results;
        let now = Instant::now();

        self.history.push(PingRecord {
            timestamp: now,
            latency,
            success_ratio,
        });

        self.last_update = now;

        if self.history.len() > self.max_history_size {
            self.history.remove(0);
        }
    }

    pub fn calculate_score(&self, now: Instant) -> f64 {
        if self.history.is_empty() {
            return DEFAULT_SCORE;
        }

        let mut total_weight = 0.0;
        let mut success_weight = 0.0;
        let mut success_latency_weighted = 0.0;

        for record in &self.history {
            let age = now.duration_since(record.timestamp);
            let weight = 2.0_f64.powf(-age.as_secs_f64() / self.half_life.as_secs_f64());
            total_weight += weight;
            success_weight += weight * record.success_ratio;
            success_latency_weighted +=
                weight * record.success_ratio * record.latency.as_secs_f64() * 1000.0;
        }

        if success_weight == 0.0 {
            return DEFAULT_SCORE;
        }

        let avg_latency = success_latency_weighted / success_weight;
        let success_rate = success_weight / total_weight;

        avg_latency / success_rate
    }

    pub fn get_stats(&self) -> ServerPerformanceStats {
        let now = Instant::now();
        let mut total_weight = 0.0;
        let mut success_weight = 0.0;
        let mut success_latency_weighted = 0.0;

        for record in &self.history {
            let age = now.duration_since(record.timestamp);
            let weight = 2.0_f64.powf(-age.as_secs_f64() / self.half_life.as_secs_f64());
            total_weight += weight;
            success_weight += weight * record.success_ratio;
            success_latency_weighted +=
                weight * record.success_ratio * record.latency.as_secs_f64() * 1000.0;
        }

        let avg_latency = if success_weight > 0.0 {
            success_latency_weighted / success_weight
        } else {
            DEFAULT_LATENCY
        };

        let success_rate = if total_weight > 0.0 {
            success_weight / total_weight
        } else {
            0.0
        };

        ServerPerformanceStats {
            score: self.calculate_score(now),
            latency: avg_latency,
            success_rate,
            success: self.success_count,
            failure: self.failure_count,
            ping_results: self.last_ping_results.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ServerPerformanceTracker {
    // Nodes may share an address but use different protocols or credentials.
    // Include the full configuration so changed transports start with fresh stats.
    performance_history: Arc<Mutex<HashMap<ServerConfig, ServerPerformance>>>,
    max_history_size: usize,
    half_life: Duration,
}

impl ServerPerformanceTracker {
    pub fn new(max_history_size: usize, half_life: Duration) -> Self {
        Self {
            performance_history: Arc::new(Mutex::new(HashMap::new())),
            max_history_size,
            half_life,
        }
    }

    pub fn add_result(
        &self,
        server: &ServerConfig,
        latency: Duration,
        success_ratio: f64,
        ping_results: Vec<PingUrlResult>,
    ) {
        let mut history = self.performance_history.lock();
        let performance = history.entry(server.clone()).or_insert_with(|| {
            ServerPerformance::new(
                server.name().to_string(),
                format!("{:?}", server.protocol()),
                self.max_history_size,
                self.half_life,
            )
        });
        performance.add_result(latency, success_ratio, ping_results);
    }

    pub fn get_server_score(&self, server: &ServerConfig, now: Instant) -> f64 {
        let history = self.performance_history.lock();
        history
            .get(server)
            .map_or(DEFAULT_SCORE, |p| p.calculate_score(now))
    }

    #[allow(dead_code)]
    pub fn get_server_stats(&self, server: &ServerConfig) -> Option<ServerPerformanceStats> {
        let history = self.performance_history.lock();
        history.get(server).map(|p| p.get_stats())
    }

    pub fn get_all_server_stats(&self) -> Vec<(String, String, String, ServerPerformanceStats)> {
        let history = self.performance_history.lock();
        history
            .iter()
            .map(|(server, perf)| {
                let stats = perf.get_stats();
                (
                    server.addr().to_string(),
                    perf.name.clone(),
                    perf.protocol.clone(),
                    stats,
                )
            })
            .collect()
    }

    /// Reset all performance history
    pub fn reset(&self) {
        self.performance_history.lock().clear();
    }

    /// Drop histories for removed or changed nodes, even when an address is reused.
    pub fn retain_servers(&self, keep_servers: &HashSet<&ServerConfig>) {
        let mut history = self.performance_history.lock();
        history.retain(|server, _| keep_servers.contains(&server));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::ServerProtocol;

    fn tracker() -> ServerPerformanceTracker {
        ServerPerformanceTracker::new(100, Duration::from_secs(300))
    }

    fn server(name: &str, protocol: ServerProtocol) -> ServerConfig {
        ServerConfig::new(
            name.to_string(),
            "shared.example:443".parse().unwrap(),
            protocol,
            None,
            None,
            None,
            None,
        )
    }

    fn record(
        tracker: &ServerPerformanceTracker,
        server: &ServerConfig,
        milliseconds: u64,
        success: bool,
    ) {
        tracker.add_result(
            server,
            Duration::from_millis(milliseconds),
            if success { 1.0 } else { 0.0 },
            vec![PingUrlResult {
                url: "https://example.test/".to_string(),
                latency_ms: Some(milliseconds as f64),
                success,
                error: (!success).then(|| "connection failed".to_string()),
            }],
        );
    }

    #[test]
    fn nodes_sharing_an_address_keep_independent_results_and_scores() {
        let tracker = tracker();
        let hy2 = server("hy2", ServerProtocol::Hysteria2);
        let reality = server("reality", ServerProtocol::Vless);
        let websocket = server("websocket", ServerProtocol::Vless);
        record(&tracker, &hy2, 20, true);
        record(&tracker, &reality, 40, false);
        record(&tracker, &websocket, 80, true);

        for (server, milliseconds) in [(&hy2, 20.0), (&websocket, 80.0)] {
            let stats = tracker.get_server_stats(server).unwrap();
            assert!((stats.latency - milliseconds).abs() < 1e-6);
            assert_eq!((stats.success, stats.failure), (1, 0));
            assert!(stats.ping_results[0].success);
            assert!(tracker.get_server_score(server, Instant::now()) < DEFAULT_SCORE);
        }
        let failed = tracker.get_server_stats(&reality).unwrap();
        assert_eq!((failed.success, failed.failure), (0, 1));
        assert_eq!(failed.latency, DEFAULT_LATENCY);
        assert!(!failed.ping_results[0].success);
        assert_eq!(
            tracker.get_server_score(&reality, Instant::now()),
            DEFAULT_SCORE
        );

        let untested = server("untested", ServerProtocol::Vless);
        assert!(tracker.get_server_stats(&untested).is_none());
        assert_eq!(
            tracker.get_server_score(&untested, Instant::now()),
            DEFAULT_SCORE
        );

        let mut exported = tracker
            .get_all_server_stats()
            .into_iter()
            .map(|(addr, name, protocol, _)| (addr, name, protocol))
            .collect::<Vec<_>>();
        exported.sort();
        assert_eq!(
            exported,
            vec![
                (
                    "shared.example:443".into(),
                    "hy2".into(),
                    "Hysteria2".into()
                ),
                (
                    "shared.example:443".into(),
                    "reality".into(),
                    "Vless".into()
                ),
                (
                    "shared.example:443".into(),
                    "websocket".into(),
                    "Vless".into()
                ),
            ]
        );
    }

    #[test]
    fn changed_configuration_does_not_inherit_a_nodes_previous_measurements() {
        let tracker = tracker();
        let original = serde_json::json!({
            "name": "node", "addr": "shared.example:443", "protocol": "Vless",
            "username": "00000000-0000-0000-0000-000000000001",
            "network": "ws", "tls": true, "sni": "original.example",
            "ws-opts": {"path": "/original", "headers": {"Host": "original.example"}}
        });
        let server: ServerConfig = serde_json::from_value(original.clone()).unwrap();
        record(&tracker, &server, 20, true);
        let changes = [
            serde_json::json!({"username": "00000000-0000-0000-0000-000000000002"}),
            serde_json::json!({"protocol": "Hysteria2"}),
            serde_json::json!({"sni": "changed.example"}),
            serde_json::json!({"ws-opts": {"path": "/changed", "headers": {"Host": "changed.example"}}}),
            serde_json::json!({"network": "tcp", "reality-opts": {
                "public-key": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
                "short-id": "aabb", "support-x25519mlkem768": true
            }}),
        ];
        let mut changed_nodes = Vec::new();
        for (index, change) in changes.into_iter().enumerate() {
            let mut config = original.clone();
            config
                .as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            let changed = serde_json::from_value(config).unwrap();
            assert!(tracker.get_server_stats(&changed).is_none());
            assert_eq!(
                tracker.get_server_score(&changed, Instant::now()),
                DEFAULT_SCORE
            );
            record(&tracker, &changed, 40 + index as u64, false);
            changed_nodes.push(changed);
        }
        let unchanged_stats = tracker.get_server_stats(&server).unwrap();
        assert_eq!((unchanged_stats.success, unchanged_stats.failure), (1, 0));
        assert!((unchanged_stats.latency - 20.0).abs() < 1e-6);
        assert_eq!(
            tracker.get_all_server_stats().len(),
            1 + changed_nodes.len()
        );

        tracker.retain_servers(&HashSet::from([&server]));
        assert_eq!(tracker.get_all_server_stats().len(), 1);
        assert!(tracker.get_server_stats(&server).is_some());
        for changed in changed_nodes {
            assert!(tracker.get_server_stats(&changed).is_none());
        }
    }
}
