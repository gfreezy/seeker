use config::ServerConfig;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const FAILURE_LATENCY: Duration = Duration::from_secs(60); // 60秒表示服务器不可用
pub const DEFAULT_SCORE: f64 = 100000.0; // 未测试过的服务器返回无穷大
pub const DEFAULT_LATENCY: f64 = 100000.0; // 未测试过的服务器返回无穷大

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

        let mut success_weight = 0.0;
        let mut total_weight = 0.0;
        let mut latency_sum = 0.0;

        for record in &self.history {
            let age = now.duration_since(record.timestamp);
            let weight = 2.0_f64.powf(-age.as_secs_f64() / self.half_life.as_secs_f64());
            total_weight += weight;
            success_weight += weight * record.success_ratio;
            latency_sum += record.latency.as_secs_f64() * 1000.0 * weight;
        }

        if total_weight == 0.0 || success_weight == 0.0 {
            return DEFAULT_SCORE;
        }

        let success_rate = success_weight / total_weight;
        let avg_latency = latency_sum / total_weight;

        avg_latency / success_rate
    }

    pub fn get_stats(&self) -> ServerPerformanceStats {
        let now = Instant::now();
        let mut success_weight = 0.0;
        let mut total_weight = 0.0;
        let mut latency_sum = 0.0;

        for record in &self.history {
            let age = now.duration_since(record.timestamp);
            let weight = 2.0_f64.powf(-age.as_secs_f64() / self.half_life.as_secs_f64());
            total_weight += weight;
            success_weight += weight * record.success_ratio;
            latency_sum += record.latency.as_secs_f64() * 1000.0 * weight;
        }

        let avg_latency = if total_weight > 0.0 {
            latency_sum / total_weight
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
    performance_history: Arc<Mutex<HashMap<String, ServerPerformance>>>,
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
        let performance = history.entry(server.addr().to_string()).or_insert_with(|| {
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
            .get(&server.addr().to_string())
            .map_or(DEFAULT_SCORE, |p| p.calculate_score(now))
    }

    #[allow(dead_code)]
    pub fn get_server_stats(&self, server: &ServerConfig) -> Option<ServerPerformanceStats> {
        let history = self.performance_history.lock();
        history
            .get(&server.addr().to_string())
            .map(|p| p.get_stats())
    }

    pub fn get_all_server_stats(&self) -> Vec<(String, String, String, ServerPerformanceStats)> {
        let history = self.performance_history.lock();
        history
            .iter()
            .map(|(addr, perf)| {
                let stats = perf.get_stats();
                (
                    addr.clone(),
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
}
