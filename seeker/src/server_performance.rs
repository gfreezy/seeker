use config::ServerConfig;
use parking_lot::Mutex;
use std::collections::HashMap;
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
