use config::ServerConfig;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const FAILURE_LATENCY: Duration = Duration::from_secs(60); // 60秒表示服务器不可用
pub const DEFAULT_SCORE: f64 = 100000.0; // 未测试过的服务器返回无穷大
pub const DEFAULT_LATENCY: f64 = 100000.0; // 未测试过的服务器返回无穷大

#[derive(Debug, Clone)]
pub struct ServerPerformanceStats {
    pub score: f64,
    pub latency: f64,
    pub success_rate: f64,
    pub success: u32,
    pub failure: u32,
}

#[derive(Clone)]
pub struct ServerPerformance {
    latency_history: Vec<(Instant, Duration)>,
    success_count: u32,
    failure_count: u32,
    last_update: Instant,
    max_history_size: usize,
    half_life: Duration,
}

impl ServerPerformance {
    pub fn new(max_history_size: usize, half_life: Duration) -> Self {
        Self {
            latency_history: Vec::new(),
            success_count: 0,
            failure_count: 0,
            last_update: Instant::now(),
            max_history_size,
            half_life,
        }
    }

    pub fn add_result(&mut self, latency: Option<Duration>, success: bool) {
        let now = Instant::now();

        if success {
            self.latency_history
                .push((now, latency.unwrap_or(FAILURE_LATENCY)));
            self.success_count += 1;
        } else {
            self.latency_history.push((now, FAILURE_LATENCY));
            self.failure_count += 1;
        }
        self.last_update = now;

        // Keep only the most recent records
        if self.latency_history.len() > self.max_history_size {
            self.latency_history.remove(0);
        }
    }

    pub fn calculate_score(&self, now: Instant) -> f64 {
        let mut total_weighted_latency = 0.0;
        let mut total_weight = 0.0;

        for (timestamp, latency) in &self.latency_history {
            let age = now.duration_since(*timestamp);
            let weight = 2.0_f64.powf(-age.as_secs_f64() / self.half_life.as_secs_f64());
            total_weighted_latency += latency.as_millis() as f64 * weight;
            total_weight += weight;
        }

        if total_weight == 0.0 {
            return DEFAULT_SCORE;
        }

        // 如果没有成功记录，返回默认高分
        if self.success_count == 0 {
            return DEFAULT_SCORE;
        }

        total_weighted_latency / total_weight
    }

    pub fn get_stats(&self) -> ServerPerformanceStats {
        let now = Instant::now();
        let mut total_latency = 0.0;
        let mut count = 0;

        for (timestamp, latency) in &self.latency_history {
            let age = now.duration_since(*timestamp);
            let weight = 2.0_f64.powf(-age.as_secs_f64() / self.half_life.as_secs_f64());
            total_latency += latency.as_millis() as f64 * weight;
            count += 1;
        }

        let avg_latency = if count > 0 {
            total_latency / count as f64
        } else {
            DEFAULT_LATENCY
        };

        let success_rate = if self.success_count + self.failure_count > 0 {
            self.success_count as f64 / (self.success_count + self.failure_count) as f64
        } else {
            0.0
        };

        let score = self.calculate_score(now);

        ServerPerformanceStats {
            score,
            latency: avg_latency,
            success_rate,
            success: self.success_count,
            failure: self.failure_count,
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

    pub fn add_result(&self, server: &ServerConfig, latency: Option<Duration>, success: bool) {
        let mut history = self.performance_history.lock();
        let performance = history
            .entry(server.addr().to_string())
            .or_insert_with(|| ServerPerformance::new(self.max_history_size, self.half_life));
        performance.add_result(latency, success);
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

    pub fn get_all_server_stats(&self) -> Vec<(String, ServerPerformanceStats)> {
        let history = self.performance_history.lock();
        history
            .iter()
            .map(|(addr, perf)| {
                let stats = perf.get_stats();
                (addr.clone(), stats)
            })
            .collect()
    }
}
