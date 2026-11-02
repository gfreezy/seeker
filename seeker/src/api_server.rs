use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::server_chooser::ServerChooser;
use crate::server_performance::{DEFAULT_SCORE, ServerPerformanceStats};

#[derive(Serialize)]
struct StatsResponse {
    groups: HashMap<String, GroupStats>,
}

#[derive(Serialize)]
struct GroupStats {
    selected_server: ServerStats,
    servers: Vec<ServerStats>,
}

#[derive(Serialize)]
struct ServerStats {
    name: String,
    server: String,
    protocol: String,
    #[serde(flatten)]
    stats: Option<ServerPerformanceStats>,
}

#[derive(Clone)]
struct ApiState {
    chooser: ServerChooser,
    ping_gate: Arc<Semaphore>,
}

async fn get_stats(State(state): State<ApiState>) -> Json<StatsResponse> {
    let all_stats = state.chooser.get_all_performance_stats();
    let groups = all_stats
        .into_iter()
        .map(
            |(group_name, (selected_name, selected_addr, selected_protocol, stats))| {
                let mut server_stats: Vec<ServerStats> = stats
                    .into_iter()
                    .map(|(server, name, protocol, stats)| ServerStats {
                        name,
                        server,
                        protocol,
                        stats: Some(stats),
                    })
                    .collect();
                server_stats.sort_by(|a, b| {
                    let score_a = a.stats.as_ref().map(|s| s.score).unwrap_or(DEFAULT_SCORE);
                    let score_b = b.stats.as_ref().map(|s| s.score).unwrap_or(DEFAULT_SCORE);
                    score_a
                        .partial_cmp(&score_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                let selected_stats = server_stats
                    .iter()
                    .find(|s| s.name == selected_name)
                    .map(|s| s.stats.clone())
                    .unwrap_or(None);
                (
                    group_name,
                    GroupStats {
                        selected_server: ServerStats {
                            name: selected_name,
                            server: selected_addr,
                            protocol: selected_protocol,
                            stats: selected_stats,
                        },
                        servers: server_stats,
                    },
                )
            },
        )
        .collect();
    Json(StatsResponse { groups })
}

async fn ping_all(State(state): State<ApiState>) -> Result<Json<StatsResponse>, StatusCode> {
    let gate = state.ping_gate.clone();
    let _permit = gate.try_acquire().map_err(|_| StatusCode::CONFLICT)?;
    state
        .chooser
        .ping_all_servers()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(get_stats(State(state)).await)
}

pub async fn run_api_server(addr: SocketAddr, server_chooser: ServerChooser) {
    let state = ApiState {
        chooser: server_chooser,
        ping_gate: Arc::new(Semaphore::new(1)),
    };
    let app = Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/ping", post(ping_all))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind API server address");
    tracing::info!("API server listening on {}", addr);
    axum::serve(listener, app).await.expect("API server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_client::DnsClient;
    use config::Config;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn state(addr: SocketAddr) -> ApiState {
        let config: Config = serde_json::from_value(serde_json::json!({
            "dns_start_ip": "11.0.0.10", "tun_bypass_direct": true,
            "tun_ip": "11.0.0.1", "tun_cidr": "11.0.0.0/16", "rules": [],
            "ping_urls": [{"host":"example.test", "port":80, "path":"/"}],
            "max_connect_errors": 1,
            "servers": [{"name":"only", "addr":addr.to_string(), "protocol":"Http"}],
            "proxy_groups": [{"name":"", "type":"select", "default_selected":"only", "proxies":["only"]}]
        })).unwrap();
        let dns = DnsClient::new(&[], Duration::from_secs(1)).await;
        let chooser = ServerChooser::new(config.clone(), dns, false).await;
        ApiState {
            chooser,
            ping_gate: Arc::new(Semaphore::new(1)),
        }
    }

    async fn read_request_headers(connection: &mut tokio::net::TcpStream) {
        let mut request = [0; 4096];
        let mut length = 0;
        while !request[..length].ends_with(b"\r\n\r\n") {
            let count = connection.read(&mut request[length..]).await.unwrap();
            assert!(count > 0, "Expected complete HTTP request headers");
            length += count;
        }
    }

    #[tokio::test]
    async fn manual_ping_tests_a_single_selected_server_without_switching_it() {
        store::Store::setup_global_for_test();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = state(listener.local_addr().unwrap()).await;
        let chooser = state.chooser.clone();
        let proxy = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            read_request_headers(&mut connection).await;
            connection
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            read_request_headers(&mut connection).await;
            connection
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
        });
        let Json(results) = ping_all(State(state)).await.unwrap();
        proxy.await.unwrap();
        assert_eq!(results.groups[""].servers.len(), 1);
        let stats = results.groups[""].servers[0].stats.as_ref().unwrap();
        assert!(stats.latency >= 0.0);
        assert_eq!(stats.success, 1);
        assert_eq!(chooser.get_all_performance_stats()[""].0, "only");
    }

    #[tokio::test]
    async fn concurrent_manual_ping_returns_conflict() {
        let state = state("127.0.0.1:9".parse().unwrap()).await;
        let gate = state.ping_gate.clone();
        let _permit = gate.acquire().await.unwrap();
        assert!(matches!(
            ping_all(State(state)).await,
            Err(StatusCode::CONFLICT)
        ));
    }
}
