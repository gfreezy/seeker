use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::server_chooser::ServerChooser;
use crate::server_performance::{ServerPerformanceStats, DEFAULT_SCORE};

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

async fn get_stats(State(chooser): State<ServerChooser>) -> Json<StatsResponse> {
    let all_stats = chooser.get_all_performance_stats();
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

pub async fn run_api_server(addr: SocketAddr, server_chooser: ServerChooser) {
    let app = Router::new()
        .route("/api/stats", get(get_stats))
        .with_state(server_chooser);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind API server address");
    tracing::info!("API server listening on {}", addr);
    axum::serve(listener, app).await.expect("API server error");
}
