use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::server_chooser::ServerChooser;
use crate::server_performance::ServerPerformanceStats;

#[derive(Serialize)]
struct StatsResponse {
    groups: HashMap<String, Vec<ServerStats>>,
}

#[derive(Serialize)]
struct ServerStats {
    name: String,
    server: String,
    #[serde(flatten)]
    stats: ServerPerformanceStats,
}

async fn get_stats(State(chooser): State<ServerChooser>) -> Json<StatsResponse> {
    let all_stats = chooser.get_all_performance_stats();
    let groups = all_stats
        .into_iter()
        .map(|(group_name, stats)| {
            let server_stats = stats
                .into_iter()
                .map(|(server, name, stats)| ServerStats {
                    name,
                    server,
                    stats,
                })
                .collect();
            (group_name, server_stats)
        })
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
    axum::serve(listener, app)
        .await
        .expect("API server error");
}
