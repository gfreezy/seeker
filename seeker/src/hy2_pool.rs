use config::ServerConfig;
use hysteria2_client::{Hy2Client, Hy2Config};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

/// Global pool of Hy2Client instances, keyed by server name.
/// Each server gets one shared QUIC connection.
static HY2_CLIENTS: Mutex<Option<HashMap<String, Arc<Hy2Client>>>> = Mutex::new(None);

/// Get or create a Hy2Client for the given server config.
pub fn get_hy2_client(
    config: &ServerConfig,
    server_addr: SocketAddr,
) -> io::Result<Arc<Hy2Client>> {
    let mut pool = HY2_CLIENTS.lock();
    let map = pool.get_or_insert_with(HashMap::new);

    let key = config.name().to_string();
    if let Some(client) = map.get(&key) {
        return Ok(client.clone());
    }

    let sni = config
        .sni()
        .map(|s| s.to_string())
        .or_else(|| config.addr().hostname().map(|s| s.to_string()))
        .unwrap_or_else(|| server_addr.ip().to_string());

    let password = config.password().unwrap_or("").to_string();

    let hy2_config = Hy2Config {
        server_addr,
        sni,
        password,
        obfs_password: config.obfs_password().map(|s| s.to_string()),
        insecure: config.insecure(),
        recv_window: config.recv_window(),
    };

    let client = Hy2Client::new(hy2_config);
    map.insert(key, client.clone());
    Ok(client)
}
