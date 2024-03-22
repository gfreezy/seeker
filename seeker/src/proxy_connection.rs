use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use crate::traffic::Traffic;
use config::{rule::Action, Address, ServerConfig};
use store::Store;

// id generator for connection
pub static CONNECTION_ID: AtomicUsize = AtomicUsize::new(0);

pub fn next_connection_id() -> u64 {
    CONNECTION_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst) as u64
}

#[allow(dead_code)]
pub trait ProxyConnection {
    fn id(&self) -> u64;
    fn network(&self) -> &'static str;
    fn conn_type(&self) -> &'static str;
    fn traffic(&self) -> Traffic;
    fn recv_bytes(&self) -> usize;
    fn sent_bytes(&self) -> usize;
    fn action(&self) -> Action;
    fn config(&self) -> Option<&ServerConfig>;
    fn has_config(&self, config: Option<&ServerConfig>) -> bool;
    fn shutdown(&self);
    fn is_alive(&self) -> bool;
    fn remote_addr(&self) -> Option<&Address> {
        None
    }
    fn duration(&self) -> Duration {
        self.connect_time().elapsed()
    }
    fn connect_time(&self) -> Instant;
}

pub trait ProxyConnectionEventListener {
    fn on_connect(&self, conn: &dyn ProxyConnection);
    fn on_shutdown(&self, conn: &dyn ProxyConnection);
    fn on_recv_bytes(&self, conn: &dyn ProxyConnection, bytes: usize);
    fn on_send_bytes(&self, conn: &dyn ProxyConnection, bytes: usize);
}

#[derive(Clone)]
pub struct StoreListener;

impl ProxyConnectionEventListener for StoreListener {
    fn on_connect(&self, conn: &dyn ProxyConnection) {
        let store = Store::global();

        let host = conn
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        let proxy_server = conn
            .config()
            .map(|config| config.addr().to_string())
            .unwrap_or_default();
        let ret = store.new_connection(
            conn.id(),
            &host,
            conn.network(),
            conn.conn_type(),
            &proxy_server,
        );
        if let Err(e) = ret {
            tracing::error!("Failed to insert live connection: {}", e);
        }
    }

    fn on_shutdown(&self, conn: &dyn ProxyConnection) {
        let store = Store::global();
        let ret = store.shutdown_connection(conn.id());
        if let Err(e) = ret {
            tracing::error!("Failed to remove live connection: {}", e);
        }
    }

    fn on_recv_bytes(&self, conn: &dyn ProxyConnection, bytes: usize) {
        let store = Store::global();
        let ret = store.incr_connection_recv_bytes(conn.id(), bytes as u64, None);
        if let Err(e) = ret {
            tracing::error!("Failed to increment recv bytes: {}", e);
        }
    }
    fn on_send_bytes(&self, conn: &dyn ProxyConnection, bytes: usize) {
        let store = Store::global();
        let ret = store.incr_connection_sent_bytes(conn.id(), bytes as u64, None);
        if let Err(e) = ret {
            tracing::error!("Failed to increment sent bytes: {}", e);
        }
    }
}
