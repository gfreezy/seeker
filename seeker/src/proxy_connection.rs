use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use crate::traffic::Traffic;
use config::{rule::Action, Address, ServerConfig};

// id generator for connection
pub static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

pub fn next_connection_id() -> u64 {
    CONNECTION_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

pub trait ProxyConnection {
    fn id(&self) -> u64;
    fn traffic(&self) -> Traffic;
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
