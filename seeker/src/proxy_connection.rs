use std::time::{Duration, Instant};

use crate::traffic::Traffic;
use config::{rule::Action, Address, ServerConfig};

pub trait ProxyConnection {
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
