use crate::traffic::Traffic;
use config::{Address, ServerConfig};

pub trait ProxyConnection {
    fn traffic(&self) -> Traffic;
    fn config(&self) -> Option<&ServerConfig>;
    fn has_config(&self, config: Option<&ServerConfig>) -> bool;
    fn shutdown(&self);
    fn strong_count(&self) -> usize;
    fn remote_addr(&self) -> Option<&Address> {
        None
    }
}
