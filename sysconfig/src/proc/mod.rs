use std::net::SocketAddr;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SocketInfo {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
pub mod sys;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
pub mod sys;
