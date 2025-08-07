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

#[cfg(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
#[path = "bsd.rs"]
pub mod sys;

pub use sys::{list_system_proc_socks, list_user_proc_socks};
