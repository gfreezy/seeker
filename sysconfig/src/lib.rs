mod net;
mod proc;

pub use net::{setup_ip, DNSSetup};

#[cfg(target_os = "macos")]
pub use proc::sys::{list_system_proc_socks, list_user_proc_socks};
pub use proc::SocketInfo;
