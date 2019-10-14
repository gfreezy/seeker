#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "darwin.rs"]
pub mod sys;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
pub mod sys;

pub use sys::{setup_ip, DNSSetup};
