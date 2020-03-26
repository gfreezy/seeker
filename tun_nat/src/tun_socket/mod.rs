#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

pub use self::tun::TunSocket;
