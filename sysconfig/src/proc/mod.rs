#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
pub mod sys;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
pub mod sys;
