use std::process::Command;
use tracing::debug;

fn run_cmd(cmd: &str, args: &[&str]) -> String {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .expect("run cmd failed");
    debug!("{} {:?}", cmd, args);

    if !output.status.success() {
        panic!(
            "{} {}\nstdout: {}\nstderr: {}",
            cmd,
            args.join(" "),
            std::str::from_utf8(&output.stdout).expect("utf8"),
            std::str::from_utf8(&output.stderr).expect("utf8")
        );
    }
    std::str::from_utf8(&output.stdout)
        .expect("utf8")
        .to_string()
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd"
))]
const IP_FORWARDING_KEY: &str = "net.inet.ip.forwarding";
#[cfg(target_os = "linux")]
const IP_FORWARDING_KEY: &str = "net.ipv4.ip_forward";

pub struct IpForward {
    original_option: usize,
}

impl IpForward {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let output = run_cmd("sysctl", &["-n", IP_FORWARDING_KEY]);
        let option = output.trim().parse::<usize>().unwrap();
        let _ = run_cmd("sysctl", &["-w", &format!("{}={}", IP_FORWARDING_KEY, 1)]);
        IpForward {
            original_option: option,
        }
    }
}

impl Drop for IpForward {
    fn drop(&mut self) {
        let _ = run_cmd(
            "sysctl",
            &[
                "-w",
                &format!("{}={}", IP_FORWARDING_KEY, self.original_option),
            ],
        );
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "darwin.rs"]
pub mod sys;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
pub mod sys;

pub use sys::{setup_ip, DNSSetup};
