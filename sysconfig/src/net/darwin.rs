use crate::net::run_cmd;
use tracing::info;

pub struct DNSSetup;

impl DNSSetup {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let _ = run_cmd("networksetup", &["-setdnsservers", "Wi-Fi", "127.0.0.1"]);
        DNSSetup
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        info!("clear dns");
        let _ = run_cmd("networksetup", &["-setdnsservers", "Wi-Fi", "empty"]);
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str) {
    let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
    let _ = run_cmd("route", &["add", cidr, ip]);
}
