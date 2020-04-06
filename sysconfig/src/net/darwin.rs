use crate::net::run_cmd;
use std::net::IpAddr;
use tracing::info;

pub struct DNSSetup {
    primary_network: String,
    original_dns: String,
}

impl DNSSetup {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let route_ret = run_cmd("route", &["-n", "get", "0.0.0.0"]);
        let device = route_ret
            .lines()
            .find(|l| l.contains("interface:"))
            .and_then(|l| l.split_whitespace().last())
            .map(|s| s.trim())
            .expect("get primary device");
        info!("Primary device is {}", device);
        let network_services = run_cmd("networksetup", &["-listallhardwareports"]);
        let mut iter = network_services.lines().peekable();
        let network = loop {
            if let Some(line) = iter.next() {
                if let Some(next_line) = iter.peek() {
                    if next_line.split(":").last().map(|l| l.contains(device)) == Some(true) {
                        if let Some(network) = line.split(":").last().map(|s| s.trim()) {
                            break network;
                        }
                    }
                } else {
                    panic!("No primary network found");
                }
            } else {
                panic!("No primary network found");
            }
        };
        info!("Primary netowrk service is {}", network);
        let original_dns = run_cmd("networksetup", &["-getdnsservers", network])
            .lines()
            .filter_map(|l| l.parse::<IpAddr>().ok())
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        info!("Original DNS is {}", &original_dns);
        if !original_dns.is_empty() {
            let _ = run_cmd(
                "networksetup",
                &["-setdnsservers", network, "127.0.0.1", &original_dns],
            );
        } else {
            let _ = run_cmd("networksetup", &["-setdnsservers", network, "127.0.0.1"]);
        }
        DNSSetup {
            primary_network: network.to_string(),
            original_dns,
        }
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        let dns = if self.original_dns.is_empty() || self.original_dns == "127.0.0.1" {
            "empty"
        } else {
            &self.original_dns
        };
        info!("Restore original DNS: {}", dns);

        let _ = run_cmd(
            "networksetup",
            &["-setdnsservers", &self.primary_network, dns],
        );
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str) {
    let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
    let _ = run_cmd("route", &["add", cidr, ip]);
}
