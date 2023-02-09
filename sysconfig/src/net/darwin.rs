use crate::command::run_cmd;
use std::net::IpAddr;
use tracing::info;

pub struct DNSSetup {
    primary_network: String,
    original_dns: Vec<String>,
    dns: String,
}

impl DNSSetup {
    #[allow(clippy::new_without_default)]
    pub fn new(dns: String) -> Self {
        let network = get_primary_network();
        info!("Primary netowrk service is {}", &network);
        let original_dns = run_cmd("networksetup", &["-getdnsservers", &network])
            .lines()
            .filter(|l| *l != "127.0.0.1" && *l != dns)
            .filter_map(|l| l.parse::<IpAddr>().ok())
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>();

        info!("Original DNS is {:?}", &original_dns);

        DNSSetup {
            primary_network: network,
            original_dns,
            dns,
        }
    }

    pub fn start(&self) {
        let original_dns = &self.original_dns;
        let network = &self.primary_network;
        if !original_dns.is_empty() {
            let mut args = vec!["-setdnsservers", network, "127.0.0.1"];
            for dns in original_dns {
                args.push(dns);
            }
            let _ = run_cmd("networksetup", &args);
        } else if self.dns.is_empty() {
            let _ = run_cmd("networksetup", &["-setdnsservers", &network, "127.0.0.1"]);
        } else {
            let _ = run_cmd(
                "networksetup",
                &["-setdnsservers", &network, "127.0.0.1", &self.dns],
            );
        }
    }

    pub fn original_dns(&self) -> Vec<String> {
        self.original_dns.clone()
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        let mut args = vec!["-setdnsservers", &self.primary_network];
        if self.original_dns.is_empty() {
            args.push("empty");
        } else {
            for dns in &self.original_dns {
                args.push(dns);
            }
        };
        info!("Restore original DNS: {:?}", self.original_dns);

        let _ = run_cmd("networksetup", &args);
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str, additional_cidrs: Vec<String>) {
    let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
    let _ = run_cmd("route", &["add", cidr, ip]);
    for additional_cidr in additional_cidrs {
        let _ = run_cmd("route", &["add", additional_cidr.as_str(), ip]);
    }
}

fn get_primary_network() -> String {
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
    loop {
        if let Some(line) = iter.next() {
            if let Some(next_line) = iter.peek() {
                if next_line.split(':').last().map(|l| l.contains(device)) == Some(true) {
                    if let Some(network) = line.split(':').last().map(|s| s.trim()) {
                        return network.to_string();
                    }
                }
            } else {
                panic!("No primary network found");
            }
        } else {
            panic!("No primary network found");
        }
    }
}
