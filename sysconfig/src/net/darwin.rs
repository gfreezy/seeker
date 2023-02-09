use crate::command::run_cmd;
use std::net::IpAddr;
use tracing::info;

pub struct DNSSetup {
    primary_network: String,
    // DNS servers from networksetup. DHCP dns servers are not included.
    original_real_dns: Vec<String>,
    // DNS servers from scutil. Real used DNS servers.
    original_manual_dns: Vec<String>,
    // DNS servers to be set.
    dns: String,
}

impl DNSSetup {
    #[allow(clippy::new_without_default)]
    pub fn new(dns: String) -> Self {
        let network = get_primary_network();
        info!("Primary netowrk service is {}", &network);
        let original_manual_dns = run_cmd("networksetup", &["-getdnsservers", &network])
            .lines()
            .filter(|l| *l != "127.0.0.1" && *l != dns)
            .filter_map(|l| l.parse::<IpAddr>().ok())
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>();

        // Get macos dns servers from terminal
        let lines = run_cmd("scutil", &["--dns"]);
        let original_dns = parse_scutil_dns(&lines);

        DNSSetup {
            primary_network: network,
            original_real_dns: original_dns,
            original_manual_dns,
            dns,
        }
    }

    pub fn start(&self) {
        let original_dns = &self.original_real_dns;
        let network = &self.primary_network;
        if !original_dns.is_empty() {
            let mut args = vec!["-setdnsservers", network, "127.0.0.1"];
            for dns in original_dns {
                args.push(dns);
            }
            let _ = run_cmd("networksetup", &args);
        } else if self.dns.is_empty() {
            let _ = run_cmd("networksetup", &["-setdnsservers", network, "127.0.0.1"]);
        } else {
            let _ = run_cmd(
                "networksetup",
                &["-setdnsservers", network, "127.0.0.1", &self.dns],
            );
        }

        info!(
            "Setup DNS: {}, Original DNS is {:?}, Original real DNS is {:?}",
            &self.dns, &self.original_manual_dns, &original_dns,
        );
    }

    pub fn original_dns(&self) -> Vec<String> {
        self.original_real_dns.clone()
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        let mut args = vec!["-setdnsservers", &self.primary_network];
        if self.original_manual_dns.is_empty() {
            args.push("empty");
        } else {
            for dns in &self.original_manual_dns {
                args.push(dns);
            }
        };
        info!("Restore original DNS: {:?}", self.original_manual_dns);

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

fn parse_scutil_dns(lines: &str) -> Vec<String> {
    let mut dns: Vec<String> = vec![];
    for l in lines.lines() {
        if !l.trim().starts_with("nameserver[") {
            continue;
        }
        let Some(ip) = l.split(':').nth(1) else { continue };
        let Ok(ip) = ip.trim().parse::<IpAddr>() else {continue;};
        let ip = ip.to_string();
        if !dns.contains(&ip) {
            dns.push(ip);
        }
    }
    dns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scutil_dns() {
        let lines = r#"DNS configuration

        resolver #1
          nameserver[0] : 192.168.2.1
          if_index : 15 (en0)
          flags    : Request A records
          reach    : 0x00020002 (Reachable,Directly Reachable Address)

        resolver #2
          domain   : local
          options  : mdns
          timeout  : 5
          flags    : Request A records
          reach    : 0x00000000 (Not Reachable)
          order    : 300000

        resolver #3
          domain   : 254.169.in-addr.arpa
          options  : mdns
          timeout  : 5
          flags    : Request A records
          reach    : 0x00000000 (Not Reachable)
          order    : 300200

        resolver #4
          domain   : 8.e.f.ip6.arpa
          options  : mdns
          timeout  : 5
          flags    : Request A records
          reach    : 0x00000000 (Not Reachable)
          order    : 300400

        resolver #5
          domain   : 9.e.f.ip6.arpa
          options  : mdns
          timeout  : 5
          flags    : Request A records
          reach    : 0x00000000 (Not Reachable)
          order    : 300600

        resolver #6
          domain   : a.e.f.ip6.arpa
          options  : mdns
          timeout  : 5
          flags    : Request A records
          reach    : 0x00000000 (Not Reachable)
          order    : 300800

        resolver #7
          domain   : b.e.f.ip6.arpa
          options  : mdns
          timeout  : 5
          flags    : Request A records
          reach    : 0x00000000 (Not Reachable)
          order    : 301000

        DNS configuration (for scoped queries)

        resolver #1
          nameserver[0] : 192.168.2.1
          if_index : 15 (en0)
          flags    : Scoped, Request A records
          reach    : 0x00020002 (Reachable,Directly Reachable Address)
        "#;
        let ret = parse_scutil_dns(lines);
        assert_eq!(ret, vec!["192.168.2.1"]);
    }
}
