use crate::command::run_cmd;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Command;
use tracing::{info, warn};

pub struct DNSSetup {
    primary_network: Option<String>,
    // DNS servers from scutil. Real used DNS servers.
    original_real_dns: Vec<String>,
    // DNS servers from networksetup. DHCP dns servers are not included.
    original_manual_dns: BTreeMap<String, Vec<String>>,
    // DNS servers to be set.
    dns: Vec<String>,
}

impl DNSSetup {
    #[allow(clippy::new_without_default)]
    pub fn new(dns: Vec<String>) -> Self {
        // Get macos dns servers from terminal
        let original_dns = get_current_dns();

        DNSSetup {
            primary_network: None,
            original_real_dns: original_dns,
            original_manual_dns: BTreeMap::new(),
            dns,
        }
    }

    pub fn start(&mut self) {
        self.reapply();
    }

    pub fn reapply(&mut self) {
        let Some(network) = get_primary_network() else {
            warn!("Skip DNS setup because primary network service was not found");
            return;
        };

        if self.primary_network.as_deref() != Some(network.as_str()) {
            info!(
                "Primary network service changed from {:?} to {}",
                self.primary_network, network
            );
        }

        self.original_manual_dns
            .entry(network.clone())
            .or_insert_with(|| get_manual_dns(&network));
        set_dns(&network, &self.dns);
        self.primary_network = Some(network.clone());

        info!(
            "Setup DNS: {:?}, Original DNS is {:?}, Original real DNS is {:?}",
            &self.dns,
            self.original_manual_dns.get(&network),
            &self.original_real_dns,
        );
    }

    pub fn original_dns(&self) -> Vec<String> {
        self.original_real_dns.clone()
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        for (network, original_manual_dns) in &self.original_manual_dns {
            restore_dns(network, original_manual_dns);
        }
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str, additional_cidrs: Vec<String>) {
    let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
    let _ = run_cmd("route", &["add", cidr, ip]);
    for additional_cidr in additional_cidrs {
        let _ = run_cmd("route", &["add", additional_cidr.as_str(), ip]);
    }
}

fn get_primary_network() -> Option<String> {
    let route_ret = try_run_cmd("route", &["-n", "get", "0.0.0.0"])?;
    let device = route_ret
        .lines()
        .find(|l| l.contains("interface:"))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| s.trim())?;
    info!("Primary device is {}", device);
    let network_services = try_run_cmd("networksetup", &["-listallhardwareports"])?;
    let network = find_network_service_for_device(&network_services, device)?;
    info!("Primary network service is {}", &network);
    Some(network)
}

fn find_network_service_for_device(network_services: &str, device: &str) -> Option<String> {
    let mut iter = network_services.lines().peekable();
    while let Some(line) = iter.next() {
        if let Some(next_line) = iter.peek() {
            if next_line.split(':').next_back().map(|l| l.contains(device)) == Some(true) {
                if let Some(network) = line.split(':').next_back().map(|s| s.trim()) {
                    return Some(network.to_string());
                }
            }
        }
    }
    None
}

fn get_manual_dns(network: &str) -> Vec<String> {
    let Some(output) = try_run_cmd("networksetup", &["-getdnsservers", network]) else {
        warn!("Failed to get manual DNS for network service {}", network);
        return vec![];
    };

    output
        .lines()
        .filter_map(|l| l.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
}

fn set_dns(network: &str, dns: &[String]) {
    let mut args = vec!["-setdnsservers", network, "127.0.0.1"];
    args.extend(dns.iter().map(String::as_str));

    if try_run_cmd("networksetup", &args).is_none() {
        warn!("Failed to setup DNS for network service {}", network);
    }
}

fn restore_dns(network: &str, original_manual_dns: &[String]) {
    let mut args = vec!["-setdnsservers", network];
    if original_manual_dns.is_empty() {
        args.push("empty");
    } else {
        args.extend(original_manual_dns.iter().map(String::as_str));
    }
    info!(
        "Restore original DNS for {}: {:?}",
        network, original_manual_dns
    );

    if try_run_cmd("networksetup", &args).is_none() {
        warn!("Failed to restore DNS for network service {}", network);
    }
}

fn try_run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    let stderr = std::str::from_utf8(&output.stderr).unwrap_or("");
    info!("cmd: {cmd}, args: {:?}", args);
    info!("stdout: {}", stdout);
    info!("stderr: {}", stderr);

    if !output.status.success() {
        warn!(
            "{} {}\nstdout: {}\nstderr: {}",
            cmd,
            args.join(" "),
            stdout,
            stderr
        );
        return None;
    }
    Some(stdout.to_string())
}

pub fn get_current_dns() -> Vec<String> {
    // Get macos dns servers from terminal
    let lines = run_cmd("scutil", &["--dns"]);
    let original_dns = parse_scutil_dns(&lines);
    info!("Original DNS is {:?}", original_dns);
    original_dns
}

fn parse_scutil_dns(lines: &str) -> Vec<String> {
    let mut dns: Vec<String> = vec![];
    for l in lines.lines() {
        if !l.trim().starts_with("nameserver[") {
            continue;
        }
        let Some(ip) = l.split(':').nth(1) else {
            continue;
        };
        let Ok(ip) = ip.trim().parse::<IpAddr>() else {
            continue;
        };
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

    #[test]
    fn test_find_network_service_for_device() {
        let network_services = r#"
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: 7e:f9:13:0a:fb:66

Hardware Port: AX88772A
Device: en14
Ethernet Address: 00:0e:c6:d6:30:b1

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 84:2f:57:31:a0:bb
"#;

        assert_eq!(
            find_network_service_for_device(network_services, "en14"),
            Some("AX88772A".to_string())
        );
    }
}
