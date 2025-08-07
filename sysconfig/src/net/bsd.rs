use crate::command::run_cmd;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::IpAddr;
use tracing::info;

pub struct DNSSetup {
    original_dns: Vec<String>,
    dns: Vec<String>,
}

const RESOLV_PATH: &str = "/etc/resolv.conf";

impl DNSSetup {
    pub fn new(dns: Vec<String>) -> Self {
        info!("setup dns with /etc/resolv.conf on BSD");
        DNSSetup {
            original_dns: vec![],
            dns,
        }
    }

    pub fn start(&mut self) {
        let original_dns = get_current_dns();
        info!("original dns: {:?}", &original_dns);

        // Backup original DNS
        self.original_dns = original_dns;

        // Set new DNS servers
        let mut resolv = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(RESOLV_PATH)
            .unwrap();
        resolv
            .write_all(generate_resolve_file(&self.dns).as_slice())
            .unwrap();
    }

    pub fn original_dns(&self) -> Vec<String> {
        self.original_dns.clone()
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        info!("Restore original DNS: {:?}", self.original_dns);
        let mut resolv = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(RESOLV_PATH)
            .unwrap();
        resolv
            .write_all(generate_resolve_file(&self.original_dns).as_slice())
            .unwrap();
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str, additional_cidrs: Vec<String>) {
    // Configure TUN interface on BSD
    let _ = run_cmd("ifconfig", &[tun_name, ip, ip]);
    let _ = run_cmd("ifconfig", &[tun_name, "up"]);

    // Add routes
    let _ = run_cmd("route", &["add", cidr, ip]);
    for additional_cidr in additional_cidrs {
        let _ = run_cmd("route", &["add", additional_cidr.as_str(), ip]);
    }
}

pub fn get_current_dns() -> Vec<String> {
    let mut resolv = OpenOptions::new()
        .read(true)
        .open(RESOLV_PATH)
        .unwrap();
    let mut buf = vec![];
    let _ = resolv.read_to_end(&mut buf).unwrap();
    let content = std::str::from_utf8(&buf).unwrap();

    let dns_list: Vec<String> = content
        .lines()
        .filter(|l| l.contains("nameserver"))
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect();
    dns_list
}

fn generate_resolve_file(dns: &[String]) -> Vec<u8> {
    let mut content = Vec::new();
    for d in dns {
        if !d.is_empty() {
            content.extend_from_slice(format!("nameserver {}\n", d).as_bytes());
        }
    }
    content
}
