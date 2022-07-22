use crate::command::run_cmd;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use tracing::info;

pub struct DNSSetup {
    original_dns: Vec<String>,
}

const RESOLV_PATH: &str = "/etc/resolv.conf";
impl DNSSetup {
    pub fn new(dns: String) -> Self {
        info!("setup dns");
        let mut resolv = OpenOptions::new()
            .read(true)
            .write(true)
            .open(RESOLV_PATH)
            .unwrap();
        let mut buf = vec![];
        let _ = resolv.read_to_end(&mut buf).unwrap();

        let content = std::str::from_utf8(&buf).unwrap();
        let original_dns = get_original_dns(content, &dns);
        info!("original dns: {:?}", &original_dns);

        resolv.set_len(0).unwrap();
        resolv.seek(SeekFrom::Start(0)).unwrap();
        resolv
            .write_all(generate_resolve_file(&["127.0.0.1", &dns]).as_slice())
            .unwrap();

        DNSSetup { original_dns }
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
            .write_all(
                generate_resolve_file(
                    self.original_dns
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .as_slice(),
            )
            .unwrap();
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, _cidr: &str) {
    let _ = run_cmd("ip", &["addr", "add", ip, "dev", tun_name]);
    let _ = run_cmd("ip", &["link", "set", tun_name, "up"]);
}

fn get_original_dns(content: &str, dns: &str) -> Vec<String> {
    let mut dns_list: Vec<_> = content
        .lines()
        .filter(|l| l.contains("nameserver"))
        .filter_map(|l| l.split_whitespace().last())
        .filter(|l| *l != dns && *l != "127.0.0.1")
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect();
    if dns_list.is_empty() && !dns.is_empty() {
        dns_list.push(dns.to_string())
    }
    dns_list
}

fn generate_resolve_file(dns: &[&str]) -> Vec<u8> {
    let mut content = Vec::new();
    for d in dns {
        if !d.is_empty() {
            content.extend_from_slice(format!("nameserver {}\n", d).as_bytes());
        }
    }
    content
}
