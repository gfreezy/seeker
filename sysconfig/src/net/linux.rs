use crate::command::run_cmd;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::IpAddr;
use tracing::info;

pub struct DNSSetup {
    original_dns: Vec<String>,
    use_resolved: bool,
    dns: Vec<String>,
}

const RESOLV_PATH: &str = "/etc/resolv.conf";
const RESOLVED_OVERRIDE_PATH: &str = "/etc/systemd/resolved.conf.d/00-dns.conf";

impl DNSSetup {
    pub fn new(dns: Vec<String>) -> Self {
        if Self::is_system_using_resolved() {
            info!("setup dns with systemd-resolved");
            DNSSetup {
                original_dns: vec![],
                use_resolved: true,
                dns,
            }
        } else {
            info!("setup dns with /etc/resolv.conf");
            DNSSetup {
                original_dns: vec![],
                use_resolved: false,
                dns,
            }
        }
    }

    fn set_with_dnsresolv_conf(&mut self) {
        let original_dns = get_current_dns();
        info!("original dns: {:?}", &original_dns);
        let mut resolv = OpenOptions::new().write(true).open(RESOLV_PATH).unwrap();
        resolv
            .write_all(generate_resolve_file(&self.dns).as_slice())
            .unwrap();
        self.original_dns = original_dns;
    }

    fn is_system_using_resolved() -> bool {
        // check `/etc/resolv.conf` is a symlink
        std::fs::symlink_metadata(RESOLV_PATH)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
    }

    fn set_with_systemd_resolved(&self) {
        // create `/etc/resolved.conf.d` folder if not exists
        let _ = run_cmd("mkdir", &["-p", "/etc/systemd/resolved.conf.d"]);
        // create `/etc/resolved.conf.d/00-dns.conf` file
        let mut dns_conf = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(RESOLVED_OVERRIDE_PATH)
            .unwrap();
        // 172.17.0.1 is the host ip in docker default network. Set it as the second DNS server
        // to resolve the domain in the docker. It's required by docker containers in the default
        // network and when building images.
        dns_conf.write_all(b"[Resolve]\n").unwrap();
        for d in &self.dns {
            dns_conf
                .write_all(format!("DNS={}\n", d).as_bytes())
                .unwrap();
        }
        // restart systemd-resolved
        let _ = run_cmd("systemctl", &["restart", "systemd-resolved.service"]);
    }

    pub fn original_dns(&self) -> Vec<String> {
        self.original_dns.clone()
    }

    pub fn start(&mut self) {
        if self.use_resolved {
            self.set_with_systemd_resolved();
        } else {
            self.set_with_dnsresolv_conf();
        }
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        if self.use_resolved {
            info!("Restore original DNS");
            let _ = run_cmd("rm", &["-f", RESOLVED_OVERRIDE_PATH]);
            let _ = run_cmd("systemctl", &["restart", "systemd-resolved.service"]);
        } else {
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
}

pub fn setup_ip(tun_name: &str, ip: &str, cidr: &str, additional_cidrs: Vec<String>) {
    let _ = run_cmd("ip", &["addr", "add", ip, "dev", tun_name]);
    let _ = run_cmd("ip", &["link", "set", tun_name, "up"]);
    let _ = run_cmd("ip", &["route", "add", cidr, "via", ip, "dev", tun_name]);
    for additional_cidr in additional_cidrs {
        let _ = run_cmd(
            "ip",
            &[
                "route",
                "add",
                additional_cidr.as_str(),
                "via",
                ip,
                "dev",
                tun_name,
            ],
        );
    }
}

pub fn get_current_dns() -> Vec<String> {
    let mut resolv = OpenOptions::new().read(true).open(RESOLV_PATH).unwrap();
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
