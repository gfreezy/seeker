pub mod rule;
mod server_config;
mod socks5;
pub use server_config::{ServerAddr, ServerConfig};
pub use socks5::Address;

use crypto::CipherType;
use rule::{ProxyRules, Rule};
use serde::Deserialize;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_configs: Arc<Vec<ServerConfig>>,
    pub dns_start_ip: Ipv4Addr,
    pub dns_server: SocketAddr,
    pub tun_name: String,
    pub tun_ip: Ipv4Addr,
    pub tun_cidr: Ipv4Cidr,
    pub rules: ProxyRules,
    pub dns_listen: String,
    pub gateway_mode: bool,
    pub probe_timeout: Duration,
    pub direct_connect_timeout: Duration,
    pub max_connect_errors: usize,
}

#[derive(Deserialize, Debug, Clone)]
struct YamlServerConfig {
    /// Server name
    name: String,
    /// Server address
    addr: String,
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    method: String,
    /// Connection timeout
    connect_timeout: u64,
    /// Connection timeout
    read_timeout: u64,
    /// Connection timeout
    write_timeout: u64,
    /// Idle Connections
    idle_connections: usize,
}

#[derive(Debug, Deserialize, Clone)]
struct YamlConfig {
    server_configs: Vec<YamlServerConfig>,
    dns_start_ip: String,
    dns_server: String,
    tun_name: String,
    tun_ip: String,
    tun_cidr: String,
    rules: Vec<String>,
    dns_listen: String,
    gateway_mode: bool,
    probe_timeout_ms: u64,
    direct_connect_timeout: u64,
    max_connect_errors: usize,
}

impl Config {
    pub fn from_config_file(path: &str) -> Self {
        let file = File::open(&path).unwrap();
        let conf: YamlConfig = serde_yaml::from_reader(&file).unwrap();
        let yaml_server_configs = conf.server_configs;
        let server_configs = yaml_server_configs
            .into_iter()
            .map(|yaml_server_config| {
                ServerConfig::new(
                    yaml_server_config.name,
                    ServerAddr::from_str(&yaml_server_config.addr).unwrap(),
                    yaml_server_config.password,
                    CipherType::from_str(&yaml_server_config.method).unwrap(),
                    Duration::from_secs(yaml_server_config.connect_timeout),
                    Duration::from_secs(yaml_server_config.read_timeout),
                    Duration::from_secs(yaml_server_config.write_timeout),
                    yaml_server_config.idle_connections,
                )
            })
            .collect();
        Config {
            server_configs: Arc::new(server_configs),
            dns_start_ip: conf.dns_start_ip.parse().unwrap(),
            dns_server: conf.dns_server.parse().unwrap(),
            tun_name: conf.tun_name,
            tun_ip: conf.tun_ip.parse().unwrap(),
            tun_cidr: parse_cidr(conf.tun_cidr),
            rules: ProxyRules::new(
                conf.rules
                    .iter()
                    .map(|rule| Rule::from_str(rule).unwrap())
                    .collect(),
            ),
            dns_listen: conf.dns_listen,
            gateway_mode: conf.gateway_mode,
            probe_timeout: Duration::from_millis(conf.probe_timeout_ms),
            direct_connect_timeout: Duration::from_secs(conf.direct_connect_timeout),
            max_connect_errors: conf.max_connect_errors,
        }
    }
}

fn parse_cidr(s: String) -> Ipv4Cidr {
    let segments = s.splitn(2, '/').collect::<Vec<&str>>();
    let addr = segments[0];
    let len = segments[1];
    let addr: Ipv4Addr = addr.parse().unwrap();
    let prefix = len.parse().unwrap();
    Ipv4Cidr::new(Ipv4Address::from(addr), prefix)
}
