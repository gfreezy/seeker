pub mod rule;

use rule::{ProxyRules, Rule};
use serde::Deserialize;
use shadowsocks::crypto::CipherType;
use shadowsocks::{ServerAddr, ServerConfig};
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_config: Arc<ServerConfig>,
    pub dns_start_ip: Ipv4Addr,
    pub dns_server: SocketAddr,
    pub tun_name: String,
    pub tun_ip: Ipv4Addr,
    pub tun_cidr: String,
    pub rules: ProxyRules,
}

#[derive(Deserialize, Debug, Clone)]
struct YamlServerConfig {
    /// Server address
    addr: String,
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    method: String,
    /// Connection timeout
    timeout: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
struct YamlConfig {
    server_config: YamlServerConfig,
    dns_start_ip: String,
    dns_server: String,
    tun_name: String,
    tun_ip: String,
    tun_cidr: String,
    rules: Vec<String>,
}

impl Config {
    pub fn from_config_file(path: &str) -> Self {
        let file = File::open(&path).unwrap();
        let conf: YamlConfig = serde_yaml::from_reader(&file).unwrap();
        let yaml_server_config = conf.server_config;
        let server_config = ServerConfig::new(
            ServerAddr::from_str(&yaml_server_config.addr).unwrap(),
            yaml_server_config.password,
            CipherType::from_str(&yaml_server_config.method).unwrap(),
            yaml_server_config
                .timeout
                .map(|t| Duration::from_secs(u64::from(t))),
            None,
        );
        Config {
            server_config: Arc::new(server_config),
            dns_start_ip: conf.dns_start_ip.parse().unwrap(),
            dns_server: conf.dns_server.parse().unwrap(),
            tun_name: conf.tun_name,
            tun_ip: conf.tun_ip.parse().unwrap(),
            tun_cidr: check_cidr(conf.tun_cidr),
            rules: ProxyRules::new(
                conf.rules
                    .iter()
                    .map(|rule| Rule::from_str(rule).unwrap())
                    .collect(),
            ),
        }
    }
}

fn check_cidr(s: String) -> String {
    let segments = s.splitn(2, '/').collect::<Vec<&str>>();
    let addr = segments[0];
    let len = segments[1];
    let _: Ipv4Addr = addr.parse().unwrap();
    let _: u16 = len.parse().unwrap();
    s
}
