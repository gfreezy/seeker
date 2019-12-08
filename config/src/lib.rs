pub mod rule;
mod server_config;
mod socks5;
pub use server_config::{ServerAddr, ServerConfig};
pub use socks5::Address;

use rule::ProxyRules;
use serde::Deserialize;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server_configs: Arc<Vec<ServerConfig>>,
    pub dns_start_ip: Ipv4Addr,
    pub dns_server: SocketAddr,
    pub tun_name: String,
    pub tun_ip: Ipv4Addr,
    #[serde(with = "ipv4_cidr")]
    pub tun_cidr: Ipv4Cidr,
    #[serde(with = "rules")]
    pub rules: ProxyRules,
    pub dns_listen: String,
    pub gateway_mode: bool,
    #[serde(with = "duration")]
    pub probe_timeout: Duration,
    #[serde(with = "duration")]
    pub direct_connect_timeout: Duration,
    pub direct_read_timeout: Duration,
    pub direct_write_timeout: Duration,
    pub max_connect_errors: usize,
}

mod ipv4_cidr {
    use crate::parse_cidr;
    use serde::{Deserialize, Deserializer};
    use smoltcp::wire::Ipv4Cidr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ipv4Cidr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_cidr(s))
    }
}

mod duration {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};
    use std::time::Duration;

    pub fn parse_duration(s: &str) -> Result<Duration, String> {
        let mut num = Vec::with_capacity(100);
        let mut chars = Vec::with_capacity(100);
        for c in s.chars() {
            if c.is_numeric() {
                num.push(c)
            } else {
                chars.push(c);
            }
        }
        let n: u64 = num.into_iter().collect::<String>().parse().unwrap();
        match chars.into_iter().collect::<String>().as_str() {
            "s" => Ok(Duration::from_secs(n)),
            "ms" => Ok(Duration::from_millis(n)),
            _ => Err(format!("invalid value: {}, expected 10s or 10ms", &s)),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(Error::custom)
    }
}

mod rules {
    use crate::rule::{ProxyRules, Rule};
    use serde::{Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ProxyRules, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rules: Vec<String> = Vec::deserialize(deserializer)?;
        let rs: Vec<Rule> = rules
            .into_iter()
            .map(|s| Rule::from_str(&s).unwrap())
            .collect();
        Ok(ProxyRules::new(rs))
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

impl Config {
    pub fn from_config_file(path: &str) -> Self {
        let file = File::open(&path).unwrap();
        let conf: Config = serde_yaml::from_reader(&file).unwrap();
        conf
    }
}

#[cfg(test)]
mod tests {
    use super::duration::parse_duration;
    use crate::Config;
    use std::time::Duration;

    #[test]
    fn test_deserialize() {
        let content = r#"
dns_start_ip: 10.0.0.10
dns_server: 223.5.5.5:53
tun_name: utun4
tun_ip: 10.0.0.1
tun_cidr: 10.0.0.0/16
dns_listen: 0.0.0.0:53
gateway_mode: true
probe_timeout: 10ms
direct_connect_timeout: 1s
max_connect_errors: 20
server_configs:
  - name: server1
    addr: domain-or-ip-to-ss-server:134
    method: chacha20-ietf
    password: password
    connect_timeout: 5s
    read_timeout: 30s
    write_timeout: 30s
    idle_connections: 10
  - name: server2
    addr: 192.168.2.3:234
    method: chacha20-ietf
    password: password
    connect_timeout: 5s
    read_timeout: 30s
    write_timeout: 30s
    idle_connections: 10

rules:
  - 'DOMAIN,audio-ssl.itunes.apple.com,DIRECT'
  - 'DOMAIN,gspe1-ssl.ls.apple.com,REJECT'
  - 'DOMAIN-SUFFIX,aaplimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,apple.co,DIRECT'
  - 'DOMAIN-KEYWORD,bbcfmt,PROXY'
  - 'DOMAIN-KEYWORD,uk-live,PROXY'
  - 'DOMAIN-SUFFIX,snssdk.com,DIRECT'
  - 'DOMAIN-SUFFIX,toutiao.com,PROBE'
  - 'MATCH,PROBE'
        "#;

        let conf: Config = serde_yaml::from_str(&content).unwrap();
        assert_eq!(
            format!("{:#?}", conf),
            r#"Config {
    server_configs: [
        ServerConfig {
            name: "server1",
            addr: DomainName(
                "domain-or-ip-to-ss-server",
                134,
            ),
            password: "password",
            method: ChaCha20Ietf,
            connect_timeout: 5s,
            read_timeout: 30s,
            write_timeout: 30s,
            idle_connections: 10,
        },
        ServerConfig {
            name: "server2",
            addr: SocketAddr(
                V4(
                    192.168.2.3:234,
                ),
            ),
            password: "password",
            method: ChaCha20Ietf,
            connect_timeout: 5s,
            read_timeout: 30s,
            write_timeout: 30s,
            idle_connections: 10,
        },
    ],
    dns_start_ip: 10.0.0.10,
    dns_server: V4(
        223.5.5.5:53,
    ),
    tun_name: "utun4",
    tun_ip: 10.0.0.1,
    tun_cidr: Cidr {
        address: Address(
            [
                10,
                0,
                0,
                0,
            ],
        ),
        prefix_len: 16,
    },
    rules: ProxyRules {
        rules: [
            Domain(
                "audio-ssl.itunes.apple.com",
                Direct,
            ),
            Domain(
                "gspe1-ssl.ls.apple.com",
                Reject,
            ),
            DomainSuffix(
                "aaplimg.com",
                Direct,
            ),
            DomainSuffix(
                "apple.co",
                Direct,
            ),
            DomainKeyword(
                "bbcfmt",
                Proxy,
            ),
            DomainKeyword(
                "uk-live",
                Proxy,
            ),
            DomainSuffix(
                "snssdk.com",
                Direct,
            ),
            DomainSuffix(
                "toutiao.com",
                Probe,
            ),
            Match(
                Probe,
            ),
        ],
    },
    dns_listen: "0.0.0.0:53",
    gateway_mode: true,
    probe_timeout: 10ms,
    direct_connect_timeout: 1s,
    max_connect_errors: 20,
}"#
        )
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s"), Ok(Duration::from_secs(10)));
        assert_eq!(parse_duration("8ms"), Ok(Duration::from_millis(8)));
    }
}
