pub mod rule;
mod server_config;
pub use server_config::{DnsServerAddr, ServerConfig, ServerProtocol};
pub use socks5_client::Address;

use rule::ProxyRules;
use serde::Deserialize;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use std::fs::File;
use std::io;
use std::io::{ErrorKind, Read};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub servers: Arc<Vec<ServerConfig>>,
    #[serde(default)]
    pub remote_config_urls: Vec<String>,
    pub dns_start_ip: Ipv4Addr,
    pub dns_servers: Vec<DnsServerAddr>,
    pub tun_bypass_direct: bool,
    pub tun_name: String,
    pub tun_ip: Ipv4Addr,
    #[serde(default)]
    pub verbose: bool,
    #[serde(with = "ipv4_cidr")]
    pub tun_cidr: Ipv4Cidr,
    #[serde(with = "rules")]
    pub rules: ProxyRules,
    pub dns_listen: String,
    #[serde(default)]
    pub gateway_mode: bool,
    #[serde(with = "duration", default = "default_connect_timeout")]
    pub ping_timeout: Duration,
    pub ping_urls: Vec<PingURL>,
    #[serde(with = "duration", default = "default_connect_timeout")]
    pub dns_timeout: Duration,
    #[serde(with = "duration", default = "default_ping_timeout")]
    pub probe_timeout: Duration,
    #[serde(with = "duration", default = "default_connect_timeout")]
    pub connect_timeout: Duration,
    #[serde(with = "duration", default = "default_read_timeout")]
    pub read_timeout: Duration,
    #[serde(with = "duration", default = "default_write_timeout")]
    pub write_timeout: Duration,
    pub max_connect_errors: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PingURL {
    host: String,
    port: u16,
    path: String,
}

impl PingURL {
    pub fn new(host: String, port: u16, path: String) -> Self {
        Self { host, port, path }
    }

    pub fn address(&self) -> Address {
        Address::DomainNameAddress(self.host.clone(), self.port)
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

fn default_read_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_write_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_connect_timeout() -> Duration {
    Duration::from_millis(100)
}
fn default_ping_timeout() -> Duration {
    Duration::from_secs(3)
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
    pub fn from_config_file(path: &str) -> io::Result<Self> {
        let file = File::open(path).unwrap();
        Config::from_reader(file)
    }

    pub fn from_reader<R: Read>(reader: R) -> io::Result<Self> {
        let conf: Config = serde_yaml::from_reader(reader).expect("serde yaml deserialize error");
        if conf.servers.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "servers can not be empty.",
            ));
        };
        Ok(conf)
    }
}

#[cfg(test)]
mod tests {
    use super::duration::parse_duration;
    use std::time::Duration;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s"), Ok(Duration::from_secs(10)));
        assert_eq!(parse_duration("8ms"), Ok(Duration::from_millis(8)));
    }
}
