pub mod rule;
mod server_config;
pub use server_config::{DnsServerAddr, ServerConfig, ServerProtocol};
pub use socks5_client::Address;

use rule::ProxyRules;
use serde::Deserialize;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::io::{ErrorKind, Read};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use store::Store;

use crate::rule::Rule;

const URL_SAFE_ENGINE: base64::engine::fast_portable::FastPortable =
    base64::engine::fast_portable::FastPortable::from(
        &base64::alphabet::STANDARD,
        base64::engine::fast_portable::FastPortableConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

#[derive(Clone, Deserialize)]
pub struct Config {
    pub servers: Arc<Vec<ServerConfig>>,
    #[serde(default)]
    pub remote_config_urls: Vec<String>,
    geo_ip: Option<PathBuf>,
    pub dns_start_ip: Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<DnsServerAddr>,
    #[serde(default)]
    pub redir_mode: bool,
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

impl Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("servers", &self.servers)
            .field("remote_config_urls", &self.remote_config_urls)
            .field("geo_ip", &self.geo_ip)
            .field("dns_start_ip", &self.dns_start_ip)
            .field("dns_servers", &self.dns_servers)
            .field("tun_bypass_direct", &self.tun_bypass_direct)
            .field("tun_name", &self.tun_name)
            .field("tun_ip", &self.tun_ip)
            .field("verbose", &self.verbose)
            .field("tun_cidr", &self.tun_cidr)
            .field("rules", &self.rules)
            .field("dns_listen", &self.dns_listen)
            .field("gateway_mode", &self.gateway_mode)
            .field("ping_timeout", &self.ping_timeout)
            .field("ping_urls", &self.ping_urls)
            .field("dns_timeout", &self.dns_timeout)
            .field("probe_timeout", &self.probe_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("max_connect_errors", &self.max_connect_errors)
            .finish()
    }
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

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn port(&self) -> u16 {
        self.port
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
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};
    use smoltcp::wire::Ipv4Cidr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ipv4Cidr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_cidr(s.clone())
            .map_err(|_| Error::invalid_value(serde::de::Unexpected::Str(&s), &"10.0.0.1/16"))?)
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
        parse_duration(&s)
            .map_err(|_| Error::invalid_value(serde::de::Unexpected::Str(&s), &"10s or 10ms"))
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

fn parse_cidr(s: String) -> Result<Ipv4Cidr, String> {
    let segments = s.split('/').collect::<Vec<&str>>();
    if segments.len() != 2 {
        return Err("invalid cidr: {}".to_string());
    }
    let addr = segments[0];
    let len = segments[1];
    let addr: Ipv4Addr = addr.parse().unwrap();
    let prefix = len.parse().unwrap();
    Ok(Ipv4Cidr::new(Ipv4Address::from(addr), prefix))
}

impl Config {
    pub fn from_config_file(path: &str) -> io::Result<Self> {
        let file = File::open(path)?;
        Config::from_reader(file)
    }

    pub fn from_reader<R: Read>(reader: R) -> io::Result<Self> {
        let mut conf: Config =
            serde_yaml::from_reader(reader).expect("serde yaml deserialize error");
        if conf.servers.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "servers can not be empty.",
            ));
        };

        Store::setup_global("seeker.sqlite", conf.dns_start_ip);

        conf.load_remote_servers();
        conf.add_proxy_servers_to_direct_rules();
        conf.rules.set_geo_ip_path(conf.geo_ip.clone());
        Ok(conf)
    }

    fn add_proxy_servers_to_direct_rules(&mut self) {
        let mut rules = vec![];
        for server in self.servers.iter() {
            let rule = match server.addr() {
                Address::SocketAddress(addr) => {
                    let Ok(cidr) = Ipv4Cidr::from_str(&format!("{}/32", addr.ip())) else {
                        tracing::error!("invalid cidr: {}", addr);
                        continue;
                    };
                    Rule::IpCidr(cidr, rule::Action::Direct)
                }
                Address::DomainNameAddress(domain, _) => {
                    Rule::Domain(domain.to_string(), rule::Action::Direct)
                }
            };
            rules.push(rule);
        }
        self.rules.prepend_rules(rules);
    }

    fn load_remote_servers(&mut self) {
        let remote_config = self.remote_config_urls.clone();
        let servers = Arc::make_mut(&mut self.servers);
        for url in remote_config {
            let data = match read_data_from_remote_config(&url) {
                Ok(servers) => {
                    if let Err(e) = store::Store::global().cache_remote_config_data(&url, &servers)
                    {
                        eprintln!("Cache remote config `{url}` error: {e}");
                    }
                    servers
                }
                Err(e) => {
                    eprintln!("Load servers from remote config `{url}` error: {e}");

                    let Ok(Some(data)) = store::Store::global().get_cached_remote_config_data(&url) else {
                        eprintln!("No cached config for `{url}`.");
                        continue;
                    };
                    eprintln!("Use config for `{url}` from cache instead.");
                    data
                }
            };
            let Ok(extra_servers) = parse_remote_config_data(&data) else {
                eprintln!("Parse config error for `{url}`.");
                continue;
            };
            servers.extend(extra_servers);
        }
    }
}

fn read_data_from_remote_config(url: &str) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let _size = ureq::get(url)
        .timeout(Duration::from_secs(5))
        .call()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "read remote config"))?
        .into_reader()
        .read_to_end(&mut data)?;
    Ok(data)
}

fn parse_remote_config_data(data: &[u8]) -> io::Result<Vec<ServerConfig>> {
    let b64decoded = base64::decode_engine(data, &URL_SAFE_ENGINE)
        .map_err(|_e| io::Error::new(io::ErrorKind::Other, "b64decode"))?;
    tracing::info!("b64decoded: {:?}", b64decoded);
    let server_urls = b64decoded.split(|&c| c == b'\n');
    let ret: Result<_, _> = server_urls
        .filter_map(|url| std::str::from_utf8(url).ok())
        .map(|s| s.trim())
        .filter(|url| !url.is_empty())
        .map(ServerConfig::from_str)
        .collect();
    ret.map_err(|_e| io::Error::new(io::ErrorKind::Other, "build server from url"))
}

#[cfg(test)]
mod tests {
    use super::duration::parse_duration;
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s"), Ok(Duration::from_secs(10)));
        assert_eq!(parse_duration("8ms"), Ok(Duration::from_millis(8)));
    }

    #[test]
    fn test_parse_remote_server() -> std::io::Result<()> {
        let data = b"c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAwMi8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDEKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAwMy8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDIKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAxMi8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDMKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAxMy8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDQKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAzMi8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNSU4RiVCMCVFNiVCOSVCRS1ISU5FVCswMQpzczovL1lXVnpMVEkxTmkxblkyMDZNVEV4QHRlc3Quc3MuY29tOjMwMDMzLz9wbHVnaW49b2Jmcy1sb2NhbCUzQm9iZnMlM0RodHRwJTNCb2Jmcy1ob3N0JTNEd3d3Lm1pY3Jvc29mdC5jb20jJUU1JThGJUIwJUU2JUI5JUJFLUhJTkVUKzAyCnNzOi8vWVdWekxUSTFOaTFuWTIwNk1URXhAdGVzdC5zcy5jb206MzAwNDIvP3BsdWdpbj1vYmZzLWxvY2FsJTNCb2JmcyUzRGh0dHAlM0JvYmZzLWhvc3QlM0R3d3cubWljcm9zb2Z0LmNvbSMlRTYlOTYlQjAlRTUlOEElQTAlRTUlOUQlQTEtRFArMDEKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDA0My8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNiU5NiVCMCVFNSU4QSVBMCVFNSU5RCVBMS1EUCswMgpzczovL1lXVnpMVEkxTmkxblkyMDZNVEV4QHRlc3Quc3MuY29tOjMwMDUyLz9wbHVnaW49b2Jmcy1sb2NhbCUzQm9iZnMlM0RodHRwJTNCb2Jmcy1ob3N0JTNEd3d3Lm1pY3Jvc29mdC5jb20jJUU2JTk3JUE1JUU2JTlDJUFDLUhBTE8rMDEKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDA1My8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNiU5NyVBNSVFNiU5QyVBQy1EUCswMgpzczovL1lXVnpMVEkxTmkxblkyMDZNVEV4QHRlc3Quc3MuY29tOjMwMDY1Lz9wbHVnaW49b2Jmcy1sb2NhbCUzQm9iZnMlM0RodHRwJTNCb2Jmcy1ob3N0JTNEd3d3Lm1pY3Jvc29mdC5jb20jJUU3JUJFJThFJUU1JTlCJUJELUhBTE8rMDIKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDA2Ni8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNyVCRSU4RSVFNSU5QiVCRC1IQUxPKzAzCnNzOi8vWVdWekxUSTFOaTFuWTIwNk1URXhAdGVzdC5zcy5jb206MzAwNjcvP3BsdWdpbj1vYmZzLWxvY2FsJTNCb2JmcyUzRGh0dHAlM0JvYmZzLWhvc3QlM0R3d3cubWljcm9zb2Z0LmNvbSMlRTclQkUlOEUlRTUlOUIlQkQtSEFMTyswNAo=";
        let servers = parse_remote_config_data(data)?;
        assert_eq!(servers.len(), 13);
        Ok(())
    }
}
