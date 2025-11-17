pub mod rule;
mod server_config;
pub use server_config::{DnsServerAddr, Obfs, ServerConfig, ServerProtocol};
pub use socks5_client::Address;
pub use tcp_connection::ObfsMode;

use rule::ProxyRules;
use serde::Deserialize;
use smoltcp::wire::Ipv4Cidr;
use std::collections::HashSet;
use std::fmt::{Debug, Display};
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

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyGroup {
    pub name: String,
    pub proxies: Vec<String>,
    #[serde(default)]
    pub ping_timeout: Option<Duration>,
    #[serde(default)]
    pub ping_urls: Vec<PingURL>,
}

#[derive(Clone, Deserialize)]
pub struct Config {
    #[serde(alias = "proxies")]
    pub servers: Arc<Vec<ServerConfig>>,
    #[serde(default)]
    pub proxy_groups: Arc<Vec<ProxyGroup>>,
    #[serde(default)]
    pub remote_config_urls: Vec<String>,
    geo_ip: Option<PathBuf>,
    pub dns_start_ip: Ipv4Addr,
    pub db_path: Option<PathBuf>,
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
    // linux only, for macos, it's always 1
    #[serde(default = "default_queue_number")]
    pub queue_number: usize,
    // packets processed threads for each queue
    #[serde(default = "default_threads_per_queue")]
    pub threads_per_queue: usize,
    #[serde(with = "rules")]
    pub rules: ProxyRules,
    pub dns_listen: Option<String>,
    #[serde(default)]
    pub dns_listens: Vec<String>,
    #[serde(default)]
    pub gateway_mode: bool,
    #[serde(with = "duration", default = "default_ping_timeout")]
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
            .field("dns_listens", &self.dns_listens)
            .field("gateway_mode", &self.gateway_mode)
            .field("ping_timeout", &self.ping_timeout)
            .field("proxy_groups", &self.proxy_groups)
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

impl Display for PingURL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
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
fn default_queue_number() -> usize {
    2
}
fn default_threads_per_queue() -> usize {
    3
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
        parse_cidr(&s)
            .map_err(|_| Error::invalid_value(serde::de::Unexpected::Str(&s), &"10.0.0.1/16"))
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
        Ok(ProxyRules::new(rs, None))
    }
}

fn parse_cidr(s: &str) -> Result<Ipv4Cidr, &str> {
    let segments = s.split('/').collect::<Vec<&str>>();
    if segments.len() != 2 {
        return Err("invalid cidr: {}");
    }
    let addr = segments[0];
    let len = segments[1];
    let addr: Ipv4Addr = addr.parse().unwrap();
    let prefix = len.parse().unwrap();
    let cidr = Ipv4Cidr::new(addr, prefix);
    Ok(cidr.network())
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
        if conf.dns_listens.is_empty() {
            if let Some(dns) = &conf.dns_listen {
                conf.dns_listens.push(dns.clone());
            } else {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "dns_listens must be provided.",
                ));
            }
        }

        if let Some(db_path) = &conf.db_path {
            Store::setup_global(db_path, conf.dns_start_ip);
        } else {
            Store::setup_global("seeker.sqlite", conf.dns_start_ip);
        }

        conf.load_remote_servers();
        conf.add_proxy_servers_to_direct_rules();
        conf.rules.set_geo_ip_path(conf.geo_ip.clone());
        conf.add_default_proxy_group();
        conf.validate_proxy_groups_and_rules();
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

                    let Ok(Some(data)) = store::Store::global().get_cached_remote_config_data(&url)
                    else {
                        eprintln!("No cached config for `{url}`.");
                        continue;
                    };
                    eprintln!("Use config for `{url}` from cache instead.");
                    data
                }
            };
            let extra_servers = match parse_remote_config_data(&data) {
                Ok(extra_servers) => extra_servers,
                Err(e) => {
                    eprintln!("Parse config error for `{url}: {e}`.");
                    continue;
                }
            };
            if !extra_servers.is_empty() {
                tracing::info!(
                    "Load {} extra servers from remote config `{url}`.",
                    extra_servers.len()
                );
            }
            for server in &extra_servers {
                tracing::info!("Load extra server: {}", server.name());
            }
            servers.extend(extra_servers);
        }
    }

    fn add_default_proxy_group(&mut self) {
        // Check if rules contain PROXY and PROBE rules with no name
        let has_default_proxy = self.rules.has_empty_proxy_or_probe_rules();
        if has_default_proxy {
            let groups = Arc::make_mut(&mut self.proxy_groups);
            let servers: Vec<String> = self.servers.iter().map(|s| s.name().to_string()).collect();
            groups.push(ProxyGroup {
                name: "".to_string(),
                ping_timeout: None,
                proxies: servers,
                ping_urls: self.ping_urls.clone(),
            });
        }
    }

    fn validate_proxy_groups_and_rules(&self) {
        let mut seen_server_names = std::collections::HashSet::new();
        for server in self.servers.iter() {
            if !seen_server_names.insert(server.name()) {
                eprintln!("Duplicate server name: {}", server.name());
                tracing::error!("Duplicate server name: {}", server.name());
            }
        }
        let mut seen_proxy_group_names: HashSet<&str> = std::collections::HashSet::new();
        for group in self.proxy_groups.iter() {
            if !seen_proxy_group_names.insert(&group.name) {
                eprintln!("Duplicate proxy group name: {}", group.name);
                tracing::error!("Duplicate proxy group name: {}", group.name);
            }
        }
        // Validate all proxy names in groups reference valid servers
        for group in self.proxy_groups.iter() {
            for proxy in group.proxies.iter() {
                if !seen_server_names.contains(proxy.as_str()) {
                    eprintln!(
                        "Invalid proxy name '{}' in group '{}' - server not found",
                        proxy, group.name
                    );
                    tracing::error!(
                        "Invalid proxy name '{}' in group '{}' - server not found",
                        proxy,
                        group.name
                    );
                }
            }
        }

        let rules = self.rules.rules.read();
        // Validate all PROXY and PROBE rules reference valid proxy groups
        for rule in rules.iter() {
            if let Some(name) = rule.target_proxy_group_name() {
                if !seen_proxy_group_names.contains(&name) {
                    eprintln!(
                        "Invalid proxy group name '{name}' referenced in PROXY rule: {rule:?}"
                    );
                    tracing::error!(
                        "Invalid proxy group name '{}' referenced in PROXY rule: {:?}",
                        name,
                        rule
                    );
                }
            }
            if let Some(name) = rule.target_proxy_group_name() {
                if !seen_proxy_group_names.contains(name) {
                    eprintln!(
                        "Invalid proxy group name '{name}' referenced in PROBE rule: {rule:?}"
                    );
                    tracing::error!(
                        "Invalid proxy group name '{}' referenced in PROBE rule: {:?}",
                        name,
                        rule
                    );
                }
            }
        }
    }

    pub fn get_servers_by_name(&self, name: &str) -> Arc<Vec<ServerConfig>> {
        // find proxy group by name, and get proxy servers
        let proxy_servers: Option<Vec<_>> = self
            .proxy_groups
            .iter()
            .find(|g| g.name == name)
            .map(|g| g.proxies.iter().map(|s| s.as_str()).collect());
        // if no proxy group found, return empty servers
        if let Some(proxy_servers) = proxy_servers {
            // find servers by names
            let servers = self
                .servers
                .iter()
                .filter(|s| proxy_servers.contains(&s.name()))
                .cloned()
                .collect();
            Arc::new(servers)
        } else {
            Arc::new(vec![])
        }
    }
}

fn read_data_from_remote_config(url: &str) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let _size = ureq::get(url)
        .timeout(Duration::from_secs(5))
        .call()
        .map_err(|_| io::Error::other("read remote config"))?
        .into_reader()
        .read_to_end(&mut data)?;
    Ok(data)
}

fn parse_remote_config_data(data: &[u8]) -> io::Result<Vec<ServerConfig>> {
    let b64decoded = base64::decode_engine(data, &URL_SAFE_ENGINE)
        .map_err(|_e| io::Error::other("b64decode"))?;
    // tracing::info!("b64decoded: {:?}", b64decoded);
    let server_urls = b64decoded.split(|&c| c == b'\n');
    let ret = server_urls
        .filter_map(|url| std::str::from_utf8(url).ok())
        .map(|s| s.trim())
        .filter(|url| !url.is_empty())
        .filter_map(|url| match ServerConfig::from_str(url) {
            Ok(server) => Some(server),
            Err(e) => {
                tracing::error!("build server from url: {}, error: {:?}", url, e);
                None
            }
        })
        .collect();
    Ok(ret)
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

    #[test]
    fn test_parse_clash_proxies_format() {
        let yaml = r#"
verbose: false
dns_start_ip: 11.0.0.10
dns_servers:
  - 223.5.5.5:53
dns_timeout: 1s
tun_bypass_direct: true
redir_mode: false
queue_number: 2
threads_per_queue: 3
tun_name: utun4
tun_ip: 11.0.0.1
tun_cidr: 11.0.0.0/16
dns_listens:
  - 0.0.0.0:53
gateway_mode: false
probe_timeout: 200ms
ping_timeout: 2s
connect_timeout: 2s
read_timeout: 300s
write_timeout: 300s
max_connect_errors: 2
ping_urls:
  - host: www.google.com
    port: 80
    path: /

proxies:
  - name: "[SS] Hong Kong-20"
    type: ss
    server: fbxt0765gh0pielsss.ftisthebest.com
    port: 56020
    cipher: chacha20-ietf-poly1305
    password: e1v3fy6lnmh
    udp: true
  - name: "SOCKS5 Proxy"
    type: socks5
    server: 127.0.0.1
    port: 1080

proxy_groups:
  - name: proxy-group-1
    proxies:
      - "[SS] Hong Kong-20"
      - "SOCKS5 Proxy"

rules:
  - 'DOMAIN,google.com,PROXY(proxy-group-1)'
  - 'MATCH,DIRECT'
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.servers[0].name(), "[SS] Hong Kong-20");
        assert_eq!(config.servers[0].protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(config.servers[1].name(), "SOCKS5 Proxy");
        assert_eq!(config.servers[1].protocol(), ServerProtocol::Socks5);
    }

    #[test]
    fn test_parse_servers_with_mixed_formats() {
        // Test parsing a single servers list with both Seeker and Clash formats
        let yaml = r#"
verbose: false
dns_start_ip: 11.0.0.10
dns_servers:
  - 223.5.5.5:53
dns_timeout: 1s
tun_bypass_direct: true
redir_mode: false
queue_number: 2
threads_per_queue: 3
tun_name: utun4
tun_ip: 11.0.0.1
tun_cidr: 11.0.0.0/16
dns_listens:
  - 0.0.0.0:53
gateway_mode: false
probe_timeout: 200ms
ping_timeout: 2s
connect_timeout: 2s
read_timeout: 300s
write_timeout: 300s
max_connect_errors: 2
ping_urls:
  - host: www.google.com
    port: 80
    path: /

servers:
  - name: server-ss1
    addr: domain-to-ss-server.com:8388
    protocol: Shadowsocks
    method: chacha20-ietf
    password: password
  - name: "[SS] Hong Kong-20"
    type: ss
    server: example.com
    port: 56020
    cipher: chacha20-ietf-poly1305
    password: e1v3fy6lnmh

proxy_groups:
  - name: proxy-group-1
    proxies:
      - server-ss1
      - "[SS] Hong Kong-20"

rules:
  - 'DOMAIN,google.com,PROXY(proxy-group-1)'
  - 'MATCH,DIRECT'
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        // Both formats can be in the same list
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.servers[0].name(), "server-ss1");
        assert_eq!(config.servers[0].protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(config.servers[1].name(), "[SS] Hong Kong-20");
        assert_eq!(config.servers[1].protocol(), ServerProtocol::Shadowsocks);
    }
}
