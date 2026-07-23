pub mod rule;
mod server_config;
pub use server_config::{
    DnsServerAddr, Obfs, ServerConfig, ServerProtocol, VMessSecurity, VlessFlow,
};
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

const URL_SAFE_ENGINE: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyGroupType {
    Select,
    #[default]
    UrlTest,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyGroup {
    pub name: String,
    #[serde(rename = "type", default)]
    pub group_type: ProxyGroupType,
    #[serde(default)]
    pub default_selected: Option<String>,
    pub proxies: Vec<String>,
    #[serde(with = "duration_opt", default)]
    pub ping_timeout: Option<Duration>,
    #[serde(default)]
    pub ping_urls: Vec<PingURL>,
}

#[derive(Clone, Deserialize)]
pub struct Config {
    #[serde(alias = "proxies")]
    #[serde(default)]
    pub servers: Arc<Vec<ServerConfig>>,
    #[serde(skip)]
    local_servers: Arc<Vec<ServerConfig>>,
    #[serde(default)]
    pub proxy_groups: Arc<Vec<ProxyGroup>>,
    #[serde(default)]
    pub remote_config_urls: Vec<String>,
    #[serde(with = "duration_opt", default)]
    pub remote_config_refresh_interval: Option<Duration>,
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
    #[serde(with = "duration", default = "default_idle_timeout")]
    pub idle_timeout: Duration,
    pub max_connect_errors: usize,
    #[serde(default)]
    pub api_addr: Option<String>,
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
            .field("idle_timeout", &self.idle_timeout)
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
    Duration::from_secs(10)
}
fn default_write_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_idle_timeout() -> Duration {
    Duration::from_secs(300)
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

mod duration_opt {
    use super::duration::parse_duration;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};
    use std::time::Duration;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        let Some(s) = s else { return Ok(None) };
        parse_duration(&s)
            .map(Some)
            .map_err(|_| Error::invalid_value(serde::de::Unexpected::Str(&s), &"10s or 10ms"))
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
            "m" => Ok(Duration::from_secs(n * 60)),
            "h" => Ok(Duration::from_secs(n * 3600)),
            _ => Err(format!(
                "invalid value: {}, expected 10s, 10ms, 5m or 1h",
                &s
            )),
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
        if conf.servers.is_empty() && conf.remote_config_urls.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "either `servers` or `remote_config_urls` must be provided.",
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

        conf.local_servers = conf.servers.clone();
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
            let Some(extra_servers) = fetch_remote_servers_with_cache_fallback(&url) else {
                continue;
            };
            servers.extend(extra_servers);
        }
    }

    /// Re-fetch all `remote_config_urls` and return a new merged server list
    /// (local servers + freshly-fetched remote servers).
    ///
    /// Returns `None` if any URL fails — caller should keep the existing in-memory
    /// list and retry on the next tick. Does not consult the SQLite cache, since
    /// the in-memory list is already a known-good fallback.
    pub fn refresh_remote_servers(&self) -> Option<Vec<ServerConfig>> {
        let mut merged: Vec<ServerConfig> = (*self.local_servers).clone();
        for url in &self.remote_config_urls {
            let extra_servers = fetch_remote_servers_no_fallback(url)?;
            merged.extend(extra_servers);
        }
        Some(merged)
    }

    fn add_default_proxy_group(&mut self) {
        // Check if rules contain PROXY and PROBE rules with no name
        let has_default_proxy = self.rules.has_empty_proxy_or_probe_rules();
        let has_configured_default = self.proxy_groups.iter().any(|group| group.name.is_empty());
        if has_default_proxy && !has_configured_default {
            let groups = Arc::make_mut(&mut self.proxy_groups);
            let servers: Vec<String> = self.servers.iter().map(|s| s.name().to_string()).collect();
            groups.push(ProxyGroup {
                name: "".to_string(),
                group_type: ProxyGroupType::UrlTest,
                default_selected: None,
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
            // An anonymous default group always tracks every loaded server. Its
            // serialized proxies list is informational and may be stale after a
            // remote subscription refresh, so only named groups validate it.
            if !group.name.is_empty() {
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
            if let Some(default_selected) = group.default_selected.as_deref() {
                if group.group_type != ProxyGroupType::Select {
                    tracing::warn!(
                        group = group.name,
                        "Ignoring default_selected on a non-select proxy group"
                    );
                } else if if group.name.is_empty() {
                    !seen_server_names.contains(default_selected)
                } else {
                    !group.proxies.iter().any(|proxy| proxy == default_selected)
                } {
                    tracing::warn!(
                        group = group.name,
                        default_selected,
                        "default_selected is not a member of the proxy group; using the first proxy"
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
        // Find the proxy group by name. The anonymous default group always
        // tracks all loaded servers, whether it was injected or persisted in
        // the configuration.
        let Some(group) = self.proxy_groups.iter().find(|group| group.name == name) else {
            return Arc::new(vec![]);
        };
        if group.name.is_empty() {
            return self.servers.clone();
        }

        {
            // Resolve in proxy-group order. For a select group this ensures the
            // first proxy is also the default when default_selected is absent.
            let servers = group
                .proxies
                .iter()
                .filter_map(|proxy_name| {
                    self.servers
                        .iter()
                        .find(|server| server.name() == proxy_name)
                        .cloned()
                })
                .collect();
            Arc::new(servers)
        }
    }
}

fn filter_dominated_servers(servers: Vec<ServerConfig>) -> Vec<ServerConfig> {
    servers
        .into_iter()
        .filter(|s| {
            let dominated = s.addr().to_string() == "8.8.8.8:12345";
            if dominated {
                tracing::info!("Skip server: {} ({})", s.name(), s.addr());
            }
            !dominated
        })
        .collect()
}

fn fetch_and_parse_remote(url: &str) -> io::Result<Vec<ServerConfig>> {
    let data = read_data_from_remote_config(url)?;
    if let Err(e) = store::Store::global().cache_remote_config_data(url, &data) {
        eprintln!("Cache remote config `{url}` error: {e}");
    }
    let parsed = parse_remote_config_data(&data)?;
    Ok(filter_dominated_servers(parsed))
}

fn fetch_remote_servers_with_cache_fallback(url: &str) -> Option<Vec<ServerConfig>> {
    let servers = match fetch_and_parse_remote(url) {
        Ok(servers) => servers,
        Err(e) => {
            eprintln!("Load servers from remote config `{url}` error: {e}");
            let Ok(Some(data)) = store::Store::global().get_cached_remote_config_data(url) else {
                eprintln!("No cached config for `{url}`.");
                return None;
            };
            eprintln!("Use config for `{url}` from cache instead.");
            match parse_remote_config_data(&data) {
                Ok(parsed) => filter_dominated_servers(parsed),
                Err(e) => {
                    eprintln!("Parse cached config error for `{url}: {e}`.");
                    return None;
                }
            }
        }
    };
    if !servers.is_empty() {
        tracing::info!(
            "Load {} extra servers from remote config `{url}`.",
            servers.len()
        );
    }
    for server in &servers {
        tracing::info!("Load extra server: {}", server.name());
    }
    Some(servers)
}

fn fetch_remote_servers_no_fallback(url: &str) -> Option<Vec<ServerConfig>> {
    match fetch_and_parse_remote(url) {
        Ok(servers) => Some(servers),
        Err(e) => {
            tracing::warn!("Refresh remote config `{url}` failed: {e}");
            None
        }
    }
}

fn read_data_from_remote_config(url: &str) -> io::Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .into();
    let mut data = Vec::new();
    let _size = agent
        .get(url)
        .header(
            "User-Agent",
            "Shadowrocket/1980 CFNetwork/1496.0.7 Darwin/23.5.0",
        )
        .call()
        .map_err(|_| io::Error::other("read remote config"))?
        .into_body()
        .into_reader()
        .read_to_end(&mut data)?;
    Ok(data)
}

#[derive(Deserialize)]
struct RemoteProxiesConfig {
    proxies: Vec<ServerConfig>,
}

fn parse_remote_config_data(data: &[u8]) -> io::Result<Vec<ServerConfig>> {
    if let Ok(parsed) = serde_yaml::from_slice::<RemoteProxiesConfig>(data) {
        return Ok(parsed.proxies);
    }

    use base64::Engine;
    let b64decoded = URL_SAFE_ENGINE
        .decode(data)
        .map_err(|_e| io::Error::other("b64decode"))?;
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

    fn test_server(name: &str, port: u16) -> ServerConfig {
        ServerConfig::new(
            name.to_string(),
            format!("127.0.0.1:{port}").parse().unwrap(),
            ServerProtocol::Http,
            None,
            None,
            None,
            None,
        )
    }

    fn test_config(proxy_groups: Vec<ProxyGroup>, rules: Vec<Rule>) -> Config {
        let servers = Arc::new(vec![
            test_server("first", 1080),
            test_server("second", 1081),
        ]);
        Config {
            servers: servers.clone(),
            local_servers: servers,
            proxy_groups: Arc::new(proxy_groups),
            remote_config_urls: vec![],
            remote_config_refresh_interval: None,
            geo_ip: None,
            dns_start_ip: "11.0.0.10".parse().unwrap(),
            db_path: None,
            dns_servers: vec![],
            redir_mode: false,
            tun_bypass_direct: true,
            tun_name: "utun4".to_string(),
            tun_ip: "11.0.0.1".parse().unwrap(),
            verbose: false,
            tun_cidr: Ipv4Cidr::new("11.0.0.0".parse().unwrap(), 16),
            queue_number: 1,
            threads_per_queue: 1,
            rules: ProxyRules::new(rules, None),
            dns_listen: None,
            dns_listens: vec!["127.0.0.1:5353".to_string()],
            gateway_mode: false,
            ping_timeout: Duration::from_secs(1),
            ping_urls: vec![],
            dns_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            write_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            max_connect_errors: 1,
            api_addr: None,
        }
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s"), Ok(Duration::from_secs(10)));
        assert_eq!(parse_duration("8ms"), Ok(Duration::from_millis(8)));
    }

    #[test]
    fn test_parse_refresh_interval_units() {
        use std::time::Duration;
        #[derive(Deserialize)]
        struct T {
            #[serde(with = "duration_opt", default)]
            interval: Option<Duration>,
        }
        let parse =
            |s: &str| -> Option<Duration> { serde_yaml::from_str::<T>(s).unwrap().interval };
        assert_eq!(parse("interval: 30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse("interval: 5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse("interval: 1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse("interval: 250ms"), Some(Duration::from_millis(250)));
        assert_eq!(parse("interval: ~"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn test_parse_proxy_group_types_and_default_selected() {
        let yaml = r#"
- name: manual
  type: select
  default_selected: server-2
  proxies: [server-1, server-2]
- name: auto
  type: url_test
  proxies: [server-1, server-2]
  ping_timeout: 2s
- name: legacy-auto
  proxies: [server-1]
"#;
        let groups: Vec<ProxyGroup> = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(groups[0].group_type, ProxyGroupType::Select);
        assert_eq!(groups[0].default_selected.as_deref(), Some("server-2"));
        assert_eq!(groups[1].group_type, ProxyGroupType::UrlTest);
        assert_eq!(groups[1].ping_timeout, Some(Duration::from_secs(2)));
        assert_eq!(groups[2].group_type, ProxyGroupType::UrlTest);
        assert!(groups[2].default_selected.is_none());
    }

    #[test]
    fn test_reject_unknown_proxy_group_type() {
        let yaml = r#"
name: unsupported
type: fallback
proxies: [server-1]
"#;
        assert!(serde_yaml::from_str::<ProxyGroup>(yaml).is_err());
    }

    #[test]
    fn test_adds_automatic_implicit_default_group() {
        let mut config = test_config(
            vec![],
            vec![Rule::Match(rule::Action::Proxy(String::new()))],
        );

        config.add_default_proxy_group();

        assert_eq!(config.proxy_groups.len(), 1);
        let group = &config.proxy_groups[0];
        assert!(group.name.is_empty());
        assert_eq!(group.group_type, ProxyGroupType::UrlTest);
        assert_eq!(group.proxies, vec!["first", "second"]);
    }

    #[test]
    fn test_persisted_default_group_is_not_duplicated_and_tracks_all_servers() {
        let persisted_default = ProxyGroup {
            name: String::new(),
            group_type: ProxyGroupType::Select,
            default_selected: Some("second".to_string()),
            proxies: vec!["stale-entry".to_string()],
            ping_timeout: None,
            ping_urls: vec![],
        };
        let mut config = test_config(
            vec![persisted_default],
            vec![Rule::Match(rule::Action::Proxy(String::new()))],
        );

        config.add_default_proxy_group();

        assert_eq!(config.proxy_groups.len(), 1);
        assert_eq!(config.proxy_groups[0].group_type, ProxyGroupType::Select);
        assert_eq!(
            config.proxy_groups[0].default_selected.as_deref(),
            Some("second")
        );
        assert_eq!(
            config
                .get_servers_by_name("")
                .iter()
                .map(|server| server.name())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );

        Arc::make_mut(&mut config.servers).push(test_server("remote", 1082));
        assert_eq!(
            config
                .get_servers_by_name("")
                .iter()
                .map(|server| server.name())
                .collect::<Vec<_>>(),
            vec!["first", "second", "remote"]
        );
    }

    #[test]
    fn test_parse_remote_yaml_proxies() -> std::io::Result<()> {
        let data = br#"
proxies:
  - name: "HK-SS"
    type: ss
    server: example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: pw
  - name: "SOCKS5"
    type: socks5
    server: 127.0.0.1
    port: 1080
"#;
        let servers = parse_remote_config_data(data)?;
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name(), "HK-SS");
        assert_eq!(servers[0].protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(servers[1].name(), "SOCKS5");
        assert_eq!(servers[1].protocol(), ServerProtocol::Socks5);
        Ok(())
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
  - host: www.baidu.com
    port: 80
    path: /

proxies:
  - name: "[SS] Hong Kong-20"
    type: ss
    server: proxy.example.org
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
    type: select
    default_selected: "[SS] Hong Kong-20"
    proxies:
      - "SOCKS5 Proxy"
      - "[SS] Hong Kong-20"

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
        let group = &config.proxy_groups[0];
        assert_eq!(group.group_type, ProxyGroupType::Select);
        assert_eq!(group.default_selected.as_deref(), Some("[SS] Hong Kong-20"));
        let group_servers = config.get_servers_by_name("proxy-group-1");
        assert_eq!(group_servers[0].name(), "SOCKS5 Proxy");
        assert_eq!(group_servers[1].name(), "[SS] Hong Kong-20");
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
  - host: www.baidu.com
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
