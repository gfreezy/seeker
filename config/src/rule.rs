use crate::parse_cidr;
use maxminddb::geoip2::Country;
use parking_lot::{Mutex, RwLock};
use smoltcp::wire::Ipv4Cidr;
use std::fmt::{self, Formatter};
use std::fs::File;
use std::io::{copy, BufWriter};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Once};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Rule {
    Domain(String, Action),
    DomainSuffix(String, Action),
    DomainKeyword(String, Action),
    IpCidr(Ipv4Cidr, Action),
    GeoIp(String, Action),
    Match(Action),
}

impl Rule {
    pub fn target_proxy_group_name(&self) -> Option<&str> {
        match self {
            Rule::Match(action) => action.target_proxy_group_name(),
            Rule::Domain(_, action) => action.target_proxy_group_name(),
            Rule::DomainSuffix(_, action) => action.target_proxy_group_name(),
            Rule::DomainKeyword(_, action) => action.target_proxy_group_name(),
            Rule::IpCidr(_, action) => action.target_proxy_group_name(),
            Rule::GeoIp(_, action) => action.target_proxy_group_name(),
        }
    }

    /// Check if the rule has a target proxy group and it's empty.
    pub fn has_empty_target_proxy_group(&self) -> bool {
        self.target_proxy_group_name()
            .is_some_and(|name| name.is_empty())
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Hash, PartialOrd, Ord, Default)]
pub enum Action {
    #[default]
    Reject,
    Direct,
    Proxy(String),
    Probe(String),
}

impl Action {
    /// Get the target proxy group name if the action is proxy or probe.
    pub fn target_proxy_group_name(&self) -> Option<&str> {
        match self {
            Action::Proxy(name) => Some(name),
            Action::Probe(name) => Some(name),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyRules {
    pub(crate) rules: Arc<RwLock<Vec<Rule>>>,
    geo_ip_path: Option<PathBuf>,
    default_download_path: PathBuf,
    geo_ip_db: Arc<Mutex<Option<maxminddb::Reader<Vec<u8>>>>>,
}

impl ProxyRules {
    pub fn new(rules: Vec<Rule>, geo_ip_path: Option<PathBuf>) -> Self {
        let s = Self {
            rules: Arc::new(RwLock::new(rules)),
            geo_ip_db: Arc::new(Mutex::new(None)),
            geo_ip_path: geo_ip_path.clone(),
            default_download_path: default_geo_ip_path(),
        };
        if geo_ip_path.is_some() {
            s.init_geo_ip_db(false);
        }
        s
    }

    /// Create a new ProxyRules with the given rules and geoip database path.
    /// Download the geoip database in the foreground if the path is a http or https url.
    #[cfg(test)]
    fn new_sync(rules: Vec<Rule>, geo_ip_path: Option<PathBuf>, download_path: PathBuf) -> Self {
        let s = Self {
            rules: Arc::new(RwLock::new(rules)),
            geo_ip_db: Arc::new(Mutex::new(None)),
            geo_ip_path,
            default_download_path: download_path,
        };
        s.init_geo_ip_db(true);
        s
    }

    pub fn take_rules(&self) -> Vec<Rule> {
        std::mem::take(&mut *self.rules.write())
    }

    pub fn replace_rules(&self, rules: Vec<Rule>) {
        let mut rules_mut = self.rules.write();
        *rules_mut = rules;
    }

    fn download_geoip_database(&self) -> bool {
        let Some(url) = self
            .geo_ip_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
        else {
            return false;
        };
        let path = &self.default_download_path;
        let success = download_geoip_database(&url, path);
        if !success {
            tracing::error!("downloaded geoip failed");
        } else {
            tracing::info!("downloaded geoip database to {:?}", path);
        }
        success
    }

    fn init_geo_ip_db(&self, force_download: bool) {
        let default_path = self.default_download_path.clone();
        let path = match &self.geo_ip_path {
            Some(path) => {
                tracing::info!("geoip path: {:?}", path);
                // Check if path is a valid http or https url
                if path.starts_with("http://") || path.starts_with("https://") {
                    if force_download {
                        let _ = self.download_geoip_database();
                    } else if !default_path.exists() {
                        static ONCE: std::sync::Once = Once::new();
                        ONCE.call_once(|| {
                            let _ = self.download_geoip_database();
                        });
                    }
                    default_path
                } else {
                    path.clone()
                }
            }
            None => {
                tracing::info!("geoip path not set, using default path");
                default_path
            }
        };

        tracing::info!("use geoip at: {:?}", path);
        let reader = match maxminddb::Reader::open_readfile(&path) {
            Ok(reader) => reader,
            Err(err) => {
                tracing::error!("failed to open geoip database: {}, path: {:?}", err, path);
                return;
            }
        };
        let mut guard = self.geo_ip_db.lock();
        *guard = Some(reader);
    }

    fn did_geo_ip_matches_name(&self, ip: IpAddr, name: &str) -> bool {
        let geo_ip_db = self.geo_ip_db.lock();
        let Some(reader) = &*geo_ip_db else {
            return false;
        };
        did_geo_ip_matches_name(reader, ip, name)
    }

    pub fn action_for_domain(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Option<Action> {
        let ip = ip.and_then(|ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        });
        let rules = self.rules.read();

        let matched_rule = rules.iter().find(|rule| match (rule, domain, ip) {
            (Rule::Domain(d, _), Some(domain), _) if d == domain => true,
            (Rule::DomainSuffix(d, _), Some(domain), _) if domain.ends_with(d) => true,
            (Rule::DomainKeyword(d, _), Some(domain), _) if domain.contains(d) => true,
            (Rule::IpCidr(cidr, _), _, Some(ip)) if cidr.contains_addr(&ip) => true,
            (Rule::GeoIp(name, _), _, Some(ip))
                if self.did_geo_ip_matches_name(ip.into(), name) =>
            {
                true
            }
            (Rule::Match(_), _, _) => true,
            _ => false,
        });
        tracing::info!("matched rule: {:?}, {:?}, {:?}", matched_rule, domain, ip);
        matched_rule.map(|rule| match rule {
            Rule::Match(action) => action.clone(),
            Rule::Domain(_, action) => action.clone(),
            Rule::DomainSuffix(_, action) => action.clone(),
            Rule::DomainKeyword(_, action) => action.clone(),
            Rule::IpCidr(_, action) => action.clone(),
            Rule::GeoIp(_, action) => action.clone(),
        })
    }

    pub fn prepend_rules(&self, rules: Vec<Rule>) {
        let mut rules_mut = self.rules.write();
        for rule in rules {
            rules_mut.insert(0, rule);
        }
    }

    pub fn default_action(&self) -> Action {
        Action::Direct
    }

    pub fn additional_cidrs(&self) -> Vec<Ipv4Cidr> {
        let rules = self.rules.read();
        rules
            .iter()
            .filter_map(|rule| match rule {
                Rule::IpCidr(cidr, Action::Probe(_) | Action::Proxy(_)) => Some(*cidr),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn set_geo_ip_path(&mut self, path: Option<PathBuf>) {
        self.geo_ip_path = path;
        self.init_geo_ip_db(false);
    }

    /// Check if the rules contain proxy or probe rules with empty target proxy group.
    pub fn has_empty_proxy_or_probe_rules(&self) -> bool {
        let rules = self.rules.read();
        rules.iter().any(|rule| rule.has_empty_target_proxy_group())
    }
}

impl FromStr for Action {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "REJECT" {
            Action::Reject
        } else if s == "DIRECT" {
            Action::Direct
        } else if s == "PROXY" {
            Action::Proxy(String::new())
        } else if s == "PROBE" {
            Action::Probe(String::new())
        } else if let Some(proxy) = s.strip_prefix("PROXY(").and_then(|s| s.strip_suffix(")")) {
            Action::Proxy(proxy.to_string())
        } else if let Some(probe) = s.strip_prefix("PROBE(").and_then(|s| s.strip_suffix(")")) {
            Action::Probe(probe.to_string())
        } else {
            panic!("Invalid action: {s}")
        })
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for Rule {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let segments = s.splitn(3, ',').collect::<Vec<_>>();
        let (rule, criteria, action) = match segments.len() {
            2 => (segments[0], "", segments[1]),
            3 => (segments[0], segments[1], segments[2]),
            _ => unreachable!("{}", s),
        };

        Ok(match rule {
            "DOMAIN" => Rule::Domain(criteria.to_string(), Action::from_str(action).unwrap()),
            "DOMAIN-SUFFIX" => {
                Rule::DomainSuffix(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "DOMAIN-KEYWORD" => {
                Rule::DomainKeyword(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "IP-CIDR" => Rule::IpCidr(parse_cidr(criteria)?, Action::from_str(action).unwrap()),
            "GEOIP" => Rule::GeoIp(criteria.to_string(), Action::from_str(action).unwrap()),
            "MATCH" => Rule::Match(Action::from_str(action).unwrap()),
            _ => unreachable!(),
        })
    }
}

fn did_geo_ip_matches_name(reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr, name: &str) -> bool {
    let Ok(country) = reader.lookup::<Country>(ip) else {
        return false;
    };
    country
        .country
        .and_then(|c| c.iso_code)
        .is_some_and(|code| code == name)
}

fn default_geo_ip_path() -> PathBuf {
    let current_exe_path = std::env::current_exe().expect("failed to get current exe path");
    current_exe_path
        .parent()
        .expect("failed to get parent dir")
        .join("geoip.mmdb")
}

fn download_geoip_database(url: &str, path: &Path) -> bool {
    tracing::info!("downloading geoip database from: {:?}, to: {:?}", url, path);
    let r = ureq::get(url).call();

    let response = match r {
        Err(e) => {
            tracing::error!("failed to download geoip database: {:?}, err: {:?}", url, e);
            return false;
        }
        Ok(r) => r,
    };

    // Create a file to save the downloaded database.
    let mut file = match File::create(path) {
        Ok(file) => file,
        Err(err) => {
            tracing::error!(
                "failed to create file for geoip database: {}, path: {:?}",
                err,
                path
            );
            return false;
        }
    };

    // Write the response body to the file.
    let mut writer = BufWriter::new(&mut file);
    if copy(&mut response.into_reader(), &mut writer).is_err() {
        tracing::error!("failed to write to geoip.mmdb file: {:?}", url);
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_geo_ip_matches_name() {
        let path = std::env::temp_dir().join("geoip_download_test.mmdb");
        // remove the file if it exists
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        download_geoip_database(
            "https://pub-a2ec2e74bf2c47428e190f227ec084ef.r2.dev/Country.mmdb",
            &path,
        );
        assert!(path.exists(), "geoip database not found: {path:?}");
        let reader =
            maxminddb::Reader::open_readfile(&path).expect("failed to open geoip database");
        assert!(did_geo_ip_matches_name(
            &reader,
            "110.242.68.66".parse().unwrap(),
            "CN"
        ));
    }

    #[test]
    fn test_proxy_rule() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let temp_path = std::env::temp_dir().join("geoip_proxy_rule_test.mmdb");
        if temp_path.exists() {
            std::fs::remove_file(&temp_path).unwrap();
        }
        let proxy_rule = ProxyRules::new_sync(
            vec![Rule::GeoIp("CN".to_string(), Action::Direct)],
            Some(
                Path::new("https://pub-a2ec2e74bf2c47428e190f227ec084ef.r2.dev/Country.mmdb")
                    .to_path_buf(),
            ),
            temp_path,
        );
        let action = proxy_rule.action_for_domain(Some("x.com"), "110.242.68.66".parse().ok());
        assert_eq!(action, Some(Action::Direct));
    }

    #[test]
    fn test_action_from_str() {
        assert_eq!(
            Action::from_str("PROXY").unwrap(),
            Action::Proxy(String::new())
        );
        assert_eq!(
            Action::from_str("PROBE").unwrap(),
            Action::Probe(String::new())
        );
        assert_eq!(
            Action::from_str("PROXY(http://example.com)").unwrap(),
            Action::Proxy("http://example.com".to_string())
        );
        assert_eq!(
            Action::from_str("PROBE(https://example.com)").unwrap(),
            Action::Probe("https://example.com".to_string())
        );
    }
}
