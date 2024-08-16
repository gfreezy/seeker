use crate::parse_cidr;
use maxminddb::geoip2::Country;
use parking_lot::{Mutex, RwLock};
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use std::fmt::{self, Formatter};
use std::fs::File;
use std::io::{copy, BufWriter};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Once};
use std::thread;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Rule {
    Domain(String, Action),
    DomainSuffix(String, Action),
    DomainKeyword(String, Action),
    IpCidr(Ipv4Cidr, Action),
    GeoIp(String, Action),
    Match(Action),
}

#[derive(Eq, PartialEq, Copy, Clone, Debug, Hash, PartialOrd, Ord, Default)]
pub enum Action {
    #[default]
    Reject,
    Direct,
    Proxy,
    Probe,
}

#[derive(Debug, Clone)]
pub struct ProxyRules {
    rules: Arc<RwLock<Vec<Rule>>>,
    geo_ip_path: Option<PathBuf>,
    default_download_path: PathBuf,
    geo_ip_db: Arc<Mutex<Option<maxminddb::Reader<Vec<u8>>>>>,
}

impl ProxyRules {
    pub fn new(rules: Vec<Rule>, geo_ip_path: Option<PathBuf>) -> Self {
        let s = Self {
            rules: Arc::new(RwLock::new(rules)),
            geo_ip_db: Arc::new(Mutex::new(None)),
            geo_ip_path: geo_ip_path,
            default_download_path: default_geo_ip_path(),
        };
        s.init_geo_ip_db(true);
        s
    }

    /// Create a new ProxyRules with the given rules and geoip database path.
    /// Download the geoip database in the foreground if the path is a http or https url.
    fn new_sync(rules: Vec<Rule>, geo_ip_path: Option<PathBuf>) -> Self {
        let s = Self {
            rules: Arc::new(RwLock::new(rules)),
            geo_ip_db: Arc::new(Mutex::new(None)),
            geo_ip_path: geo_ip_path,
            default_download_path: default_geo_ip_path(),
        };
        s.init_geo_ip_db(false);
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
        if self.default_download_path.exists() {
            tracing::info!("geoip database already exists, skipping download");
            return true;
        }
        let success = download_geoip_database(&url, path);
        if !success {
            tracing::error!("downloaded geoip failed");
        } else {
            tracing::info!("downloaded geoip database to {:?}", path);
        }
        success
    }

    fn init_geo_ip_db(&self, background: bool) {
        let default_path = self.default_download_path.clone();
        let path = match &self.geo_ip_path {
            Some(path) => {
                tracing::info!("geoip path: {:?}", path);
                // Check if path is a valid http or https url
                if path.starts_with("http://") || path.starts_with("https://") {
                    if !default_path.exists() {
                        let self_clone = self.clone();
                        static ONCE: std::sync::Once = Once::new();
                        if background {
                            ONCE.call_once(|| {
                                thread::spawn(move || {
                                    let _ = self_clone.download_geoip_database();
                                });
                            });
                            return;
                        } else {
                            let _ = self_clone.download_geoip_database();
                        }
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
            (Rule::IpCidr(cidr, _), _, Some(ip)) => {
                let ip: Ipv4Address = ip.into();
                if cidr.contains_addr(&ip) {
                    return true;
                }
                false
            }
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
            Rule::Match(action) => *action,
            Rule::Domain(_, action) => *action,
            Rule::DomainSuffix(_, action) => *action,
            Rule::DomainKeyword(_, action) => *action,
            Rule::IpCidr(_, action) => *action,
            Rule::GeoIp(_, action) => *action,
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
                Rule::IpCidr(cidr, Action::Probe | Action::Proxy) => Some(*cidr),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn set_geo_ip_path(&mut self, path: Option<PathBuf>) {
        self.geo_ip_path = path;
    }
}

impl FromStr for Action {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "REJECT" => Action::Reject,
            "DIRECT" => Action::Direct,
            "PROXY" => Action::Proxy,
            "PROBE" => Action::Probe,
            _ => panic!("Invalid action: {}", s),
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
        .map_or(false, |code| code == name)
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
        let path = default_geo_ip_path();
        if !path.exists() {
            download_geoip_database(
                "https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/Country.mmdb",
                &path,
            );
        }
        assert!(path.exists(), "geoip database not found: {:?}", path);
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
        tracing_subscriber::fmt::init();
        let proxy_rule = ProxyRules::new_sync(
            vec![Rule::GeoIp("CN".to_string(), Action::Direct)],
            Some(
                Path::new("https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/Country.mmdb")
                    .to_path_buf(),
            ),
        );
        let action = proxy_rule.action_for_domain(Some("x.com"), "110.242.68.66".parse().ok());
        assert_eq!(action, Some(Action::Direct));
    }
}
