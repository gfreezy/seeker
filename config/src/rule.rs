use crate::parse_cidr;
use smoltcp::wire::Ipv4Cidr;
use std::fmt::{self, Formatter};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Rule {
    Domain(String, Action),
    DomainSuffix(String, Action),
    DomainKeyword(String, Action),
    IpCidr(Ipv4Cidr, Action),
    Match(Action),
}

#[derive(Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub enum Action {
    Reject,
    Direct,
    Proxy,
    Probe,
}

#[derive(Debug, Clone)]
pub struct ProxyRules {
    rules: Arc<Vec<Rule>>,
}

impl ProxyRules {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules: Arc::new(rules),
        }
    }

    pub fn action_for_domain(&self, domain: &str) -> Option<Action> {
        self.rules
            .iter()
            .filter_map(|rule| match rule {
                Rule::Domain(d, action) if d == domain => Some(*action),
                Rule::DomainSuffix(d, action) if domain.ends_with(d) => Some(*action),
                Rule::DomainKeyword(d, action) if domain.contains(d) => Some(*action),
                Rule::Match(action) => Some(*action),
                _ => None,
            })
            .take(1)
            .next()
    }

    #[allow(dead_code)]
    pub fn action_for_ip(&self, ip: Ipv4Addr) -> Option<Action> {
        self.rules
            .iter()
            .filter_map(|rule| match rule {
                Rule::IpCidr(cidr, action) if cidr.contains_addr(&ip.into()) => Some(*action),
                _ => None,
            })
            .take(1)
            .next()
    }

    pub fn default_action(&self) -> Action {
        Action::Direct
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
            _ => unreachable!(),
        })
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Rule {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let segments = s.splitn(3, ',').collect::<Vec<_>>();
        let (rule, criteria, action) = match segments.len() {
            2 => (segments[0], "", segments[1]),
            3 => (segments[0], segments[1], segments[2]),
            _ => unreachable!(),
        };

        Ok(match rule {
            "DOMAIN" => Rule::Domain(criteria.to_string(), Action::from_str(action).unwrap()),
            "DOMAIN-SUFFIX" => {
                Rule::DomainSuffix(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "DOMAIN-KEYWORD" => {
                Rule::DomainKeyword(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "IP-CIDR" => Rule::IpCidr(
                parse_cidr(criteria.to_string()),
                Action::from_str(action).unwrap(),
            ),
            "MATCH" => Rule::Match(Action::from_str(action).unwrap()),
            _ => unreachable!(),
        })
    }
}
