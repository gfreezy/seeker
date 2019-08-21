use crate::config::ip_cidr_from_str;
use smoltcp::wire::IpCidr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Rule {
    Domain(String, Action),
    DomainSuffix(String, Action),
    DomainKeyword(String, Action),
    IpCidr(IpCidr, Action),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Action {
    Reject,
    Direct,
    Proxy,
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
                Rule::Domain(d, action) if d == domain => Some(action.clone()),
                Rule::DomainSuffix(d, action) if domain.ends_with(d) => Some(action.clone()),
                Rule::DomainKeyword(d, action) if domain.contains(d) => Some(action.clone()),
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
                Rule::IpCidr(cidr, action) if cidr.contains_addr(&ip.into()) => {
                    Some(action.clone())
                }
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
            _ => unreachable!(),
        })
    }
}

impl FromStr for Rule {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let segments = s.splitn(3, ",").collect::<Vec<_>>();
        let (rule, criteria, action) = (segments[0], segments[1], segments[2]);
        Ok(match rule {
            "DOMAIN" => Rule::Domain(criteria.to_string(), Action::from_str(action).unwrap()),
            "DOMAIN-SUFFIX" => {
                Rule::DomainSuffix(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "DOMAIN-KEYWORD" => {
                Rule::DomainKeyword(criteria.to_string(), Action::from_str(action).unwrap())
            }
            "IP-CIDR" => Rule::IpCidr(
                ip_cidr_from_str(criteria),
                Action::from_str(action).unwrap(),
            ),
            _ => unreachable!(),
        })
    }
}
