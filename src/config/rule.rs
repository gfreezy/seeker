use smoltcp::wire::IpCidr;
use std::net::Ipv4Addr;
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
