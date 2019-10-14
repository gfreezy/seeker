use async_std::sync::Mutex;
use async_trait::async_trait;
use config::rule::{Action, ProxyRules};
use hermesdns::{
    DnsClient, DnsNetworkClient, DnsPacket, DnsRecord, DnsResolver, QueryType, TransientTtl,
};
use sled::Db;
use std::io::Result;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

const NEXT_IP: &str = "next_ip";

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
#[derive(Clone)]
pub struct RuleBasedDnsResolver {
    inner: Arc<Mutex<Inner>>,
}

impl RuleBasedDnsResolver {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        server: (String, u16),
        rules: ProxyRules,
        next_ip: u32,
    ) -> Self {
        RuleBasedDnsResolver {
            inner: Arc::new(Mutex::new(Inner::new(path, server, rules, next_ip).await)),
        }
    }

    pub async fn lookup_host(&self, addr: &str) -> Option<String> {
        self.inner.lock().await.lookup_host(addr)
    }
}

struct Inner {
    server: (String, u16),
    dns_client: DnsNetworkClient,
    db: Db,
    next_ip: u32,
    rules: ProxyRules,
}

impl Inner {
    async fn new<P: AsRef<Path>>(
        path: P,
        server: (String, u16),
        rules: ProxyRules,
        next_ip: u32,
    ) -> Self {
        let db = Db::open(path).expect("open db error");
        let next_ip = match db.get(NEXT_IP.as_bytes()) {
            Ok(Some(v)) => {
                let mut s = [0; 4];
                s.copy_from_slice(&v);
                u32::from_be_bytes(s)
            }
            _ => {
                db.clear().unwrap();
                next_ip
            }
        };
        let dns_client = DnsNetworkClient::new(0).await;

        Self {
            server,
            db,
            dns_client,
            rules,
            next_ip,
        }
    }

    fn lookup_host(&self, addr: &str) -> Option<String> {
        debug!("lookup host: {}", addr);
        self.db
            .get(addr.as_bytes())
            .unwrap()
            .map(|host| String::from_utf8(host.to_vec()).unwrap())
    }

    fn gen_ipaddr(&mut self) -> String {
        let [a, b, c, d] = self.next_ip.to_be_bytes();
        self.next_ip += 1;
        // TODO: assert next_ip is not to large
        let addr = Ipv4Addr::new(a, b, c, d);
        debug!("Resolver.gen_ipaddr: {}", addr);
        addr.to_string()
    }

    async fn resolve(&mut self, domain: &str) -> Result<DnsPacket> {
        let default_action = self.rules.default_action();

        let action = self
            .rules
            .action_for_domain(domain)
            .unwrap_or(default_action);

        let resp = match action {
            Action::Reject => DnsPacket::new(),
            Action::Direct => {
                debug!("direct, domain: {}", domain);
                self.dns_client
                    .send_query(domain, QueryType::A, (&self.server.0, self.server.1), true)
                    .await?
            }
            Action::Proxy => {
                let ip = if let Some(addr) = self.db.get(domain).expect("get domain") {
                    let ip = String::from_utf8(addr.to_vec()).unwrap();
                    debug!("resolve from cache, domain: {}, ip: {}", domain, &ip);
                    ip
                } else {
                    let ip = self.gen_ipaddr();
                    debug!("resolve to tun, domain: {}, ip: {}", domain, &ip);

                    self.db
                        .insert(NEXT_IP.as_bytes(), &self.next_ip.to_be_bytes())
                        .unwrap();
                    self.db.insert(domain.as_bytes(), ip.as_bytes()).unwrap();
                    self.db.insert(ip.as_bytes(), domain.as_bytes()).unwrap();
                    ip
                };
                let mut packet = DnsPacket::new();
                packet.answers.push(DnsRecord::A {
                    domain: domain.to_string(),
                    addr: ip.parse().unwrap(),
                    ttl: TransientTtl(5),
                });
                packet
            }
        };

        Ok(resp)
    }
}

#[async_trait]
impl DnsResolver for RuleBasedDnsResolver {
    async fn resolve(
        &self,
        domain: &str,
        _qtype: QueryType,
        _recursive: bool,
    ) -> Result<DnsPacket> {
        let mut guard = self.inner.lock().await;
        guard.resolve(domain).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use config::rule::{Action, Rule};

    #[test]
    fn test_inner_resolve_ip_and_lookup_host() {
        let dir = tempfile::tempdir().unwrap();
        let server = ("114.114.114.114".to_string(), 53);
        let rules = ProxyRules::new(vec![
            Rule::Domain("baidu.com".to_string(), Action::Proxy),
            Rule::Domain("to-deny.com".to_string(), Action::Reject),
            Rule::DomainKeyword("ali".to_string(), Action::Proxy),
            Rule::DomainKeyword("www.taobao.com".to_string(), Action::Direct),
        ]);
        let start_ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        let n = u32::from_be_bytes(start_ip.octets());
        task::block_on(async {
            let mut inner = Inner::new(dir.path(), server, rules, n).await;
            println!("server");
            assert_eq!(
                inner.resolve("baidu.com").await.unwrap().get_random_a(),
                Some("10.0.0.1".to_string())
            );
            assert_eq!(
                inner.resolve("to-deny.com").await.unwrap().get_random_a(),
                None
            );
            assert_eq!(
                inner.resolve("www.ali.com").await.unwrap().get_random_a(),
                Some("10.0.0.2".to_string())
            );
            assert!(inner.resolve("www.taobao.com").await.unwrap().answers.len() > 0);
            assert_eq!(inner.lookup_host("10.0.0.1"), Some("baidu.com".to_string()));
            assert_eq!(inner.lookup_host("10.1.0.1"), None);
        });
    }
}
