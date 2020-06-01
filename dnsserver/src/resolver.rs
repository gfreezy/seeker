use async_std::sync::Mutex;
use async_trait::async_trait;
use config::rule::{Action, ProxyRules};
use hermesdns::{
    DnsClient, DnsNetworkClient, DnsPacket, DnsRecord, DnsResolver, Hosts, QueryType, TransientTtl,
};
use sled::Db;
use std::any::Any;
use std::io::Result;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
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
        next_ip: u32,
        rules: ProxyRules,
        dns_server: (String, u16),
    ) -> Self {
        RuleBasedDnsResolver {
            inner: Arc::new(Mutex::new(
                Inner::new(path, next_ip, rules, dns_server).await,
            )),
        }
    }

    pub async fn lookup_host(&self, addr: &str) -> Option<String> {
        self.inner.lock().await.lookup_host(addr).await
    }
}

struct Inner {
    db: Db,
    next_ip: u32,
    hosts: Hosts,
    rules: ProxyRules,
    dns_server: (String, u16),
    resolver: DnsNetworkClient,
}

impl Inner {
    async fn new<P: AsRef<Path>>(
        path: P,
        next_ip: u32,
        rules: ProxyRules,
        dns_server: (String, u16),
    ) -> Self {
        let db = sled::open(path).expect("open db error");
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

        Self {
            db,
            next_ip,
            hosts: Hosts::load().expect("load /etc/hosts"),
            rules,
            dns_server,
            resolver: DnsNetworkClient::new(0, Duration::from_millis(100)).await,
        }
    }

    async fn lookup_host(&self, addr: &str) -> Option<String> {
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
        let mut packet = DnsPacket::new();
        if let Some(ip) = self.hosts.get(domain) {
            packet.answers.push(DnsRecord::A {
                domain: domain.to_string(),
                addr: ip,
                ttl: TransientTtl(1),
            });
            return Ok(packet);
        }

        match self.rules.action_for_domain(domain) {
            Some(Action::Direct) => {
                debug!("lookup host for direct domain: {}", domain);
                return self
                    .resolver
                    .send_query(
                        domain,
                        QueryType::A,
                        (&self.dns_server.0, self.dns_server.1),
                        true,
                    )
                    .await;
            }
            Some(Action::Reject) => return Ok(packet),
            _ => {}
        };

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
        packet.answers.push(DnsRecord::A {
            domain: domain.to_string(),
            addr: ip.parse().unwrap(),
            ttl: TransientTtl(1),
        });
        Ok(packet)
    }
}

pub async fn resolve_domain<T: DnsClient>(
    resolver: &T,
    server: (&str, u16),
    domain: &str,
) -> Result<Option<String>> {
    let packet = resolver
        .send_query(domain, QueryType::A, server, true)
        .await?;
    let ip = packet.get_first_a();
    Ok(ip)
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;

    #[test]
    fn test_inner_resolve_ip_and_lookup_host() {
        let dir = tempfile::tempdir().unwrap();
        let start_ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        let n = u32::from_be_bytes(start_ip.octets());
        let dns = std::env::var("DNS").unwrap_or_else(|_| "223.5.5.5".to_string());
        task::block_on(async {
            let mut inner = Inner::new(dir.path(), n, ProxyRules::new(vec![]), (dns, 53)).await;
            assert_eq!(
                inner.resolve("baidu.com").await.unwrap().get_random_a(),
                Some("10.0.0.1".to_string())
            );
            assert_eq!(
                inner.resolve("www.ali.com").await.unwrap().get_random_a(),
                Some("10.0.0.2".to_string())
            );
            assert_eq!(
                inner.lookup_host("10.0.0.1").await,
                Some("baidu.com".to_string())
            );
            assert_eq!(inner.lookup_host("10.1.0.1").await, None);
        });
    }
}
