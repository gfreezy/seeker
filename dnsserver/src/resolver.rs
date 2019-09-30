use async_std::sync::Mutex;
use async_trait::async_trait;
use config::rule::{Action, ProxyRules};
use hermesdns::{
    DnsClient, DnsNetworkClient, DnsPacket, DnsRecord, DnsResolver, QueryType, TransientTtl,
};
use sled::Db;
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::path::Path;
use tracing::debug;

const NEXT_IP: &str = "next_ip";

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
pub struct RuleBasedDnsResolver {
    inner: Mutex<Inner>,
}

impl RuleBasedDnsResolver {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        server: (String, u16),
        rules: ProxyRules,
        next_ip: u32,
    ) -> Self {
        RuleBasedDnsResolver {
            inner: Mutex::new(Inner::new(path, server, rules, next_ip).await),
        }
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
    pub async fn new<P: AsRef<Path>>(
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

    #[allow(dead_code)]
    pub async fn lookup_host(&self, addr: &str) -> Result<String> {
        debug!("lookup host: {}", addr);
        if let Some(host) = self.db.get(addr.as_bytes()).unwrap() {
            Ok(String::from_utf8(host.to_vec()).unwrap())
        } else {
            Err(Error::new(ErrorKind::Other, "no host found".to_string()))
        }
    }

    fn gen_ipaddr(&mut self) -> String {
        let [a, b, c, d] = self.next_ip.to_be_bytes();
        self.next_ip += 1;
        // TODO: assert next_ip is not to large
        let addr = Ipv4Addr::new(a, b, c, d);
        debug!("Resolver.gen_ipaddr: {}", addr);
        addr.to_string()
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
        let default_action = guard.rules.default_action();

        let action = guard
            .rules
            .action_for_domain(domain)
            .unwrap_or(default_action);

        let resp = match action {
            Action::Reject => DnsPacket::new(),
            Action::Direct => {
                debug!("direct, domain: {}", domain);
                guard
                    .dns_client
                    .send_query(
                        domain,
                        QueryType::A,
                        (&guard.server.0, guard.server.1),
                        true,
                    )
                    .await?
            }
            Action::Proxy => {
                let ip = if let Some(addr) = guard.db.get(domain).expect("get domain") {
                    let ip = String::from_utf8(addr.to_vec()).unwrap();
                    debug!("resolve from cache, domain: {}, ip: {}", domain, &ip);
                    ip
                } else {
                    let ip = guard.gen_ipaddr();
                    debug!("resolve to tun, domain: {}, ip: {}", domain, &ip);

                    guard
                        .db
                        .insert(NEXT_IP.as_bytes(), &guard.next_ip.to_be_bytes())
                        .unwrap();
                    guard.db.insert(domain.as_bytes(), ip.as_bytes()).unwrap();
                    guard.db.insert(ip.as_bytes(), domain.as_bytes()).unwrap();
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
