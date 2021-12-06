use async_std::net::IpAddr;
use async_std_resolver::AsyncStdResolver;
use async_trait::async_trait;
use config::rule::{Action, ProxyRules};
use hermesdns::{DnsPacket, DnsRecord, DnsResolver, Hosts, QueryType, TransientTtl};
use sled::Db;
use std::any::Any;
use std::io;
use std::io::Result;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::{debug, error, trace};
use trust_dns_proto::rr::RData;

const NEXT_IP: &str = "next_ip";

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
#[derive(Clone)]
pub struct RuleBasedDnsResolver {
    inner: Arc<Inner>,
}

struct Inner {
    hosts: Hosts,
    rules: ProxyRules,
    db: Db,
    next_ip: AtomicU32,
    resolver: AsyncStdResolver,
}

impl RuleBasedDnsResolver {
    pub async fn new<P: AsRef<Path>>(
        path: P,
        next_ip: u32,
        rules: ProxyRules,
        resolver: AsyncStdResolver,
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

        RuleBasedDnsResolver {
            inner: Arc::new(Inner {
                hosts: Hosts::load().expect("load /etc/hosts"),
                rules,
                next_ip: AtomicU32::new(next_ip),
                db,
                resolver,
            }),
        }
    }

    pub fn lookup_host(&self, addr: &str) -> Option<String> {
        let host = self
            .inner
            .db
            .get(addr.as_bytes())
            .unwrap()
            .map(|host| String::from_utf8(host.to_vec()).unwrap());
        debug!("lookup host: {}, addr: {:?}", addr, host);
        host
    }

    fn gen_ipaddr(&self) -> String {
        let [a, b, c, d] = (self.inner.next_ip.load(Ordering::SeqCst) as u32).to_be_bytes();
        self.inner.next_ip.fetch_add(1, Ordering::SeqCst);
        // TODO: assert next_ip is not to large
        let addr = Ipv4Addr::new(a, b, c, d);
        debug!("Resolver.gen_ipaddr: {}", addr);
        addr.to_string()
    }

    async fn resolve(&self, domain: &str) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();
        if let Some(ip) = self.inner.hosts.get(domain) {
            packet.answers.push(DnsRecord::A {
                domain: domain.to_string(),
                addr: ip,
                ttl: TransientTtl(60),
            });
            debug!(
                "lookup host for /etc/hosts domain: {}, ip: {:?}",
                domain, ip
            );
            return Ok(packet);
        }

        match self.inner.rules.action_for_domain(domain) {
            Some(Action::Direct) => {
                let lookup_ip = self.inner.resolver.lookup_ip(domain).await.map_err(|e| {
                    let msg = e.to_string();
                    error!("directly lookup host error: {}", &msg);
                    io::Error::new(io::ErrorKind::Other, msg)
                })?;
                let mut ips: Vec<IpAddr> = vec![];
                for record in lookup_ip.as_lookup().record_iter() {
                    let rdata = match record.rdata() {
                        RData::A(ip) => {
                            ips.push(IpAddr::V4(*ip));
                            DnsRecord::A {
                                domain: domain.to_string(),
                                addr: *ip,
                                ttl: TransientTtl(record.ttl()),
                            }
                        }
                        RData::AAAA(ip) => {
                            ips.push(IpAddr::V6(*ip));
                            DnsRecord::AAAA {
                                domain: domain.to_string(),
                                addr: *ip,
                                ttl: TransientTtl(record.ttl()),
                            }
                        }
                        other => {
                            trace!("resolve return other: {:?}", other);
                            continue;
                        }
                    };
                    packet.answers.push(rdata)
                }

                debug!("lookup host for direct domain: {}, ip: {:?}", domain, ips);
                return Ok(packet);
            }
            Some(Action::Reject) => return Ok(packet),
            _ => {}
        };

        let ip = if let Some(addr) = self.inner.db.get(domain).expect("get domain") {
            let ip = String::from_utf8(addr.to_vec()).unwrap();
            debug!("lookup host from cache, domain: {}, ip: {}", domain, &ip);
            ip
        } else {
            let ip = self.gen_ipaddr();
            debug!("lookup host gen ip, domain: {}, ip: {}", domain, &ip);

            self.inner
                .db
                .insert(
                    NEXT_IP.as_bytes(),
                    &self.inner.next_ip.load(Ordering::SeqCst).to_be_bytes(),
                )
                .unwrap();
            self.inner
                .db
                .insert(domain.as_bytes(), ip.as_bytes())
                .unwrap();
            self.inner
                .db
                .insert(ip.as_bytes(), domain.as_bytes())
                .unwrap();
            ip
        };

        packet.answers.push(DnsRecord::A {
            domain: domain.to_string(),
            addr: ip.parse().unwrap(),
            ttl: TransientTtl(5),
        });
        Ok(packet)
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
        self.resolve(domain).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::new_resolver;
    use async_std::task;

    #[test]
    fn test_inner_resolve_ip_and_lookup_host() {
        let dir = tempfile::tempdir().unwrap();
        let start_ip = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        let n = u32::from_be_bytes(start_ip.octets());
        let dns = std::env::var("DNS").unwrap_or_else(|_| "223.5.5.5".to_string());
        task::block_on(async {
            let resolver = RuleBasedDnsResolver::new(
                dir.path(),
                n,
                ProxyRules::new(vec![]),
                new_resolver(dns, 53).await,
            )
            .await;
            assert_eq!(
                resolver.resolve("baidu.com").await.unwrap().get_random_a(),
                Some("10.0.0.1".to_string())
            );
            assert_eq!(
                resolver
                    .resolve("www.ali.com")
                    .await
                    .unwrap()
                    .get_random_a(),
                Some("10.0.0.2".to_string())
            );
            assert_eq!(
                resolver.lookup_host("10.0.0.1"),
                Some("baidu.com".to_string())
            );
            assert_eq!(resolver.lookup_host("10.1.0.1"), None);
        });
    }
}
