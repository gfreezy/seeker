use hickory_resolver::proto::rr::rdata::{A, AAAA};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use async_trait::async_trait;
use config::rule::{Action, ProxyRules};
use hermesdns::{DnsPacket, DnsRecord, DnsResolver, Hosts, QueryType, TransientTtl};
use std::any::Any;
use std::io;
use std::io::Result;
use std::sync::Arc;
use store::Store;
use tracing::{debug, error};

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
    bypass_direct: bool,
    resolver: TokioAsyncResolver,
}

impl RuleBasedDnsResolver {
    pub async fn new(bypass_direct: bool, rules: ProxyRules, resolver: TokioAsyncResolver) -> Self {
        RuleBasedDnsResolver {
            inner: Arc::new(Inner {
                hosts: Hosts::load().expect("load /etc/hosts"),
                rules,
                bypass_direct,
                resolver,
            }),
        }
    }

    pub fn lookup_host(&self, addr: &str) -> Option<String> {
        let host = Store::global()
            .get_host_by_ipv4(addr.parse().expect("invalid addr"))
            .expect("get host");
        debug!("lookup host: {:?}, addr: {:?}", host, addr);
        host
    }

    async fn resolve_real(&self, domain: &str, qtype: QueryType) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();
        // AAAA record is not supported yet.
        if qtype == QueryType::AAAA {
            return Ok(packet);
        }
        let lookup = self
            .inner
            .resolver
            .lookup(domain, RecordType::from(qtype.to_num()))
            .await;
        let lookup = match lookup {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "resolve error, domain: {}, type: {:?}, {:?}",
                    domain, qtype, e
                );
                return Ok(packet);
            }
        };

        for record in lookup.record_iter() {
            let rdata = match record.data() {
                None => {
                    continue;
                }
                Some(RData::A(A(ip))) => DnsRecord::A {
                    domain: domain.to_string(),
                    addr: *ip,
                    ttl: TransientTtl(record.ttl()),
                },
                Some(RData::AAAA(AAAA(ip))) => DnsRecord::AAAA {
                    domain: domain.to_string(),
                    addr: *ip,
                    ttl: TransientTtl(record.ttl()),
                },
                Some(RData::CNAME(cname)) => DnsRecord::CNAME {
                    domain: domain.to_string(),
                    host: cname.to_string(),
                    ttl: TransientTtl(record.ttl()),
                },
                Some(RData::MX(mx)) => DnsRecord::MX {
                    domain: domain.to_string(),
                    host: mx.exchange().to_string(),
                    priority: mx.preference(),
                    ttl: TransientTtl(record.ttl()),
                },
                Some(RData::NS(ns)) => DnsRecord::NS {
                    domain: domain.to_string(),
                    host: ns.to_string(),
                    ttl: TransientTtl(record.ttl()),
                },
                Some(RData::SOA(soa)) => DnsRecord::SOA {
                    domain: domain.to_string(),
                    m_name: soa.mname().to_string(),
                    r_name: soa.rname().to_string(),
                    serial: soa.serial(),
                    refresh: soa.refresh() as u32,
                    retry: soa.retry() as u32,
                    expire: soa.expire() as u32,
                    minimum: soa.minimum(),
                    ttl: TransientTtl(record.ttl()),
                },
                Some(RData::TXT(txt)) => DnsRecord::TXT {
                    domain: domain.to_string(),
                    data: txt.to_string(),
                    ttl: TransientTtl(record.ttl()),
                },
                Some(RData::SRV(srv)) => DnsRecord::SRV {
                    domain: domain.to_string(),
                    priority: srv.priority(),
                    weight: srv.weight(),
                    port: srv.port(),
                    host: srv.target().to_string(),
                    ttl: TransientTtl(record.ttl()),
                },
                other => {
                    tracing::info!("unsupported record type: {:?}", other);
                    continue;
                }
            };
            let record_type_num: u16 = record.record_type().into();
            if record_type_num == qtype.to_num() {
                packet.answers.push(rdata)
            }
        }

        Ok(packet)
    }

    async fn resolve(&self, domain: &str, qtype: QueryType) -> Result<DnsPacket> {
        // We only support A record for now, for other records, we just forward them to upstream.
        if !matches!(qtype, QueryType::A) {
            return self.resolve_real(domain, qtype).await;
        }

        let mut packet = DnsPacket::new();

        // lookup /etc/hosts
        if let Some(ip) = self.inner.hosts.get(domain) {
            packet.answers.push(DnsRecord::A {
                domain: domain.to_string(),
                addr: ip,
                ttl: TransientTtl(3),
            });
            debug!(
                "lookup host for /etc/hosts domain: {}, ip: {:?}",
                domain, ip
            );
            return Ok(packet);
        }

        // direct traffic bypass tun.
        let bypass_direct = self.inner.bypass_direct;
        let mut real_packet: Result<DnsPacket> = Err(io::Error::other("real packet not found"));
        // lookup real ip
        let ip = if bypass_direct {
            // resolve real ip only when `bypass_direct` is false.
            real_packet = self.resolve_real(domain, qtype).await;
            if let Ok(p) = &real_packet {
                let real_ip = p
                    .answers
                    .iter()
                    .filter_map(|record| {
                        if let DnsRecord::A { addr, .. } = record {
                            Some(std::net::IpAddr::V4(*addr))
                        } else {
                            None
                        }
                    })
                    .next();
                real_ip
            } else {
                None
            }
        } else {
            None
        };

        match self.inner.rules.action_for_domain(Some(domain), ip) {
            // Return real ip when `bypass_direct` is true.
            Some(Action::Direct) if bypass_direct => {
                tracing::info!("bypass_direct, domain: {:?}, ip: {:?}", domain, ip);
                return real_packet;
            }
            // Do not return dns records when action is reject.
            Some(Action::Reject) => return Ok(packet),
            _ => {}
        };

        let ip = Store::global()
            .get_ipv4_by_host(domain)
            .expect("get domain");
        packet.answers.push(DnsRecord::A {
            domain: domain.to_string(),
            addr: ip,
            ttl: TransientTtl(3),
        });
        tracing::info!("lookup domain: {:?}, ip: {:?}", domain, ip);
        Ok(packet)
    }
}

#[async_trait]
impl DnsResolver for RuleBasedDnsResolver {
    async fn resolve(&self, domain: &str, qtype: QueryType, _recursive: bool) -> Result<DnsPacket> {
        self.resolve(domain, qtype).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::new_resolver;
    use config::rule::Rule;

    #[test]
    fn test_inner_resolve_ip_and_lookup_host() {
        store::Store::setup_global_for_test();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
        let dns = std::env::var("DNS").unwrap_or_else(|_| "223.5.5.5".to_string());
        tokio_test::block_on(async {
            let resolver = RuleBasedDnsResolver::new(
                false,
                ProxyRules::new(
                    vec![Rule::Domain(
                        "baidu.com".to_string(),
                        Action::Proxy("".to_string()),
                    )],
                    None,
                ),
                new_resolver(dns, 53).await,
            )
            .await;
            let baidu_ip = resolver
                .resolve("baidu.com", QueryType::A)
                .await
                .unwrap()
                .get_random_a();
            assert_eq!(
                resolver.lookup_host(&baidu_ip.unwrap()),
                Some("baidu.com".to_string())
            );
            assert!(resolver
                .resolve("mycookbook.allsunday.io", QueryType::TXT)
                .await
                .unwrap()
                .get_txt()
                .is_some());
            assert_eq!(resolver.lookup_host("10.1.0.1"), None);
        });
    }
}
