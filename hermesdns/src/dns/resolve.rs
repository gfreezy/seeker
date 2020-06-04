//! resolver implementations implementing different strategies for answering
//! incoming queries

use async_trait::async_trait;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::vec::Vec;

use crate::dns::authority::Authority;
use crate::dns::cache::SynchronizedCache;
use crate::dns::client::DnsClient;
use crate::dns::protocol::{DnsPacket, QueryType, ResultCode};
use std::any::Any;

#[async_trait]
pub trait DnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket>;

    fn as_any(&self) -> &dyn Any;
}

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
pub struct ForwardingDnsResolver {
    server: (String, u16),
    cache: SynchronizedCache,
    dns_client: Box<dyn DnsClient + Sync + Send>,
    allow_recursive: bool,
}

impl ForwardingDnsResolver {
    pub async fn new(
        server: (String, u16),
        allow_recursive: bool,
        dns_client: Box<dyn DnsClient + Send + Sync>,
    ) -> ForwardingDnsResolver {
        ForwardingDnsResolver {
            server,
            cache: SynchronizedCache::new(),
            dns_client,
            allow_recursive,
        }
    }
}

#[async_trait]
impl DnsResolver for ForwardingDnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        if !recursive || !self.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Some(qr) = self.cache.lookup(qname, qtype) {
            return Ok(qr);
        }

        if qtype == QueryType::A || qtype == QueryType::AAAA {
            if let Some(qr) = self.cache.lookup(qname, QueryType::CNAME) {
                return Ok(qr);
            }
        }
        let &(ref host, port) = &self.server;
        let result = self
            .dns_client
            .send_query(qname, qtype, (host.as_str(), port), true)
            .await;

        if let Ok(ref qr) = result {
            let _ = self.cache.store(&qr.answers);
        }

        result
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A Recursive DNS resolver
///
/// This resolver can answer any request using the root servers of the internet
pub struct RecursiveDnsResolver {
    cache: SynchronizedCache,
    dns_client: Box<dyn DnsClient + Send + Sync>,
    allow_recursive: bool,
    #[allow(dead_code)]
    authority: Authority,
}

impl RecursiveDnsResolver {
    pub async fn new(
        allow_recursive: bool,
        dns_client: Box<dyn DnsClient + Sync + Send>,
    ) -> RecursiveDnsResolver {
        let authority = Authority::new();
        authority.load().await.expect("load authority");
        RecursiveDnsResolver {
            cache: SynchronizedCache::new(),
            dns_client,
            authority,
            allow_recursive,
        }
    }

    async fn perform(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Find the closest name server by splitting the label and progessively
        // moving towards the root servers. I.e. check "google.com", then "com",
        // and finally "".
        let mut tentative_ns = None;

        let labels = qname.split('.').collect::<Vec<&str>>();
        for lbl_idx in 0..=labels.len() {
            let domain = labels[lbl_idx..].join(".");

            match self
                .cache
                .lookup(&domain, QueryType::NS)
                .and_then(|qr| qr.get_unresolved_ns(&domain))
                .and_then(|ns| self.cache.lookup(&ns, QueryType::A))
                .and_then(|qr| qr.get_random_a())
            {
                Some(addr) => {
                    tentative_ns = Some(addr);
                    break;
                }
                None => continue,
            }
        }

        let mut ns = match tentative_ns {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::NotFound, "No DNS server found")),
        };

        // Start querying name servers
        loop {
            let ns_copy = ns.clone();

            let server = (ns_copy.as_str(), 53);
            let response = self
                .dns_client
                .send_query(qname, qtype.clone(), server, false)
                .await?;

            // If we've got an actual answer, we're done!
            if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
                let _ = self.cache.store(&response.answers);
                let _ = self.cache.store(&response.authorities);
                let _ = self.cache.store(&response.resources);
                return Ok(response.clone());
            }

            if response.header.rescode == ResultCode::NXDOMAIN {
                if let Some(ttl) = response.get_ttl_from_soa() {
                    let _ = self.cache.store_nxdomain(qname, qtype, ttl);
                }
                return Ok(response.clone());
            }

            // Otherwise, try to find a new nameserver based on NS and a
            // corresponding A record in the additional section
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                // If there is such a record, we can retry the loop with that NS
                ns = new_ns.clone();
                let _ = self.cache.store(&response.answers);
                let _ = self.cache.store(&response.authorities);
                let _ = self.cache.store(&response.resources);

                continue;
            }

            // If not, we'll have to resolve the ip of a NS record
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => return Ok(response.clone()),
            };

            // Recursively resolve the NS
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true).await?;

            // Pick a random IP and restart
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns.clone();
            } else {
                return Ok(response.clone());
            }
        }
    }
}

#[async_trait]
impl DnsResolver for RecursiveDnsResolver {
    async fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        if !recursive || !self.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Some(qr) = self.cache.lookup(qname, qtype) {
            return Ok(qr);
        }

        if qtype == QueryType::A || qtype == QueryType::AAAA {
            if let Some(qr) = self.cache.lookup(qname, QueryType::CNAME) {
                return Ok(qr);
            }
        }

        self.perform(qname, qtype).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {

    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};

    use super::*;

    use crate::dns::context::tests::create_test_context;
    use crate::ResolveStrategy;
    use async_std::task::block_on;

    #[test]
    fn test_forwarding_resolver() {
        block_on(async {
            let context = create_test_context(
                Box::new(|qname, _, _, _| {
                    let mut packet = DnsPacket::new();

                    if qname == "google.com" {
                        packet.answers.push(DnsRecord::A {
                            domain: "google.com".to_string(),
                            addr: "127.0.0.1".parse().unwrap(),
                            ttl: TransientTtl(3600),
                        });
                    } else {
                        packet.header.rescode = ResultCode::NXDOMAIN;
                    }

                    Ok(packet)
                }),
                ResolveStrategy::Forward {
                    host: "114.114.114.114".to_string(),
                    port: 53,
                },
            )
            .await;

            let resolver: &ForwardingDnsResolver = context
                .resolver
                .as_any()
                .downcast_ref::<ForwardingDnsResolver>()
                .expect("cast to ForwardingDnsResolver");

            // First verify that we get a match back
            {
                let res = match resolver.resolve("google.com", QueryType::A, true).await {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(1, res.answers.len());

                match res.answers[0] {
                    DnsRecord::A { ref domain, .. } => {
                        assert_eq!("google.com", domain);
                    }
                    _ => panic!(),
                }
            };

            // Do the same lookup again, and verify that it's present in the cache
            // and that the counter has been updated
            {
                let res = match resolver.resolve("google.com", QueryType::A, true).await {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(1, res.answers.len());

                let list = match resolver.cache.list() {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(1, list.len());

                assert_eq!("google.com", list[0].domain);
                assert_eq!(1, list[0].record_types.len());
                assert_eq!(1, list[0].hits);
            };

            // Do a failed lookup
            {
                let res = match resolver.resolve("yahoo.com", QueryType::A, true).await {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(0, res.answers.len());
                assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
            };
        });
    }

    #[test]
    fn test_recursive_resolver_with_no_nameserver() {
        block_on(async {
            let context = create_test_context(
                Box::new(|_, _, _, _| {
                    let mut packet = DnsPacket::new();
                    packet.header.rescode = ResultCode::NXDOMAIN;
                    Ok(packet)
                }),
                ResolveStrategy::Recursive,
            )
            .await;

            let resolver = &context.resolver;

            // Expect failure when no name servers are available
            if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
                panic!();
            }
        })
    }

    #[test]
    fn test_recursive_resolver_with_missing_a_record() {
        block_on(async {
            let context = create_test_context(
                Box::new(|_, _, _, _| {
                    let mut packet = DnsPacket::new();
                    packet.header.rescode = ResultCode::NXDOMAIN;
                    Ok(packet)
                }),
                ResolveStrategy::Recursive,
            )
            .await;

            let resolver: &RecursiveDnsResolver = context
                .resolver
                .as_any()
                .downcast_ref::<RecursiveDnsResolver>()
                .expect("cast to RecursiveDnsResolver");

            // Expect failure when no name servers are available
            if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
                panic!();
            }

            // Insert name server, but no corresponding A record
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "".to_string(),
                host: "a.myroot.net".to_string(),
                ttl: TransientTtl(3600),
            });

            let _ = resolver.cache.store(&nameservers);

            if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
                panic!();
            }
        })
    }

    #[test]
    fn test_recursive_resolver_match_order() {
        block_on(async {
            let context = create_test_context(
                Box::new(|_, _, (server, _), _| {
                    let mut packet = DnsPacket::new();

                    if server == "127.0.0.1" {
                        packet.header.id = 1;

                        packet.answers.push(DnsRecord::A {
                            domain: "a.google.com".to_string(),
                            addr: "127.0.0.1".parse().unwrap(),
                            ttl: TransientTtl(3600),
                        });

                        return Ok(packet);
                    } else if server == "127.0.0.2" {
                        packet.header.id = 2;

                        packet.answers.push(DnsRecord::A {
                            domain: "b.google.com".to_string(),
                            addr: "127.0.0.1".parse().unwrap(),
                            ttl: TransientTtl(3600),
                        });

                        return Ok(packet);
                    } else if server == "127.0.0.3" {
                        packet.header.id = 3;

                        packet.answers.push(DnsRecord::A {
                            domain: "c.google.com".to_string(),
                            addr: "127.0.0.1".parse().unwrap(),
                            ttl: TransientTtl(3600),
                        });

                        return Ok(packet);
                    }

                    packet.header.id = 999;
                    packet.header.rescode = ResultCode::NXDOMAIN;
                    Ok(packet)
                }),
                ResolveStrategy::Recursive,
            )
            .await;

            let resolver = context
                .resolver
                .as_any()
                .downcast_ref::<RecursiveDnsResolver>()
                .expect("cast to ForwardingDnsResolver");

            // Expect failure when no name servers are available
            if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
                panic!();
            }

            // Insert root servers
            {
                let mut nameservers = Vec::new();
                nameservers.push(DnsRecord::NS {
                    domain: "".to_string(),
                    host: "a.myroot.net".to_string(),
                    ttl: TransientTtl(3600),
                });
                nameservers.push(DnsRecord::A {
                    domain: "a.myroot.net".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                let _ = resolver.cache.store(&nameservers);
            }

            match resolver.resolve("google.com", QueryType::A, true).await {
                Ok(packet) => {
                    assert_eq!(1, packet.header.id);
                }
                Err(_) => panic!(),
            }

            // Insert TLD servers
            {
                let mut nameservers = Vec::new();
                nameservers.push(DnsRecord::NS {
                    domain: "com".to_string(),
                    host: "a.mytld.net".to_string(),
                    ttl: TransientTtl(3600),
                });
                nameservers.push(DnsRecord::A {
                    domain: "a.mytld.net".to_string(),
                    addr: "127.0.0.2".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                let _ = resolver.cache.store(&nameservers);
            }

            match resolver.resolve("google.com", QueryType::A, true).await {
                Ok(packet) => {
                    assert_eq!(2, packet.header.id);
                }
                Err(_) => panic!(),
            }

            // Insert authoritative servers
            {
                let mut nameservers = Vec::new();
                nameservers.push(DnsRecord::NS {
                    domain: "google.com".to_string(),
                    host: "ns1.google.com".to_string(),
                    ttl: TransientTtl(3600),
                });
                nameservers.push(DnsRecord::A {
                    domain: "ns1.google.com".to_string(),
                    addr: "127.0.0.3".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                let _ = resolver.cache.store(&nameservers);
            }

            match resolver.resolve("google.com", QueryType::A, true).await {
                Ok(packet) => {
                    assert_eq!(3, packet.header.id);
                }
                Err(_) => panic!(),
            }
        });
    }

    #[test]
    fn test_recursive_resolver_successfully() {
        block_on(async {
            let context = create_test_context(
                Box::new(|qname, _, _, _| {
                    let mut packet = DnsPacket::new();

                    if qname == "google.com" {
                        packet.answers.push(DnsRecord::A {
                            domain: "google.com".to_string(),
                            addr: "127.0.0.1".parse().unwrap(),
                            ttl: TransientTtl(3600),
                        });
                    } else {
                        packet.header.rescode = ResultCode::NXDOMAIN;

                        packet.authorities.push(DnsRecord::SOA {
                            domain: "google.com".to_string(),
                            r_name: "google.com".to_string(),
                            m_name: "google.com".to_string(),
                            serial: 0,
                            refresh: 3600,
                            retry: 3600,
                            expire: 3600,
                            minimum: 3600,
                            ttl: TransientTtl(3600),
                        });
                    }

                    Ok(packet)
                }),
                ResolveStrategy::Recursive,
            )
            .await;

            let resolver: &RecursiveDnsResolver = context
                .resolver
                .as_any()
                .downcast_ref::<RecursiveDnsResolver>()
                .expect("cast to ForwardingDnsResolver");

            // Insert name servers
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "google.com".to_string(),
                host: "ns1.google.com".to_string(),
                ttl: TransientTtl(3600),
            });
            nameservers.push(DnsRecord::A {
                domain: "ns1.google.com".to_string(),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600),
            });

            let _ = resolver.cache.store(&nameservers);

            // Check that we can successfully resolve
            {
                let res = match resolver.resolve("google.com", QueryType::A, true).await {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(1, res.answers.len());

                match res.answers[0] {
                    DnsRecord::A { ref domain, .. } => {
                        assert_eq!("google.com", domain);
                    }
                    _ => panic!(),
                }
            };

            // And that we won't find anything for a domain that isn't present
            {
                let res = match resolver
                    .resolve("foobar.google.com", QueryType::A, true)
                    .await
                {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
                assert_eq!(0, res.answers.len());
            };

            // Perform another successful query, that should hit the cache
            {
                let res = match resolver.resolve("google.com", QueryType::A, true).await {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(1, res.answers.len());
            };

            // Now check that the cache is used, and that the statistics is correct
            {
                let list = match resolver.cache.list() {
                    Ok(x) => x,
                    Err(_) => panic!(),
                };

                assert_eq!(3, list.len());

                // Check statistics for google entry
                assert_eq!("google.com", list[1].domain);

                // Should have a NS record and an A record for a total of 2 record types
                assert_eq!(2, list[1].record_types.len());

                // Should have been hit two times for NS google.com and once for
                // A google.com
                assert_eq!(3, list[1].hits);

                assert_eq!("ns1.google.com", list[2].domain);
                assert_eq!(1, list[2].record_types.len());
                assert_eq!(2, list[2].hits);
            };
        });
    }
}
