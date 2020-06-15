use async_std_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use async_std_resolver::{resolver, AsyncStdResolver};
use config::Address;
use std::io::{Error, ErrorKind, Result};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone)]
pub struct DnsClient {
    resolver: AsyncStdResolver,
}

impl DnsClient {
    pub async fn new(dns_servers: &[SocketAddr], timeout: Duration) -> Self {
        let mut name_servers = NameServerConfigGroup::with_capacity(dns_servers.len());

        for addr in dns_servers {
            let udp = NameServerConfig {
                socket_addr: *addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
            };
            name_servers.push(udp);
        }

        let num_concurrent_reqs = name_servers.len();

        // Construct a new Resolver with default configuration options
        let resolver = resolver(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            ResolverOpts {
                timeout,
                num_concurrent_reqs,
                ..Default::default()
            },
        )
        .await
        .expect("failed to create resolver");

        DnsClient { resolver }
    }

    pub fn resolver(&self) -> AsyncStdResolver {
        self.resolver.clone()
    }
    pub async fn lookup(&self, domain: &str) -> Result<IpAddr> {
        let response = self
            .resolver
            .lookup_ip(domain)
            .await
            .map_err(|_| Error::new(ErrorKind::NotFound, format!("{} not resolved", domain)))?;
        response
            .iter()
            .next()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("{} not resolved", domain)))
    }

    pub async fn lookup_address(&self, addr: &Address) -> Result<SocketAddr> {
        match addr {
            Address::SocketAddress(a) => Ok(*a),
            Address::DomainNameAddress(domain, port) => {
                let ip = self.lookup(domain).await?;
                Ok(SocketAddr::new(ip, *port))
            }
        }
    }
}
