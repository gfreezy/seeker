use async_std_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
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
    pub async fn new(dns_server: SocketAddr, timeout: Duration) -> Self {
        // Construct a new Resolver with default configuration options
        let resolver = resolver(
            ResolverConfig::from_parts(
                None,
                Vec::new(),
                NameServerConfigGroup::from_ips_clear(&[dns_server.ip()], dns_server.port()),
            ),
            ResolverOpts {
                timeout,
                ..Default::default()
            },
        )
        .await
        .expect("failed to create resolver");

        DnsClient { resolver }
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
