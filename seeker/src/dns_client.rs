use async_std_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use async_std_resolver::{AsyncStdResolver, resolver};
use config::{Address, DnsServerAddr};
use std::io::{Error, ErrorKind, Result};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone)]
pub struct DnsClient {
    resolver: AsyncStdResolver,
}

impl DnsClient {
    pub async fn new(dns_servers: &[DnsServerAddr], timeout: Duration) -> Self {
        let mut name_servers = NameServerConfigGroup::with_capacity(dns_servers.len());

        for addr in dns_servers {
            match addr {
                DnsServerAddr::UdpSocketAddr(addr) => {
                    let udp = NameServerConfig {
                        socket_addr: *addr,
                        protocol: Protocol::Udp,
                        tls_dns_name: None,
                        trust_negative_responses: false,
                        bind_addr: None,
                    };
                    name_servers.push(udp);
                }
                DnsServerAddr::TcpSocketAddr(addr) => {
                    if !["tcp", "tls"].contains(&addr.scheme()) {
                        panic!("Invalid dns server address")
                    }
                    let tcp = NameServerConfig {
                        socket_addr: format!("{}:{}", addr.host().unwrap(), addr.port().unwrap())
                            .parse()
                            .unwrap(),
                        protocol: Protocol::Tcp,
                        tls_dns_name: None,
                        trust_negative_responses: false,
                        bind_addr: None,
                    };
                    name_servers.push(tcp);
                }
            }
        }

        let num_concurrent_reqs = name_servers.len();

        // Construct a new Resolver with default configuration options
        let resolver = resolver(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            {
                let mut opts = ResolverOpts::default();
                opts.timeout = timeout;
                opts.num_concurrent_reqs = num_concurrent_reqs;
                opts
            },
        )
        .await;

        DnsClient { resolver }
    }

    pub fn resolver(&self) -> AsyncStdResolver {
        self.resolver.clone()
    }
    pub async fn lookup(&self, domain: &str) -> Result<IpAddr> {
        let response =
            self.resolver.lookup_ip(domain).await.map_err(|e| {
                Error::new(ErrorKind::NotFound, format!("{domain} not resolved.\n{e}"))
            })?;
        response.iter().next().ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("no response returned for {domain}."),
            )
        })
    }

    #[tracing::instrument(skip(self))]
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
