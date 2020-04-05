use config::Address;
use hermesdns::{DnsClient as _, DnsNetworkClient, DnsRecord, QueryType, TransientTtl};
use lru_time_cache::LruCache;
use parking_lot::Mutex;
use std::io::{Error, ErrorKind, Result};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct DnsClient {
    dns_server: String,
    dns_port: u16,
    client: DnsNetworkClient,
    cache: Arc<Mutex<LruCache<String, IpAddr>>>,
}

impl DnsClient {
    pub async fn new(dns_server: SocketAddr, timeout: Duration) -> Self {
        let client = DnsNetworkClient::new(0, timeout).await;
        DnsClient {
            dns_server: dns_server.ip().to_string(),
            dns_port: dns_server.port(),
            client,
            cache: Arc::new(Mutex::new(LruCache::with_capacity_and_auto_expiration(100))),
        }
    }

    pub async fn lookup(&self, domain: &str) -> Result<IpAddr> {
        if let Some(addr) = self.cache.lock().get(domain) {
            return Ok(*addr);
        }

        let packet = self
            .client
            .send_query(
                domain,
                QueryType::A,
                (self.dns_server.as_ref(), self.dns_port),
                true,
            )
            .await?;

        for answer in &packet.answers {
            if let DnsRecord::A {
                domain,
                addr: ip,
                ttl: TransientTtl(ttl),
            } = answer
            {
                let _ = self.cache.lock().insert_with_ttl(
                    domain.to_string(),
                    IpAddr::V4(*ip),
                    Duration::from_secs(*ttl as u64),
                );
                return Ok(IpAddr::V4(*ip));
            };
        }

        Err(Error::new(
            ErrorKind::NotFound,
            format!("{} not resolved", domain),
        ))
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
