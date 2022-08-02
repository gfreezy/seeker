pub mod resolver;

use async_std_resolver::AsyncStdResolver;
use config::rule::ProxyRules;
use hermesdns::DnsUdpServer;
use resolver::RuleBasedDnsResolver;
use std::net::Ipv4Addr;
use std::path::Path;

pub async fn create_dns_server<P: AsRef<Path>>(
    path: P,
    listen: String,
    start_ip: Ipv4Addr,
    bypass_direct: bool,
    rules: ProxyRules,
    async_resolver: AsyncStdResolver,
) -> (DnsUdpServer, RuleBasedDnsResolver) {
    let n = u32::from_be_bytes(start_ip.octets());
    let resolver = RuleBasedDnsResolver::new(path, n, bypass_direct, rules, async_resolver).await;
    let server = DnsUdpServer::new(listen, Box::new(resolver.clone())).await;
    (server, resolver)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use async_std::io;
    use async_std::task;
    use async_std_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
    use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
    use std::time::Duration;

    const LOCAL_UDP_PORT: u16 = 1153;
    async fn get_ip(client: &DnsNetworkClient, host: &str) -> Option<String> {
        let resp = io::timeout(
            Duration::from_secs(5),
            client.send_query(host, QueryType::A, ("127.0.0.1", LOCAL_UDP_PORT), true),
        )
        .await
        .unwrap();
        resp.get_random_a()
    }

    pub(crate) async fn new_resolver(ip: String, port: u16) -> AsyncStdResolver {
        let name_servers =
            NameServerConfigGroup::from_ips_clear(&[ip.parse().unwrap()], port, false);

        // Construct a new Resolver with default configuration options
        async_std_resolver::resolver(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            ResolverOpts::default(),
        )
        .await
        .expect("failed to create resolver")
    }

    #[test]
    fn test_resolve_ip() {
        let dir = tempfile::tempdir().unwrap();
        let dns = std::env::var("DNS").unwrap_or_else(|_| "223.5.5.5".to_string());
        task::block_on(async {
            let resolver = new_resolver(dns, 53).await;
            let (server, resolver) = create_dns_server(
                dir.path(),
                format!("0.0.0.0:{}", LOCAL_UDP_PORT),
                "10.0.0.1".parse().unwrap(),
                true,
                ProxyRules::new(vec![]),
                resolver,
            )
            .await;
            task::spawn(server.run_server());
            task::sleep(Duration::from_secs(1)).await;
            let client = DnsNetworkClient::new(0, Duration::from_secs(3)).await;
            assert_eq!(
                get_ip(&client, "baidu.com").await,
                Some("10.0.0.1".to_string())
            );
            assert_eq!(
                get_ip(&client, "to.aliyun.com").await,
                Some("10.0.0.2".to_string())
            );
            assert_eq!(
                resolver.lookup_host("10.0.0.2"),
                Some("to.aliyun.com".to_string())
            )
        });
    }
}
