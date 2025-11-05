pub mod resolver;

use hickory_resolver::TokioAsyncResolver;
use config::rule::ProxyRules;
use hermesdns::DnsUdpServer;
use resolver::RuleBasedDnsResolver;

pub async fn create_dns_server(
    listens: Vec<String>,
    bypass_direct: bool,
    rules: ProxyRules,
    async_resolver: TokioAsyncResolver,
) -> (DnsUdpServer, RuleBasedDnsResolver) {
    let resolver = RuleBasedDnsResolver::new(bypass_direct, rules, async_resolver).await;
    let server = DnsUdpServer::new(listens, Box::new(resolver.clone())).await;
    (server, resolver)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::time;
    use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
    use std::time::Duration;

    const LOCAL_UDP_PORT: u16 = 6153;
    async fn get_ip(client: &DnsNetworkClient, host: &str) -> Option<String> {
        let _a = client.get_failed_count();
        let resp = time::timeout(
            Duration::from_secs(10),
            client.send_query(host, QueryType::A, ("127.0.0.1", LOCAL_UDP_PORT), true),
        )
        .await
        .unwrap();
        resp.ok().and_then(|p| p.get_random_a())
    }

    pub(crate) async fn new_resolver(ip: String, port: u16) -> TokioAsyncResolver {
        let name_servers =
            NameServerConfigGroup::from_ips_clear(&[ip.parse().unwrap()], port, false);

        // Construct a new Resolver with default configuration options
        TokioAsyncResolver::tokio(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            ResolverOpts::default(),
        )
    }

    #[test]
    fn test_resolve_ip() {
        store::Store::setup_global_for_test();
        let dns = std::env::var("DNS").unwrap_or_else(|_| "114.114.114.114".to_string());
        tokio_test::block_on(async {
            let resolver = new_resolver(dns, 53).await;
            let (server, resolver) = create_dns_server(
                vec![format!("0.0.0.0:{LOCAL_UDP_PORT}")],
                false,
                ProxyRules::new(vec![], None),
                resolver,
            )
            .await;
            tokio::task::spawn(server.run_server());
            tokio::time::sleep(Duration::from_secs(3)).await;
            let client = DnsNetworkClient::new(0, Duration::from_secs(50)).await;
            let ali_ip = get_ip(&client, "google.com").await;
            assert!(ali_ip.is_some());
            let baidu_ip = get_ip(&client, "baidu.com").await;
            assert!(baidu_ip.is_some());

            assert_eq!(
                resolver.lookup_host(&baidu_ip.unwrap()),
                Some("baidu.com".to_string())
            );
            assert_eq!(
                resolver.lookup_host(&ali_ip.unwrap()),
                Some("google.com".to_string())
            )
        });
    }
}
