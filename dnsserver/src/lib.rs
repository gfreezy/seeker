pub mod resolver;

use async_std_resolver::AsyncStdResolver;
use config::rule::ProxyRules;
use hermesdns::DnsUdpServer;
use resolver::RuleBasedDnsResolver;

pub async fn create_dns_server(
    listen: String,
    bypass_direct: bool,
    rules: ProxyRules,
    async_resolver: AsyncStdResolver,
) -> (DnsUdpServer, RuleBasedDnsResolver) {
    let resolver = RuleBasedDnsResolver::new(bypass_direct, rules, async_resolver).await;
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
    use store::Store;

    const LOCAL_UDP_PORT: u16 = 6153;
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
        let _ = Store::try_setup_global(dir.path().join("db.sqlite"), "10.0.0.1".parse().unwrap());
        task::block_on(async {
            let resolver = new_resolver(dns, 53).await;
            let (server, resolver) = create_dns_server(
                format!("0.0.0.0:{LOCAL_UDP_PORT}"),
                false,
                ProxyRules::new(vec![]),
                resolver,
            )
            .await;
            task::spawn(server.run_server());
            task::sleep(Duration::from_secs(1)).await;
            let client = DnsNetworkClient::new(0, Duration::from_secs(3)).await;
            let baidu_ip = get_ip(&client, "baidu.com").await;
            assert!(baidu_ip.is_some());
            let ali_ip = get_ip(&client, "aliyun.com").await;
            assert!(ali_ip.is_some());
            assert_eq!(
                resolver.lookup_host(&baidu_ip.unwrap()),
                Some("baidu.com".to_string())
            );
            assert_eq!(
                resolver.lookup_host(&ali_ip.unwrap()),
                Some("aliyun.com".to_string())
            )
        });
    }
}
