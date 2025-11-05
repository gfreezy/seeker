pub mod resolver;

use config::rule::ProxyRules;
use hermesdns::DnsUdpServer;
use hickory_resolver::TokioResolver;
use resolver::RuleBasedDnsResolver;

pub async fn create_dns_server(
    listens: Vec<String>,
    bypass_direct: bool,
    rules: ProxyRules,
    async_resolver: TokioResolver,
) -> (DnsUdpServer, RuleBasedDnsResolver) {
    let resolver = RuleBasedDnsResolver::new(bypass_direct, rules, async_resolver).await;
    let server = DnsUdpServer::new(listens, Box::new(resolver.clone())).await;
    (server, resolver)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
    use hickory_proto::xfer::Protocol;
    use hickory_resolver::config::{
        NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
    };
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::TokioResolver;
    use std::time::Duration;
    use tokio::time;

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

    pub(crate) async fn new_resolver(ip: String, port: u16) -> TokioResolver {
        let mut name_servers = NameServerConfigGroup::new();
        let socket_addr = format!("{ip}:{port}").parse().unwrap();
        name_servers.push(NameServerConfig::new(socket_addr, Protocol::Udp));

        // Construct a new Resolver with default configuration options
        TokioResolver::builder_with_config(
            ResolverConfig::from_parts(None, Vec::new(), name_servers),
            TokioConnectionProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build()
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
