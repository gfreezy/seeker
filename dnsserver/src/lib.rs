pub mod resolver;

use config::rule::ProxyRules;
use hermesdns::DnsUdpServer;
use resolver::RuleBasedDnsResolver;
use std::net::Ipv4Addr;
use std::path::Path;

pub async fn create_dns_server<P: AsRef<Path>>(
    path: P,
    server: (String, u16),
    start_ip: Ipv4Addr,
    rules: ProxyRules,
) -> (DnsUdpServer, RuleBasedDnsResolver) {
    let n = u32::from_be_bytes(start_ip.octets());
    let resolver = RuleBasedDnsResolver::new(path, server, rules, n).await;
    let server = DnsUdpServer::new(53, Box::new(resolver.clone())).await;
    (server, resolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;
    use config::rule::{Action, Rule};
    use hermesdns::{DnsClient, DnsNetworkClient, QueryType};

    async fn get_ip(client: &DnsNetworkClient, host: &str) -> Option<String> {
        let resp = client
            .send_query(host, QueryType::A, ("127.0.0.1", 53), true)
            .await
            .unwrap();
        resp.get_random_a()
    }

    #[test]
    fn test_resolve_ip() {
        let dir = tempfile::tempdir().unwrap();
        let server = ("114.114.114.114".to_string(), 53);
        let rules = ProxyRules::new(vec![
            Rule::Domain("baidu.com".to_string(), Action::Proxy),
            Rule::Domain("to-deny.com".to_string(), Action::Reject),
            Rule::DomainKeyword("ali".to_string(), Action::Proxy),
        ]);
        task::block_on(async {
            let (server, resolver) =
                create_dns_server(dir.path(), server, "10.0.0.1".parse().unwrap(), rules).await;
            task::spawn(server.run_server());
            let client = DnsNetworkClient::new(0).await;
            assert_eq!(
                get_ip(&client, "baidu.com").await,
                Some("10.0.0.1".to_string())
            );
            assert_eq!(get_ip(&client, "to-deny.com").await, None);
            assert_eq!(
                get_ip(&client, "to.aliyun.com").await,
                Some("10.0.0.2".to_string())
            );
            assert_eq!(
                resolver.lookup_host("10.0.0.2").await,
                Some("to.aliyun.com".to_string())
            )
        });
    }
}
