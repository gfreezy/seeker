pub mod resolver;

use hermesdns::DnsUdpServer;
use resolver::RuleBasedDnsResolver;
use std::net::Ipv4Addr;
use std::path::Path;

pub async fn create_dns_server<P: AsRef<Path>>(
    path: P,
    listen: String,
    start_ip: Ipv4Addr,
) -> (DnsUdpServer, RuleBasedDnsResolver) {
    let n = u32::from_be_bytes(start_ip.octets());
    let resolver = RuleBasedDnsResolver::new(path, n).await;
    let server = DnsUdpServer::new(listen, Box::new(resolver.clone())).await;
    (server, resolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::io;
    use async_std::task;
    use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
    use std::time::Duration;

    const LOCAL_UDP_PORT: u16 = 53;
    async fn get_ip(client: &DnsNetworkClient, host: &str) -> Option<String> {
        let resp = io::timeout(
            Duration::from_secs(5),
            client.send_query(host, QueryType::A, ("127.0.0.1", LOCAL_UDP_PORT), true),
        )
        .await
        .unwrap();
        resp.get_random_a()
    }

    #[test]
    fn test_resolve_ip() {
        let dir = tempfile::tempdir().unwrap();
        task::block_on(async {
            let (server, resolver) = create_dns_server(
                dir.path(),
                format!("127.0.0.1:{}", LOCAL_UDP_PORT),
                "10.0.0.1".parse().unwrap(),
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
                resolver.lookup_host("10.0.0.2").await,
                Some("to.aliyun.com".to_string())
            )
        });
    }
}
