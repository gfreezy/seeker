use crate::resolver::RuleBasedDnsResolver;
use config::rule::ProxyRules;
use hermesdns::DnsUdpServer;
use std::net::Ipv4Addr;
use std::path::Path;

pub async fn run_dns_server<P: AsRef<Path>>(
    path: P,
    server: (String, u16),
    start_ip: Ipv4Addr,
    rules: ProxyRules,
) {
    let n = u32::from_be_bytes(start_ip.octets());
    let resolver = RuleBasedDnsResolver::new(path, server, rules, n).await;
    let server = DnsUdpServer::new(Box::new(resolver)).await;
    server.run_server().await;
}
