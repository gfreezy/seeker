use crate::dns_server::authority::LocalAuthority;
use log::debug;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use trust_dns::rr::Name;
use trust_dns_resolver::AsyncResolver;
use trust_dns_server::authority::Catalog;
use trust_dns_server::ServerFuture;

pub fn run_dns_server(
    addr: &SocketAddr,
    start_ip: Ipv4Addr,
    async_resolver: AsyncResolver,
) -> (ServerFuture<Catalog>, LocalAuthority) {
    debug!("run dns server");
    let udpsocket = UdpSocket::bind(addr).unwrap();
    let local_authority = LocalAuthority::new("dns.db", start_ip, async_resolver);
    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), Box::new(local_authority.clone()));
    let server = ServerFuture::new(catalog);
    server.register_socket(udpsocket);
    (server, local_authority)
}
