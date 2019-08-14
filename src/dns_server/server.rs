use crate::dns_server::authority::LocalAuthority;
use log::debug;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use trust_dns::rr::Name;
use trust_dns_server::authority::Catalog;
use trust_dns_server::ServerFuture;

pub fn run_dns_server(
    addr: &SocketAddr,
    start_ip: Ipv4Addr,
) -> (ServerFuture<Catalog>, LocalAuthority) {
    debug!("run dns server");
    let udpsocket = UdpSocket::bind(addr).unwrap();
    let local_authority = LocalAuthority::new("dns.db", start_ip);
    let mut catalog = Catalog::new();
    catalog.upsert(Name::root().into(), Box::new(local_authority.clone()));
    //    catalog.upsert(Name::root().into(), Box::new(foward_authority));
    let server = ServerFuture::new(catalog);
    server.register_socket(udpsocket);
    (server, local_authority)
}

#[cfg(test)]
mod tests {
    use crate::dns_server::server::run_dns_server;
    use log::debug;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::prelude::future::finished;
    use tokio::prelude::future::lazy;
    use tokio::runtime::current_thread::run;
    use trust_dns::client::ClientFuture;
    use trust_dns::proto::udp::UdpClientStream;

    #[test]
    fn test_dns_udp_server() {
        let _ = env_logger::builder().is_test(true).try_init();
        println!("start test");
        let port = 53;
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port);
        run(lazy(move || {
            run_dns_server(&addr, Ipv4Addr::new(10, 0, 0, 3));
            Ok(())
        }))
    }
}
