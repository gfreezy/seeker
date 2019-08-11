use crate::dns_server::authority::LocalAuthority;
use log::debug;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::executor::current_thread::spawn;
use tokio::net::UdpSocket;
use trust_dns::rr::Name;
use trust_dns_resolver::config::NameServerConfigGroup;
use trust_dns_server::authority::{Catalog, ZoneType};
use trust_dns_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use trust_dns_server::ServerFuture;

pub fn run_dns_server(
    addr: &SocketAddr,
    start_ip: Ipv4Addr,
) -> (ServerFuture<Catalog>, LocalAuthority) {
    debug!("run dns server");
    let udpsocket = UdpSocket::bind(addr).unwrap();
    let local_authority = LocalAuthority::new(start_ip);
    //    let config = ForwardConfig {
    //        name_servers: NameServerConfigGroup::from_ips_clear(
    //            &["114.114.114.114".parse().unwrap()],
    //            53,
    //        ),
    //        options: None,
    //    };
    //    let (foward_authority, bg) =
    //        ForwardAuthority::try_from_config(Name::root().into(), ZoneType::Forward, &config).unwrap();
    //    spawn(bg);
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
