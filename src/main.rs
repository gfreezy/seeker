#![recursion_limit = "128"]
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use shadowsocks::crypto::CipherType;
use shadowsocks::relay::socks5::Address;
use shadowsocks::{ServerAddr, ServerConfig};
use tokio::prelude::future::lazy;
use tokio::prelude::{AsyncRead, Future, Stream};
use tokio::runtime::current_thread::{run, spawn};

use crate::dns_server::server::run_dns_server;
use crate::ssclient::SSClient;
use crate::tun::socket::TunSocket;
use crate::tun::Tun;
use shadowsocks::relay::boxed_future;
use smoltcp::wire::{IpAddress, IpCidr};

mod dns_server;
mod ssclient;
mod tun;

struct Config {
    server_config: Arc<ServerConfig>,
    dns_start_ip: Ipv4Addr,
    dns_server: SocketAddr,
    tun_name: String,
    tun_ip: IpAddress,
    tun_cidr: IpCidr,
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    better_panic::install();

    let mut args = pico_args::Arguments::from_env();
    let local = args.contains("--local");
    let _name: Option<String> = args.value_from_str("--tun")?;

    let (server_addr, method) = if local {
        ("127.0.0.1", CipherType::Plain)
    } else {
        ("sg1.edge.bgp.app", CipherType::ChaCha20Ietf)
    };
    let srv_cfg = ServerConfig::new(
        ServerAddr::DomainName(server_addr.to_string(), 14187),
        "rixCloud".to_string(),
        method,
        Some(Duration::from_secs(5)),
        None,
    );
    let config = Config {
        server_config: Arc::new(srv_cfg),
        dns_start_ip: Ipv4Addr::new(10, 0, 0, 10),
        dns_server: "223.5.5.5:53".parse().unwrap(),
        tun_name: "utun4".to_string(),
        tun_ip: IpAddress::v4(10, 0, 0, 1),
        tun_cidr: IpCidr::new(IpAddress::v4(10, 0, 0, 0), 24),
    };

    Tun::setup(config.tun_name.clone(), config.tun_ip, config.tun_cidr);

    run(lazy(move || {
        let dns_listen = "0.0.0.0:53".parse().unwrap();
        let (_, authority) = run_dns_server(&dns_listen, config.dns_start_ip);
        let client = Arc::new(SSClient::new(config.server_config, &config.dns_server));
        spawn(Tun::bg_send().map_err(|_| ()));

        Tun::listen()
            .for_each(move |socket| {
                info!("new socket accepted: {}", socket);
                let client = client.clone();
                let authority = authority.clone();

                spawn(lazy(move || {
                    let remote_addr = socket.local_addr();
                    let remote_ip = remote_addr.ip().to_string();
                    let remote_port = remote_addr.port();

                    authority
                        .lookup_host(remote_ip.clone())
                        .then(move |ret| {
                            let addr = match ret {
                                Ok(d) => Address::DomainNameAddress(d, remote_port),
                                Err(_) => Address::SocketAddress(remote_addr),
                            };
                            info!("send remote addr to ss server, addr: {}", addr,);
                            futures::finished(addr)
                        })
                        .and_then(move |addr| match socket {
                            TunSocket::Tcp(socket) => {
                                let addr1 = addr.clone();
                                let addr2 = addr.clone();
                                let (reader, writer) = socket.split();
                                boxed_future(
                                    client
                                        .handle_connect((reader, writer), addr)
                                        .map(move |r| {
                                            info!("handle connect ok, addr: {}", addr1);
                                            r
                                        })
                                        .map_err(move |e| {
                                            error!("handle connect error: {}, addr: {}", e, addr2);
                                            e
                                        }),
                                )
                            }
                            TunSocket::Udp(socket) => {
                                boxed_future(client.handle_packets(socket, addr))
                            }
                        })
                        .map_err(|_| ())
                }));
                Ok(())
            })
            .map_err(|e| {
                error!("for_each error: {}", e);
                ()
            })
    }));

    Ok(())
}
