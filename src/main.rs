#![recursion_limit = "128"]
use std::error::Error;
use std::net::Ipv4Addr;
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
use crate::tun::{bg_send, listen};
use shadowsocks::relay::boxed_future;

mod dns_server;
mod ssclient;
mod tun;

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
        Some(Duration::from_secs(30)),
        None,
    );

    run(lazy(move || {
        let addr = "127.0.0.1:53".parse().unwrap();
        let (_, authority) = run_dns_server(&addr, Ipv4Addr::new(10, 0, 0, 10));
        let client = Arc::new(SSClient::new(srv_cfg));
        spawn(bg_send().map_err(|_| ()));

        listen()
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
