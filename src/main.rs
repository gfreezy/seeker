use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info};
use shadowsocks::crypto::CipherType;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::socks5::Address::SocketAddress;
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite};
use shadowsocks::{ServerAddr, ServerConfig};
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpEndpoint;
use tokio::prelude::future::lazy;
use tokio::prelude::{AsyncRead, Future, Stream};
use tokio::runtime::current_thread::{run, spawn};
use trust_dns_server::authority::Authority;

use crate::dns_server::server::run_dns_server;
use crate::ssclient::SSClient;
use crate::tun::socket::TunSocket;
use crate::tun::{bg_send, listen};

mod dns_server;
mod ssclient;
mod tun;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    better_panic::install();

    let mut args = pico_args::Arguments::from_env();
    let debug = args.contains("-d");
    let local = args.contains("--local");
    let _name: Option<String> = args.value_from_str("--tun")?;

    let (server_addr, method) = if local {
        ("127.0.0.1", CipherType::ChaCha20Ietf)
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
                spawn(lazy(move || -> Box<dyn Future<Item = (), Error = ()>> {
                    match socket {
                        TunSocket::Tcp(socket) => {
                            let remote_addr = socket.local_addr();
                            let remote_ip = remote_addr.ip().to_string();
                            Box::new(
                                authority
                                    .lookup_host(remote_ip)
                                    .and_then(move |domain| {
                                        debug!(
                                            "send remote addr to ss server: {} {}",
                                            &domain,
                                            remote_addr.port()
                                        );
                                        let addr =
                                            Address::DomainNameAddress(domain, remote_addr.port());
                                        let (reader, writer) = socket.split();
                                        client.handle_connect((reader, writer), addr)
                                    })
                                    .map_err(|e| {
                                        error!("handle_connect error: {}", e);
                                        ()
                                    }),
                            )
                            //                            let addr = match remote_addr.ip().to_string().as_str() {
                            //                                "10.0.0.2" => Address::SocketAddress(SocketAddr::new(
                            //                                    "106.75.50.164".parse().unwrap(),
                            //                                    remote_addr.port(),
                            //                                )),
                            //                                "10.0.0.3" => Address::SocketAddress(SocketAddr::new(
                            //                                    "31.13.71.7".parse().unwrap(),
                            //                                    remote_addr.port(),
                            //                                )),
                            //                                "10.0.0.4" => Address::DomainNameAddress(
                            //                                    "twitter.com".to_string(),
                            //                                    remote_addr.port(),
                            //                                ),
                            //                                _ => Address::SocketAddress(remote_addr),
                            //                            };
                            //                            debug!("send remote addr to ss server: {}", &addr);
                            //                            let (reader, writer) = socket.split();
                            //                            Box::new(client.handle_connect((reader, writer), addr).map_err(
                            //                                |e| {
                            //                                    error!("handle_connect error: {}", e);
                            //                                    ()
                            //                                },
                            //                            ))
                        }
                        TunSocket::Udp(socket) => {
                            let buf = vec![0; 1000];
                            Box::new(
                                socket
                                    .recv_dgram(buf)
                                    .and_then(|(socket, mut buf, size, addr)| {
                                        buf.truncate(size);
                                        socket.send_dgram(buf, addr)
                                    })
                                    .map(|_| ())
                                    .map_err(|_| ()),
                            )
                        }
                    }
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
