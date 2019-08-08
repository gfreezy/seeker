mod ssclient;
mod tun;

use crate::ssclient::SSClient;
use crate::tun::socket::TunSocket;
use crate::tun::{bg_send, listen};
use log::{debug, error, info};
use shadowsocks::crypto::CipherType;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::socks5::Address::SocketAddress;
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite};
use shadowsocks::{ServerAddr, ServerConfig};
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpEndpoint;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::future::lazy;
use tokio::prelude::{AsyncRead, Future, Stream};
use tokio::runtime::current_thread::{run, spawn};

fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    better_panic::install();

    let mut args = pico_args::Arguments::from_env();
    let debug = args.contains("-d");
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

    run(lazy(move || {
        let client = Arc::new(SSClient::new(srv_cfg));
        spawn(bg_send().map_err(|_| ()));

        listen()
            .for_each(move |socket| {
                info!("new socket accepted: {}", socket);
                let client = client.clone();
                spawn(lazy(move || -> Box<dyn Future<Item = (), Error = ()>> {
                    match socket {
                        TunSocket::Tcp(socket) => {
                            if !debug {
                                let remote_addr = socket.local_addr();
                                let addr = match remote_addr.ip().to_string().as_str() {
                                    "10.0.0.2" => Address::SocketAddress(SocketAddr::new(
                                        "106.75.50.164".parse().unwrap(),
                                        remote_addr.port(),
                                    )),
                                    "10.0.0.3" => Address::SocketAddress(SocketAddr::new(
                                        "31.13.71.7".parse().unwrap(),
                                        remote_addr.port(),
                                    )),
                                    "10.0.0.4" => Address::DomainNameAddress(
                                        "twitter.com".to_string(),
                                        remote_addr.port(),
                                    ),
                                    _ => Address::SocketAddress(remote_addr),
                                };
                                debug!("send remote addr to ss server: {}", &addr);
                                let (reader, writer) = socket.split();
                                Box::new(client.handle_connect((reader, writer), addr).map_err(
                                    |e| {
                                        error!("handle_connect error: {}", e);
                                        ()
                                    },
                                ))
                            } else {
                                let (reader, writer) = socket.split();
                                Box::new(
                                    tokio::io::copy(reader, writer).map(|_| ()).map_err(|_| ()),
                                )
                            }
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
            .map_err(|_| ())
    }));

    Ok(())
}
