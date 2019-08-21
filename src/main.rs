#![recursion_limit = "128"]

mod config;
mod dns_server;
mod ssclient;
mod tun;

use std::error::Error;
use std::sync::Arc;

use log::{error, info};
use shadowsocks::relay::socks5::Address;
use tokio::prelude::future::lazy;
use tokio::prelude::{AsyncRead, Future, Stream};
use tokio::runtime::current_thread::{run, spawn};

use shadowsocks::relay::boxed_future;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::AsyncResolver;

use config::Config;
use dns_server::server::run_dns_server;
use pico_args::Arguments;
use ssclient::SSClient;
use tun::socket::TunSocket;
use tun::Tun;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    better_panic::install();

    let mut args = Arguments::from_env();
    let path: String = args.value_from_str("--config")?.unwrap();

    let config = Config::from_config_file(&path);

    Tun::setup(config.tun_name.clone(), config.tun_ip, config.tun_cidr);

    run(lazy(move || {
        let dns = config.dns_server;
        let nameserver_config_group =
            NameServerConfigGroup::from_ips_clear(&[dns.ip()], dns.port());
        let resolver_config = ResolverConfig::from_parts(None, vec![], nameserver_config_group);
        let options = ResolverOpts::default();
        let (resolver, background) = AsyncResolver::new(resolver_config, options);
        spawn(background);
        let dns_listen = "0.0.0.0:53".parse().unwrap();
        let (_, authority) = run_dns_server(
            &dns_listen,
            config.dns_start_ip,
            resolver.clone(),
            config.rules,
        );
        let client = Arc::new(SSClient::new(config.server_config, resolver));
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
