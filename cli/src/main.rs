use std::error::Error;
use std::sync::Arc;

use clap::{App, Arg};
use config::Config;
use dns_server::server::run_dns_server;
use shadowsocks::relay::boxed_future;
use shadowsocks::relay::socks5::Address;
use ssclient::SSClient;
use sysconfig::DNSSetup;
use tokio::prelude::future::lazy;
use tokio::prelude::{AsyncRead, Future, Stream};
use tokio::runtime::current_thread::{spawn, Runtime};
use tracing::{debug_span, error, info, info_span};
use tracing_futures::Instrument;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::AsyncResolver;
use tun::socket::TunSocket;
use tun::Tun;

fn main() -> Result<(), Box<dyn Error>> {
    let my_subscriber = tracing_fmt::FmtSubscriber::new();
    tracing::subscriber::set_global_default(my_subscriber).expect("setting tracing default failed");

    let matches = App::new("Seeker")
        .version("0.0.1")
        .author("gfreezy <gfreezy@gmail.com>")
        .about("Tun to Shadowsockets proxy. https://github.com/gfreezy/seeker")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets config file. Sample config at https://github.com/gfreezy/seeker/blob/master/sample_config.yml")
                .required(true),
        )
        .get_matches();

    let path = matches.value_of("config").unwrap();
    let config = Config::from_config_file(path);

    Tun::setup(config.tun_name.clone(), config.tun_ip, config.tun_cidr);

    let _dns_setup = DNSSetup::new();
    let mut runtime = Runtime::new().unwrap();
    runtime.spawn(lazy(move || {
        let dns = config.dns_server;
        let nameserver_config_group =
            NameServerConfigGroup::from_ips_clear(&[dns.ip()], dns.port());
        let resolver_config = ResolverConfig::from_parts(None, vec![], nameserver_config_group);
        let mut options = ResolverOpts::default();
        options.cache_size = 1024;
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
        spawn(
            Tun::bg_send()
                .instrument(debug_span!("main::bg_send"))
                .map_err(|_| ()),
        );

        Tun::listen()
            .for_each(move |socket| {
                info!("new socket accepted: {}", socket);
                let client = client.clone();
                let authority = authority.clone();
                let handle = socket.handle();

                spawn(
                    lazy(move || {
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
                                info!("lookup host: {}", addr);
                                futures::finished(addr)
                            })
                            .instrument(info_span!("main::lookup_host"))
                            .and_then(move |addr| match socket {
                                TunSocket::Tcp(socket) => {
                                    let (reader, writer) = socket.split();
                                    boxed_future(
                                        client
                                            .handle_connect((reader, writer), addr)
                                            .instrument(info_span!("main::handle_connect_tcp")),
                                    )
                                }
                                TunSocket::Udp(socket) => boxed_future(
                                    client
                                        .handle_packets(socket, addr)
                                        .instrument(debug_span!("main::handle_packets_udp")),
                                ),
                            })
                            .map_err(|_| ())
                    })
                    .instrument(info_span!(
                        "main::new_connection",
                        socket = %handle
                    )),
                );
                Ok(())
            })
            .instrument(debug_span!("main::listen"))
            .map_err(|e| {
                error!("for_each error: {}", e);
            })
    }));

    let stream = tokio_signal::ctrl_c().flatten_stream();
    let _ = runtime.block_on(stream.into_future()).ok().unwrap();
    Ok(())
}
