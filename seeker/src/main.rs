use std::error::Error;

use async_std::task::{block_on, spawn};
use clap::{App, Arg};
use config::Config;
use dnsserver::create_dns_server;
use futures::StreamExt;
use ssclient::SSClient;
use sysconfig::DNSSetup;
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

    block_on(async {
        let dns = config.dns_server;
        let dns_server_addr = (dns.ip().to_string(), dns.port());
        let (dns_server, resolver) = create_dns_server(
            "dns.db",
            dns_server_addr.clone(),
            config.dns_start_ip,
            config.rules,
        )
        .await;
        spawn(dns_server.run_server());
        let client = SSClient::new(config.server_config, dns_server_addr).await;
        spawn(Tun::bg_send());

        while let Some(socket) = Tun::listen().next().await {
            let socket = socket.expect("socket error");
            let resolver_clone = resolver.clone();
            let client_clone = client.clone();
            spawn(async move {
                let remote_addr = socket.local_addr();

                let host = resolver_clone
                    .lookup_host(&remote_addr.to_string())
                    .await
                    .unwrap_or_else(|| remote_addr.to_string());

                match socket {
                    TunSocket::Tcp(socket) => client_clone.handle_connect(socket, host).await,
                    TunSocket::Udp(socket) => client_clone.handle_packets(socket, host).await,
                }
            });
        }
    });

    Ok(())
}
