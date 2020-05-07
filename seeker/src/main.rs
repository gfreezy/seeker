#[macro_use]
mod macros;
mod dns_client;
mod logger;
mod proxy_client;
mod proxy_tcp_stream;
mod proxy_udp_socket;
mod server_chooser;

use std::error::Error;

use crate::logger::setup_logger;
use crate::proxy_client::ProxyClient;
use async_signals::Signals;
use async_std::prelude::{FutureExt, StreamExt};
use async_std::task::block_on;
use clap::{App, Arg};
use config::Config;
use sysconfig::{set_rlimit_no_file, DNSSetup, IpForward};

fn main() -> Result<(), Box<dyn Error>> {
    let version = env!("CARGO_PKG_VERSION");
    let matches = App::new("Seeker")
        .version(version)
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
        .arg(
            Arg::with_name("user_id")
                .short("u")
                .long("uid")
                .value_name("UID")
                .help("User id to proxy.")
                .required(false),
        )
        .arg(
            Arg::with_name("log")
                .short("l")
                .long("log")
                .value_name("PATH")
                .help("Log file.")
                .required(false),
        )
        .get_matches();

    let path = matches.value_of("config").unwrap();
    let uid = matches.value_of("user_id").map(|uid| uid.parse().unwrap());
    let log_path = matches.value_of("log");

    setup_logger(log_path)?;

    let mut config = Config::from_config_file(path)?;

    let mut signals = Signals::new(vec![libc::SIGINT, libc::SIGTERM]).unwrap();

    set_rlimit_no_file(10240)?;

    let _dns_setup = DNSSetup::new(config.dns_server.ip().to_string());
    let _ip_forward = if config.gateway_mode {
        // In gateway mode, dns server need be accessible from the network.
        config.dns_listen = "0.0.0.0:53".to_string();
        Some(IpForward::new())
    } else {
        None
    };

    block_on(async {
        let client = ProxyClient::new(config, uid).await;
        client
            .run()
            .race(async {
                signals.next().await.unwrap();
            })
            .await;
    });

    println!("Stop server. Bye bye...");
    Ok(())
}
