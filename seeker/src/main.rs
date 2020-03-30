// mod client;
//mod signal;
mod connection;
mod logger;
mod proxy_client;

use std::error::Error;

use crate::logger::setup_logger;
use crate::proxy_client::ProxyClient;
use async_std::task::block_on;
use clap::{App, Arg};
use config::Config;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use sysconfig::{DNSSetup, IpForward};

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
    let uid = matches
        .value_of("user_id")
        .map(|uid| uid.parse::<u16>().unwrap());
    let log_path = matches.value_of("log");

    setup_logger(log_path)?;

    let mut config = Config::from_config_file(path)?;

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::SIGINT, Arc::clone(&term))?;
    signal_hook::flag::register(signal_hook::SIGTERM, Arc::clone(&term))?;

    let _dns_setup = DNSSetup::new();
    let _ip_forward = if config.gateway_mode {
        // In gateway mode, dns server need be accessible from the network.
        config.dns_listen = "0.0.0.0:53".to_string();
        Some(IpForward::new())
    } else {
        None
    };

    block_on(async {
        let client = ProxyClient::new(config, uid, term.clone()).await;
        client.run().await;
    });

    println!("Stop server. Bye bye...");
    Ok(())
}
