mod client;
//mod signal;

use std::error::Error;

use crate::client::{Client, RuledClient};
use async_std::io::timeout;
use async_std::task::{block_on, spawn};
use clap::{App, Arg};
use config::{Address, Config};
use dnsserver::create_dns_server;
use futures::StreamExt;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysconfig::DNSSetup;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use tun::socket::TunSocket;
use tun::Tun;

async fn handle_connection<T: Client + Clone + Send + Sync + 'static>(
    client: T,
    config: Config,
    term: Arc<AtomicBool>,
) {
    let (dns_server, resolver) =
        create_dns_server("dns.db", "127.0.0.1:53".to_string(), config.dns_start_ip).await;
    println!("Spawn DNS server");
    spawn(dns_server.run_server());
    spawn(Tun::bg_send());

    let mut stream = Tun::listen();
    loop {
        let socket = timeout(Duration::from_secs(1), async {
            stream.next().await.transpose()
        })
        .await;
        let socket = match socket {
            Ok(Some(s)) => s,
            Ok(None) => break,
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                if term.load(Ordering::Relaxed) {
                    break;
                } else {
                    continue;
                }
            }
            Err(e) => panic!(e),
        };
        let resolver_clone = resolver.clone();
        let client_clone = client.clone();
        spawn(async move {
            let remote_addr = socket.local_addr();

            let host = resolver_clone
                .lookup_host(&remote_addr.ip().to_string())
                .await
                .map(|s| Address::DomainNameAddress(s, remote_addr.port()))
                .unwrap_or_else(|| Address::SocketAddress(remote_addr));

            match socket {
                TunSocket::Tcp(socket) => client_clone.handle_tcp(socket, host).await,
                TunSocket::Udp(socket) => client_clone.handle_udp(socket, host).await,
            }
        });
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let my_subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
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
        .arg(
            Arg::with_name("user_id")
                .short("u")
                .long("uid")
                .value_name("UID")
                .help("User id to proxy.")
                .required(false),
        )
        .get_matches();

    let path = matches.value_of("config").unwrap();
    let uid = matches.value_of("user_id").map(|uid| uid.parse().unwrap());
    let config = Config::from_config_file(path);

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::SIGINT, Arc::clone(&term))?;
    signal_hook::flag::register(signal_hook::SIGTERM, Arc::clone(&term))?;

    Tun::setup(
        config.tun_name.clone(),
        config.tun_ip,
        config.tun_cidr,
        term.clone(),
    );

    let _dns_setup = DNSSetup::new();

    block_on(async {
        let client = RuledClient::new(config.clone(), uid, term.clone()).await;

        handle_connection(client, config, term.clone()).await;
    });

    println!("Stop server. Bye bye...");
    Ok(())
}
