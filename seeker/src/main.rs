mod client;
//mod signal;

use std::error::Error;

use crate::client::ruled_client::RuledClient;
use crate::client::Client;
use async_std::io::timeout;
use async_std::prelude::*;
use async_std::task::{block_on, spawn};
use clap::{App, Arg};
use config::{Address, Config};
use dnsserver::create_dns_server;
use file_rotate::{FileRotate, RotationMode};
use std::io;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use sysconfig::{DNSSetup, IpForward};
use tracing::{trace, trace_span};
use tracing_futures::Instrument;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use tun::socket::TunSocket;
use tun::Tun;

async fn handle_connection<T: Client + Clone + Send + Sync + 'static>(
    client: T,
    config: Config,
    term: Arc<AtomicBool>,
) {
    let (dns_server, resolver) =
        create_dns_server("dns.db", config.dns_listen.clone(), config.dns_start_ip).await;
    println!("Spawn DNS server");
    spawn(
        dns_server
            .run_server()
            .instrument(trace_span!("dns_server.run_server")),
    );
    spawn(Tun::bg_send().instrument(trace_span!("Tun::bg_send")));

    let mut stream = Tun::listen();
    loop {
        let socket = timeout(Duration::from_secs(1), async {
            stream.next().await.transpose()
        })
        .await;
        let socket: TunSocket = match socket {
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
        let remote_addr = socket.local_addr();

        spawn(
            async move {
                let ip = remote_addr.ip().to_string();
                let host = resolver_clone
                    .lookup_host(&ip)
                    .instrument(trace_span!("lookup host", ip = ?ip))
                    .await
                    .map(|s| Address::DomainNameAddress(s, remote_addr.port()))
                    .unwrap_or_else(|| Address::SocketAddress(remote_addr));

                trace!(ip = ?ip, host = ?host, "lookup host");

                match socket {
                    TunSocket::Tcp(socket) => {
                        let src_addr = socket.remote_addr();
                        client_clone
                            .handle_tcp(socket, host.clone())
                            .instrument(
                                trace_span!("handle tcp", src_addr = %src_addr, host = %host),
                            )
                            .await
                    }
                    TunSocket::Udp(socket) => {
                        client_clone
                            .handle_udp(socket, host.clone())
                            .instrument(trace_span!("handle udp", host = %host))
                            .await
                    }
                }
            }
            .instrument(trace_span!("handle socket", socket = %remote_addr)),
        );
    }
}

#[derive(Clone)]
struct TracingWriter {
    file_rotate: Arc<Mutex<FileRotate>>,
}

impl TracingWriter {
    fn new(file_rotate: Arc<Mutex<FileRotate>>) -> Self {
        TracingWriter { file_rotate }
    }
}

impl io::Write for TracingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.file_rotate.lock().unwrap();
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self.file_rotate.lock().unwrap();
        guard.flush()
    }
}

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

    if let Some(log_path) = log_path {
        if let Some(path) = PathBuf::from(log_path).parent() {
            std::fs::create_dir_all(path)?;
        }
        let logger = Arc::new(Mutex::new(FileRotate::new(
            log_path,
            RotationMode::Lines(100_000),
            20,
        )));
        let env_filter = EnvFilter::from_default_env()
            .add_directive("seeker=trace".parse()?)
            .add_directive("ssclient=trace".parse()?)
            .add_directive("hermesdns=trace".parse()?);
        let my_subscriber = FmtSubscriber::builder()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_writer(move || TracingWriter::new(logger.clone()))
            .finish();
        tracing::subscriber::set_global_default(my_subscriber)
            .expect("setting tracing default failed");
    } else {
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .with_ansi(false)
            .compact()
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("setting tracing default failed");
    };

    let mut config = Config::from_config_file(path);

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
    let _ip_forward = if config.gateway_mode {
        // In gateway mode, dns server need be accessible from the network.
        config.dns_listen = "0.0.0.0:53".to_string();
        Some(IpForward::new())
    } else {
        None
    };

    block_on(async {
        let client = RuledClient::new(config.clone(), uid, term.clone()).await;

        handle_connection(client, config, term.clone()).await;
    });

    println!("Stop server. Bye bye...");
    Ok(())
}
