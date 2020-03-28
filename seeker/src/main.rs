mod client;
//mod signal;

use std::error::Error;

use crate::client::ruled_client::RuledClient;
use crate::client::Client;
use async_std::io::timeout;
use async_std::net::{SocketAddrV4, TcpListener};
use async_std::prelude::*;
use async_std::task::{block_on, spawn};
use clap::{App, Arg};
use config::{Address, Config};
use dnsserver::create_dns_server;
use file_rotate::{FileRotate, RotationMode};
use parking_lot::RwLock;
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
use tun_nat::{run_nat, SessionManager};

async fn handle_connection<T: Client + Clone + Send + Sync + 'static>(
    client: T,
    session_manager: Arc<RwLock<SessionManager>>,
    config: Config,
    term: Arc<AtomicBool>,
) {
    let (dns_server, resolver) = create_dns_server(
        "dns.db",
        config.dns_listen.clone(),
        config.dns_start_ip,
        config.rules.clone(),
        (config.dns_server.ip().to_string(), config.dns_server.port()),
    )
    .await;
    println!("Spawn DNS server");
    spawn(
        dns_server
            .run_server()
            .instrument(trace_span!("dns_server.run_server")),
    );

    let tcp_relay = async {
        let listener = TcpListener::bind((config.tun_ip, 1300)).await?;
        let mut incoming = listener.incoming();
        loop {
            let conn = timeout(Duration::from_secs(1), async {
                incoming.next().await.transpose()
            })
            .await;
            let conn = match conn {
                Ok(Some(conn)) => conn,
                Ok(None) => break,
                Err(e) if e.kind() == ErrorKind::TimedOut => {
                    if term.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            let remote_addr = conn.peer_addr()?;
            let manager = session_manager.read();
            let assoc = manager.get_by_port(remote_addr.port());
            let real_dest_addr = SocketAddrV4::new(assoc.dest_addr, assoc.dest_port);
            let real_src_addr = SocketAddrV4::new(assoc.src_addr, assoc.src_port);
            let resolver_clone = resolver.clone();
            let client_clone = client.clone();

            spawn(async move {
                let ip = real_dest_addr.ip().to_string();
                let host = resolver_clone
                    .lookup_host(&ip)
                    .instrument(trace_span!("lookup host", ip = ?ip))
                    .await
                    .map(|s| Address::DomainNameAddress(s, real_dest_addr.port()))
                    .unwrap_or_else(|| Address::SocketAddress(real_dest_addr.into()));

                trace!(ip = ?ip, host = ?host, "lookup host");

                client_clone
                    .handle_tcp(conn, host.clone())
                    .instrument(trace_span!("handle tcp", src_addr = %real_src_addr, host = %host))
                    .await
            });
        }
        Ok::<(), io::Error>(())
    };

    tcp_relay.await.unwrap();
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
        let env_filter = EnvFilter::new("seeker=trace")
            .add_directive("seeker=trace".parse()?)
            .add_directive("ssclient=trace".parse()?)
            .add_directive("hermesdns=trace".parse()?)
            .add_directive("tun=info".parse()?);
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

    let mut config = Config::from_config_file(path)?;

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::SIGINT, Arc::clone(&term))?;
    signal_hook::flag::register(signal_hook::SIGTERM, Arc::clone(&term))?;

    let session_manager = run_nat(&config.tun_name, config.tun_ip, config.tun_cidr, 1300)?;

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

        handle_connection(client, session_manager, config, term.clone()).await;
    });

    println!("Stop server. Bye bye...");
    Ok(())
}
