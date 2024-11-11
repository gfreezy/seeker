#![type_length_limit = "2374570"]
#[macro_use]
mod macros;
mod config_encryptor;
mod config_watcher;
mod dns_client;
mod group_servers_chooser;
mod logger;
mod probe_connectivity;
mod proxy_client;
mod proxy_connection;
mod proxy_tcp_stream;
mod proxy_udp_socket;
mod relay_tcp_stream;
mod relay_udp_socket;
mod server_chooser;
mod traffic;

use clap::Parser;
use std::env::current_dir;
use std::net::SocketAddrV4;
use std::path::Path;
use std::time::Duration;

use crate::config_watcher::watch_config;
use crate::logger::setup_logger;
use crate::proxy_client::ProxyClient;
use anyhow::{bail, Context};
use async_std::prelude::FutureExt;
use async_std::task::block_on;
use config::Config;
use crypto::CipherType;
use std::fs::File;
use sysconfig::{get_current_dns, set_rlimit_no_file, DNSSetup, IpForward, IptablesSetup};
use tracing::Instrument;

const REDIR_LISTEN_PORT: u16 = 1300;

/// CLI program for a proxy
#[derive(Parser, Debug)]
#[clap(
    name = "Seeker",
    author = "gfreezy <gfreezy@gmail.com>",
    about = "Tun to Shadowsockets proxy. https://github.com/gfreezy/seeker"
)]
struct SeekerArgs {
    /// Set config file. The sample config at https://github.com/gfreezy/seeker/blob/master/sample_config.yml
    #[clap(short, long, value_name = "FILE")]
    config: Option<String>,

    /// URL to config
    #[clap(long, value_name = "CONFIG_URL")]
    config_url: Option<String>,

    /// Key for encryption/decryption
    #[clap(long, value_name = "KEY")]
    key: Option<String>,

    /// User id to proxy
    #[clap(short = 'u', long, value_name = "UID")]
    user_id: Option<u32>,

    /// Encrypt config file and output to terminal
    #[clap(long)]
    encrypt: bool,

    /// Log file
    #[clap(short = 'l', long, value_name = "PATH")]
    log: Option<String>,

    /// Write a trace log
    #[clap(short = 't', long)]
    trace: bool,

    /// Show connection stats
    #[clap(short = 's', long)]
    stats: bool,
}

fn main() -> anyhow::Result<()> {
    let args = SeekerArgs::parse();

    let path = args.config.as_ref().map(String::as_ref);
    let key = args.key.as_ref().map(String::as_ref);
    let to_encrypt = args.encrypt;
    let to_trace = args.trace;

    if to_encrypt {
        println!(
            "Encrypted content is as below:\n\n\n{}\n\n",
            encrypt_config(path, key)?
        );
        return Ok(());
    }
    let config_url = args.config_url;

    let config = load_config(path, config_url.as_deref(), get_current_dns(), key)?;

    // watch config file if path is provided
    let _watcher_handler = if let Some(p) = path {
        let config_clone = config.clone();
        let mut config_path = Path::new(p).to_path_buf();
        if !config_path.is_absolute() {
            config_path = current_dir()
                .expect("get current dir")
                .join(config_path)
                .canonicalize()
                .expect("canonicalize path");
        }
        let watch_path = config_path.clone();
        let path = config_path.to_str().expect("path to str").to_string();
        tracing::info!("start watching config file: {:?}", watch_path);
        let debouncer = watch_config(watch_path, move |e| {
            tracing::info!("config file changed, reload rules: {:?}", e);
            match load_config(Some(&path), None, vec![], None) {
                Ok(new_config) => {
                    config_clone
                        .rules
                        .replace_rules(new_config.rules.take_rules());
                    tracing::info!("Update rules success.");
                }
                Err(e) => {
                    tracing::info!("Reload config error: {:?}", e);
                }
            }
        });
        Some(debouncer)
    } else {
        None
    };

    let dns = config
        .dns_listens
        .iter()
        .map(|addr| addr.parse::<SocketAddrV4>().unwrap().ip().to_string())
        .collect();
    // Linux system needs to be mut.
    #[allow(unused_mut)]
    let mut dns_setup = DNSSetup::new(dns);

    let uid = args.user_id;
    let log_path = args.log;
    let show_stats = args.stats;

    eprint!("Starting.");
    let _guard = setup_logger(log_path.as_deref(), to_trace)?;
    eprint!(".");
    set_rlimit_no_file(10240)?;
    eprint!(".");
    let _ip_forward = if config.gateway_mode {
        // In gateway mode, dns server need be accessible from the network.
        Some(IpForward::new())
    } else {
        None
    };
    eprint!(".");
    // oneshot channel
    let (tx, rx) = async_std::channel::bounded(1);
    ctrlc::set_handler(move || block_on(tx.send(())).expect("send signal"))
        .expect("Error setting Ctrl-C handler");

    block_on(async {
        let cidr = config.tun_cidr.to_string();
        let redir_mode = config.redir_mode;
        let client = ProxyClient::new(config, uid, show_stats)
            .instrument(tracing::trace_span!("ProxyClient.new"))
            .await;
        eprint!(".");

        dns_setup.start();
        eprintln!("Started!");

        let mut _iptables_setup: Option<IptablesSetup> = None;
        if redir_mode {
            let setup = IptablesSetup::new(REDIR_LISTEN_PORT, cidr);
            setup.start();
            _iptables_setup = Some(setup);
        }

        client
            .run()
            .instrument(tracing::trace_span!("ProxyClient.run"))
            .race(async {
                rx.recv()
                    .instrument(tracing::trace_span!("Signal receiver"))
                    .await
                    .expect("Could not receive signal on channel.");
            })
            .await;
    });

    println!("Stop server. Bye bye...");
    Ok(())
}

fn load_config(
    path: Option<&str>,
    url: Option<&str>,
    original_dns: Vec<String>,
    decrypt_key: Option<&str>,
) -> anyhow::Result<Config> {
    let mut c = match (path, url, decrypt_key) {
        (Some(p), ..) => Config::from_config_file(p).context("Load config from path error")?,
        (_, Some(url), Some(key)) => {
            let ret = ureq::get(url).timeout(Duration::from_secs(5)).call();
            let resp = match ret {
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Load config from remote host error: {}",
                        e.to_string()
                    ));
                }
                Ok(resp) => resp,
            };
            let config =
                config_encryptor::decrypt_config(resp.into_reader(), CipherType::ChaCha20Ietf, key)
                    .context("Decrypt remote config error")?;
            Config::from_reader(config.as_slice()).context("Load Config error")?
        }
        _ => bail!("Parameters error"),
    };

    // If dns_servers is empty, use original dns servers.
    if c.dns_servers.is_empty() {
        for dns in original_dns {
            c.dns_servers.push(config::DnsServerAddr::UdpSocketAddr(
                format!("{dns}:53").parse()?,
            ));
        }
    }
    Ok(c)
}

fn encrypt_config(path: Option<&str>, encrypt_key: Option<&str>) -> anyhow::Result<String> {
    let (Some(path), Some(key)) = (path, encrypt_key) else {
        return Err(anyhow::anyhow!("path and encrypt_key must be provided"));
    };
    let file = File::open(path).context("Open config error")?;
    config_encryptor::encrypt_config(file, CipherType::ChaCha20Ietf, key)
        .context("Encrypt config error")
}
