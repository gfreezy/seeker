#![type_length_limit = "2374570"]
#[macro_use]
mod macros;
mod config_encryptor;
mod dns_client;
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

use std::time::Duration;

use crate::logger::setup_logger;
use crate::proxy_client::ProxyClient;
use anyhow::{bail, Context};
use async_signals::Signals;
use async_std::prelude::{FutureExt, StreamExt};
use async_std::task::block_on;
use clap::{Arg, ArgAction, Command};
use config::Config;
use crypto::CipherType;
use std::fs::File;
use sysconfig::{set_rlimit_no_file, DNSSetup, IpForward};
use tracing::Instrument;

fn main() -> anyhow::Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let matches = Command::new("Seeker")
        .version(version)
        .author("gfreezy <gfreezy@gmail.com>")
        .about("Tun to Shadowsockets proxy. https://github.com/gfreezy/seeker")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Set config file. The sample config at https://github.com/gfreezy/seeker/blob/master/sample_config.yml")
                .required(false),
        )
        .arg(
            Arg::new("config-url")
                .long("config-url")
                .value_name("CONFIG_URL")
                .help("URL to config")
                .required(false),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .help("Key for encryption/decryption")
                .value_name("KEY")
                .required(false),
        )
        .arg(
            Arg::new("user_id")
                .short('u')
                .long("uid")
                .value_name("UID")
                .help("User id to proxy")
                .required(false),
        )
        .arg(
            Arg::new("encrypt")
                .long("encrypt")
                .help("Encrypt config file and output to terminal")
                .action(ArgAction::SetTrue)
                .required(false),
        )
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .value_name("PATH")
                .help("Log file")
                .required(false),
        )
        .arg(
            Arg::new("trace")
                .short('t')
                .long("trace")
                .action(ArgAction::SetTrue)
                .help("Write a trace log")
                .required(false),
        )
        .get_matches();

    let path = matches.get_one::<String>("config").map(String::as_ref);
    let key = matches.get_one::<String>("key").map(String::as_ref);
    let to_encrypt = matches.get_flag("encrypt");
    let to_trace = matches.get_flag("trace");
    if to_encrypt {
        println!(
            "Encrypted content is as below:\n\n\n{}\n\n",
            encrypt_config(path, key)?
        );
        return Ok(());
    }
    let config_url = matches.get_one::<String>("config-url").map(String::as_ref);

    let dns_setup = DNSSetup::new("".to_string());

    let config = load_config(path, config_url, dns_setup.original_dns(), key)?;

    let uid = matches.get_one::<u32>("user_id").copied();
    let log_path = matches.get_one::<String>("log").map(String::as_ref);

    eprint!("Starting.");
    let _guard = setup_logger(log_path, to_trace)?;
    eprint!(".");
    let mut signals = Signals::new(vec![libc::SIGINT, libc::SIGTERM]).unwrap();
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
    block_on(async {
        let client = ProxyClient::new(config, uid)
            .instrument(tracing::trace_span!("ProxyClient.new"))
            .await;
        eprint!(".");

        dns_setup.start();
        eprintln!("Started!");

        client
            .run()
            .instrument(tracing::trace_span!("ProxyClient.run"))
            .race(
                async {
                    let signal = signals.next().await.unwrap();
                    println!("Signal {signal} received.");
                }
                .instrument(tracing::trace_span!("Signal receiver")),
            )
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
            c.dns_servers
                .push(config::DnsServerAddr::UdpSocketAddr(dns.parse()?));
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
