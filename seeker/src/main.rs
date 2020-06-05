#[macro_use]
mod macros;
mod config_encryptor;
mod dns_client;
mod logger;
mod proxy_client;
mod proxy_tcp_stream;
mod proxy_udp_socket;
mod server_chooser;

use std::error::Error;

use crate::logger::setup_logger;
use crate::proxy_client::ProxyClient;
use anyhow::Context;
use async_signals::Signals;
use async_std::prelude::{FutureExt, StreamExt};
use async_std::task::block_on;
use clap::{App, Arg};
use config::Config;
use crypto::CipherType;
use std::fs::File;
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
                .required(false),
        )
        .arg(
            Arg::with_name("config-url")
                .long("config-url")
                .value_name("CONFIG_URL")
                .help("URL to config")
                .required(false),
        )
        .arg(
            Arg::with_name("key")
                .long("key")
                .help("Key for encryption/decryption")
                .value_name("KEY")
                .required(false),
        )
        .arg(
            Arg::with_name("user_id")
                .short("u")
                .long("uid")
                .value_name("UID")
                .help("User id to proxy")
                .required(false),
        )
        .arg(
            Arg::with_name("encrypt")
                .long("encrypt")
                .help("Encrypt config file and output to terminal")
                .required(false),
        )
        .arg(
            Arg::with_name("log")
                .short("l")
                .long("log")
                .value_name("PATH")
                .help("Log file")
                .required(false),
        )
        .get_matches();

    let path = matches.value_of("config");
    let key = matches.value_of("key");
    let to_encrypt = matches.is_present("encrypt");
    if to_encrypt {
        println!(
            "Encrypted content is as below:\n\n\n{}\n\n",
            encrypt_config(path, key)?
        );
        return Ok(());
    }
    let config_url = matches.value_of("config-url");
    let config = load_config(path, config_url, key)?;

    let uid = matches.value_of("user_id").map(|uid| uid.parse().unwrap());
    let log_path = matches.value_of("log");

    setup_logger(log_path)?;

    let mut signals = Signals::new(vec![libc::SIGINT, libc::SIGTERM]).unwrap();

    set_rlimit_no_file(10240)?;

    let _dns_setup = DNSSetup::new("".to_string());
    let _ip_forward = if config.gateway_mode {
        // In gateway mode, dns server need be accessible from the network.
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

fn load_config(
    path: Option<&str>,
    url: Option<&str>,
    decrypt_key: Option<&str>,
) -> anyhow::Result<Config> {
    match (path, url, decrypt_key) {
        (Some(p), ..) => Config::from_config_file(p).context("Load config from path error"),
        (_, Some(url), Some(key)) => {
            let resp = ureq::get(url)
                .timeout_read(5000)
                .timeout_connect(5000)
                .timeout_write(5000)
                .call();
            if !resp.ok() {
                return Err(anyhow::anyhow!("Load config from remote host error"));
            }
            let config =
                config_encryptor::decrypt_config(resp.into_reader(), CipherType::ChaCha20Ietf, key)
                    .context("Decrypt remote config error")?;
            Config::from_reader(config.as_slice()).context("Load Config error")
        }
        _ => Err(anyhow::anyhow!("Parameters error")),
    }
}

fn encrypt_config(path: Option<&str>, encrypt_key: Option<&str>) -> anyhow::Result<String> {
    if let (Some(path), Some(key)) = (path, encrypt_key) {
        let file = File::open(&path).context("Open config error")?;
        return config_encryptor::encrypt_config(file, CipherType::ChaCha20Ietf, key)
            .context("Encrypt config error");
    }
    Err(anyhow::anyhow!("Parameters error"))
}
