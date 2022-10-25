#![type_length_limit = "2374570"]
#[macro_use]
mod macros;
mod config_encryptor;
mod dns_client;
mod logger;
mod proxy_client;
mod proxy_connection;
mod proxy_tcp_stream;
mod proxy_udp_socket;
mod server_chooser;
mod traffic;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use crate::logger::setup_logger;
use crate::proxy_client::ProxyClient;
use anyhow::Context;
use async_signals::Signals;
use async_std::prelude::{FutureExt, StreamExt};
use async_std::task::block_on;
use clap::{Arg, Command};
use config::{Config, ServerConfig};
use crypto::CipherType;
use std::fs::File;
use sysconfig::{set_rlimit_no_file, DNSSetup, IpForward};

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
                let signal = signals.next().await.unwrap();
                println!("Signal {signal} received.");
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
    let mut config = match (path, url, decrypt_key) {
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
        _ => return Err(anyhow::anyhow!("Parameters error")),
    };
    let remote_config = config.remote_config_urls.clone();
    let servers = Arc::make_mut(&mut config.servers);
    for url in remote_config {
        let extra_servers = read_servers_from_remote_config(&url)?;
        servers.extend(extra_servers);
    }
    Ok(config)
}

fn encrypt_config(path: Option<&str>, encrypt_key: Option<&str>) -> anyhow::Result<String> {
    if let (Some(path), Some(key)) = (path, encrypt_key) {
        let file = File::open(&path).context("Open config error")?;
        return config_encryptor::encrypt_config(file, CipherType::ChaCha20Ietf, key)
            .context("Encrypt config error");
    }
    Err(anyhow::anyhow!("Parameters error"))
}

fn read_servers_from_remote_config(url: &str) -> anyhow::Result<Vec<ServerConfig>> {
    let mut data = Vec::new();
    let _size = ureq::get(url)
        .timeout(Duration::from_secs(5))
        .call()?
        .into_reader()
        .read_to_end(&mut data)?;
    parse_remote_config_data(&data)
}

fn parse_remote_config_data(data: &[u8]) -> anyhow::Result<Vec<ServerConfig>> {
    let b64decoded = base64::decode(data).context("base64 decode error")?;
    tracing::info!("b64decoded: {:?}", b64decoded);
    let server_urls = b64decoded.split(|&c| c == b'\n');
    let ret: Result<_, _> = server_urls
        .filter_map(|url| std::str::from_utf8(url).ok())
        .map(|s| s.trim())
        .filter(|url| !url.is_empty())
        .map(ServerConfig::from_str)
        .collect();
    Ok(ret?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_remote_server() -> anyhow::Result<()> {
        let data = b"c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAwMi8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDEKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAwMy8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDIKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAxMi8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDMKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAxMy8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFOSVBNiU5OSVFNiVCOCVBRi1CeVdhdmUrMDQKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDAzMi8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNSU4RiVCMCVFNiVCOSVCRS1ISU5FVCswMQpzczovL1lXVnpMVEkxTmkxblkyMDZNVEV4QHRlc3Quc3MuY29tOjMwMDMzLz9wbHVnaW49b2Jmcy1sb2NhbCUzQm9iZnMlM0RodHRwJTNCb2Jmcy1ob3N0JTNEd3d3Lm1pY3Jvc29mdC5jb20jJUU1JThGJUIwJUU2JUI5JUJFLUhJTkVUKzAyCnNzOi8vWVdWekxUSTFOaTFuWTIwNk1URXhAdGVzdC5zcy5jb206MzAwNDIvP3BsdWdpbj1vYmZzLWxvY2FsJTNCb2JmcyUzRGh0dHAlM0JvYmZzLWhvc3QlM0R3d3cubWljcm9zb2Z0LmNvbSMlRTYlOTYlQjAlRTUlOEElQTAlRTUlOUQlQTEtRFArMDEKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDA0My8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNiU5NiVCMCVFNSU4QSVBMCVFNSU5RCVBMS1EUCswMgpzczovL1lXVnpMVEkxTmkxblkyMDZNVEV4QHRlc3Quc3MuY29tOjMwMDUyLz9wbHVnaW49b2Jmcy1sb2NhbCUzQm9iZnMlM0RodHRwJTNCb2Jmcy1ob3N0JTNEd3d3Lm1pY3Jvc29mdC5jb20jJUU2JTk3JUE1JUU2JTlDJUFDLUhBTE8rMDEKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDA1My8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNiU5NyVBNSVFNiU5QyVBQy1EUCswMgpzczovL1lXVnpMVEkxTmkxblkyMDZNVEV4QHRlc3Quc3MuY29tOjMwMDY1Lz9wbHVnaW49b2Jmcy1sb2NhbCUzQm9iZnMlM0RodHRwJTNCb2Jmcy1ob3N0JTNEd3d3Lm1pY3Jvc29mdC5jb20jJUU3JUJFJThFJUU1JTlCJUJELUhBTE8rMDIKc3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2TVRFeEB0ZXN0LnNzLmNvbTozMDA2Ni8/cGx1Z2luPW9iZnMtbG9jYWwlM0JvYmZzJTNEaHR0cCUzQm9iZnMtaG9zdCUzRHd3dy5taWNyb3NvZnQuY29tIyVFNyVCRSU4RSVFNSU5QiVCRC1IQUxPKzAzCnNzOi8vWVdWekxUSTFOaTFuWTIwNk1URXhAdGVzdC5zcy5jb206MzAwNjcvP3BsdWdpbj1vYmZzLWxvY2FsJTNCb2JmcyUzRGh0dHAlM0JvYmZzLWhvc3QlM0R3d3cubWljcm9zb2Z0LmNvbSMlRTclQkUlOEUlRTUlOUIlQkQtSEFMTyswNAo=";
        let servers = parse_remote_config_data(data)?;
        assert_eq!(servers.len(), 13);
        Ok(())
    }
}
