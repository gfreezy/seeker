use std::{fmt::Debug, net::SocketAddr};

use crate::Address;
use bytes::Bytes;
use crypto::CipherType;
use serde::Deserialize;
use tcp_connection::ObfsMode;
use url::Url;

/// Server address
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum DnsServerAddr {
    /// IP Address
    UdpSocketAddr(SocketAddr),
    /// eg. tcp://114.114.114.114:53
    TcpSocketAddr(Url),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Copy)]
pub enum ServerProtocol {
    Http,
    Https,
    Socks5,
    Shadowsocks,
}

/// Configuration for a server
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ServerConfig {
    /// Server address
    name: String,
    #[serde(with = "server_addr")]
    addr: Address,
    protocol: ServerProtocol,
    username: Option<String>,
    password: Option<String>,
    #[serde(default)]
    #[serde(with = "cipher_type")]
    method: Option<CipherType>,
    obfs: Option<Obfs>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Obfs {
    pub mode: ObfsMode,
    pub host: String,
}

mod cipher_type {
    use crypto::CipherType;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<CipherType>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            None => Ok(None),
            Some(s) => Ok(Some(CipherType::from_str(&s).map_err(Error::custom)?)),
        }
    }
}

mod server_addr {
    use crate::Address;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s)
            .map_err(|_| Error::custom(format!("invalid value: {}, ip:port or domain:port", s)))
    }
}

impl ServerConfig {
    /// Get server name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get server address
    pub fn addr(&self) -> &Address {
        &self.addr
    }

    /// Get server protocol
    pub fn protocol(&self) -> ServerProtocol {
        self.protocol
    }

    /// Get encryption key
    pub fn key(&self) -> Option<Bytes> {
        Some(self.method()?.bytes_to_key(self.password()?.as_bytes()))
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get password
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    /// Get method
    pub fn method(&self) -> Option<CipherType> {
        self.method
    }

    pub fn obfs(&self) -> Option<&Obfs> {
        self.obfs.as_ref()
    }
}
