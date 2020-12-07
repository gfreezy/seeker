use std::{fmt::Debug, net::SocketAddr, string::ToString};

use crate::Address;
use bytes::Bytes;
use crypto::CipherType;
use serde::Deserialize;
use url::Url;

/// Server address
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum DnsServerAddr {
    /// IP Address
    UdpSocketAddr(SocketAddr),
    /// eg. tcp://114.114.114.114:53
    #[serde(with = "url_serde")]
    TcpSocketAddr(Url),
}

#[derive(Clone, Debug, Deserialize)]
pub enum ProxyProtocol {
    Http,
    Https,
    Socks5,
}
/// Configuration for a server
#[derive(Clone, Debug, Deserialize)]
pub struct ProxyServerConfig {
    /// Server address
    #[serde(with = "server_addr")]
    pub addr: Address,
    pub protocol: ProxyProtocol,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Configuration for a server
#[derive(Clone, Debug, Deserialize)]
pub struct ShadowsocksServerConfig {
    /// Server name
    name: String,
    /// Server address
    #[serde(with = "server_addr")]
    addr: Address,
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    #[serde(with = "cipher_type")]
    method: CipherType,
}

mod cipher_type {
    use crypto::CipherType;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CipherType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CipherType::from_str(&s).map_err(Error::custom)
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

impl ShadowsocksServerConfig {
    /// Creates a new ServerConfig
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        addr: Address,
        pwd: String,
        method: CipherType,
    ) -> ShadowsocksServerConfig {
        ShadowsocksServerConfig {
            name,
            addr,
            password: pwd,
            method,
        }
    }

    /// Create a basic config
    pub fn basic(
        addr: SocketAddr,
        password: String,
        method: CipherType,
    ) -> ShadowsocksServerConfig {
        ShadowsocksServerConfig::new(
            addr.to_string(),
            Address::SocketAddress(addr),
            password,
            method,
        )
    }

    /// Set encryption method
    pub fn set_method(&mut self, t: CipherType, pwd: String) {
        self.password = pwd;
        self.method = t;
    }

    /// Get server name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set server addr
    pub fn set_addr(&mut self, a: Address) {
        self.addr = a;
    }

    /// Get server address
    pub fn addr(&self) -> &Address {
        &self.addr
    }

    /// Get encryption key
    pub fn key(&self) -> Bytes {
        self.method.bytes_to_key(self.password.as_bytes())
    }

    /// Get password
    pub fn password(&self) -> &str {
        &self.password[..]
    }

    /// Get method
    pub fn method(&self) -> CipherType {
        self.method
    }
}
