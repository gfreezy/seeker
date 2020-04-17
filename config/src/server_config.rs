use std::{
    fmt::{self, Debug, Display, Formatter},
    net::SocketAddr,
    str::FromStr,
    string::ToString,
};

use crate::Address;
use bytes::Bytes;
use crypto::CipherType;
use serde::Deserialize;

/// Server address
#[derive(Clone, Debug, Deserialize)]
pub enum ServerAddr {
    /// IP Address
    SocketAddr(SocketAddr),
    /// Domain name address, eg. example.com:8080
    DomainName(String, u16),
}

impl ServerAddr {
    /// Get address for server listener
    /// Panic if address is domain name
    pub fn listen_addr(&self) -> &SocketAddr {
        match *self {
            ServerAddr::SocketAddr(ref s) => s,
            _ => panic!("Cannot use domain name as server listen address"),
        }
    }

    /// Get string representation of domain
    pub fn host(&self) -> String {
        match *self {
            ServerAddr::SocketAddr(ref s) => s.ip().to_string(),
            ServerAddr::DomainName(ref dm, _) => dm.clone(),
        }
    }

    /// Get port
    pub fn port(&self) -> u16 {
        match *self {
            ServerAddr::SocketAddr(ref s) => s.port(),
            ServerAddr::DomainName(_, p) => p,
        }
    }
}

/// Parse `ServerAddr` error
#[derive(Debug)]
pub struct ServerAddrError;

impl FromStr for ServerAddr {
    type Err = ServerAddrError;

    fn from_str(s: &str) -> Result<ServerAddr, ServerAddrError> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(ServerAddr::SocketAddr(addr)),
            Err(..) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => match port.parse::<u16>() {
                        Ok(port) => Ok(ServerAddr::DomainName(dn.to_owned(), port)),
                        Err(..) => Err(ServerAddrError),
                    },
                    _ => Err(ServerAddrError),
                }
            }
        }
    }
}

impl Display for ServerAddr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            ServerAddr::SocketAddr(ref a) => write!(f, "{}", a),
            ServerAddr::DomainName(ref d, port) => write!(f, "{}:{}", d, port),
        }
    }
}

/// Configuration for a server
#[derive(Clone, Debug, Deserialize)]
pub struct ProxyServerConfig {
    /// Server address
    #[serde(with = "server_addr")]
    pub addr: Address,
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
