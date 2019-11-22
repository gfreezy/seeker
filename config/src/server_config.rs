use std::{
    fmt::{self, Debug, Display, Formatter},
    net::SocketAddr,
    str::FromStr,
    string::ToString,
    time::Duration,
};

use crate::duration;
use bytes::Bytes;
use crypto::CipherType;
use serde::Deserialize;
use tracing::trace;

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
pub struct ServerConfig {
    /// Server name
    name: String,
    /// Server address
    #[serde(with = "server_addr")]
    addr: ServerAddr,
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    #[serde(with = "cipher_type")]
    method: CipherType,
    /// Connection timeout
    #[serde(with = "duration")]
    connect_timeout: Duration,
    /// Read timeout
    #[serde(with = "duration")]
    read_timeout: Duration,
    /// Write timeout
    #[serde(with = "duration")]
    write_timeout: Duration,
    /// Max idle connections
    idle_connections: usize,
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

    use crate::ServerAddr;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ServerAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ServerAddr::from_str(&s)
            .map_err(|_| Error::custom(format!("invalid value: {}, ip:port or domain:port", s)))
    }
}

impl ServerConfig {
    /// Creates a new ServerConfig
    pub fn new(
        name: String,
        addr: ServerAddr,
        pwd: String,
        method: CipherType,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
        idle_connections: usize,
    ) -> ServerConfig {
        let enc_key = method.bytes_to_key(pwd.as_bytes());
        trace!("Initialize config with pwd: {:?}, key: {:?}", pwd, enc_key);
        ServerConfig {
            name,
            addr,
            password: pwd,
            method,
            connect_timeout,
            read_timeout,
            write_timeout,
            idle_connections,
        }
    }

    /// Create a basic config
    pub fn basic(addr: SocketAddr, password: String, method: CipherType) -> ServerConfig {
        ServerConfig::new(
            addr.to_string(),
            ServerAddr::SocketAddr(addr),
            password,
            method,
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
            10,
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
    pub fn set_addr(&mut self, a: ServerAddr) {
        self.addr = a;
    }

    /// Get server address
    pub fn addr(&self) -> &ServerAddr {
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

    /// Get connect timeout
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Get read timeout
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Get write timeout
    pub fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    /// Get idle connections
    pub fn idle_connections(&self) -> usize {
        self.idle_connections
    }
}
