use std::str::FromStr;
use std::{error, fmt};
use std::{fmt::Debug, net::SocketAddr};

use crate::Address;
use base64::decode_engine;
use bytes::Bytes;
use crypto::CipherType;
use serde::Deserialize;
use tcp_connection::ObfsMode;
use tracing::error;
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Copy)]
pub enum ServerProtocol {
    #[serde(alias = "http")]
    Http,
    #[serde(alias = "https")]
    Https,
    #[serde(alias = "socks5")]
    Socks5,
    #[serde(alias = "ss")]
    Shadowsocks,
}

/// Configuration for a server
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Server address
    name: String,
    #[serde(alias = "server")]
    #[serde(with = "server_addr")]
    addr: Address,
    #[serde(alias = "type")]
    protocol: ServerProtocol,
    username: Option<String>,
    password: Option<String>,
    #[serde(default)]
    #[serde(alias = "cipher")]
    #[serde(with = "cipher_type")]
    method: Option<CipherType>,
    obfs: Option<Obfs>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Obfs {
    pub mode: ObfsMode,
    pub host: String,
}

impl Obfs {
    fn new(mode: ObfsMode, to_string: String) -> Self {
        Obfs {
            mode,
            host: to_string,
        }
    }
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
            .map_err(|_| Error::custom(format!("invalid value: {s}, ip:port or domain:port")))
    }
}

impl ServerConfig {
    pub fn new(
        name: String,
        addr: Address,
        protocol: ServerProtocol,
        username: Option<String>,
        password: Option<String>,
        method: Option<CipherType>,
        obfs: Option<Obfs>,
    ) -> Self {
        Self {
            name,
            addr,
            protocol,
            username,
            password,
            method,
            obfs,
        }
    }

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

    pub fn from_url(encoded: &str) -> Result<ServerConfig, UrlParseError> {
        let parsed = Url::parse(encoded).map_err(UrlParseError::from)?;

        if parsed.scheme() != "ss" {
            return Err(UrlParseError::InvalidScheme);
        }

        let user_info = parsed.username();
        if user_info.is_empty() {
            // This maybe a QRCode URL, which is ss://BASE64-URL-ENCODE(pass:encrypt@hostname:port)

            let encoded = match parsed.host_str() {
                Some(e) => e,
                None => return Err(UrlParseError::MissingHost),
            };

            let mut decoded_body = match decode_engine(encoded, &crate::URL_SAFE_ENGINE) {
                Ok(b) => match String::from_utf8(b) {
                    Ok(b) => b,
                    Err(..) => return Err(UrlParseError::InvalidServerAddr),
                },
                Err(err) => {
                    error!(
                        "failed to parse legacy ss://ENCODED with Base64, err: {}",
                        err
                    );
                    return Err(UrlParseError::InvalidServerAddr);
                }
            };

            decoded_body.insert_str(0, "ss://");
            if let Some(fragment) = parsed.fragment() {
                decoded_body.push_str(&format!("#{}", fragment));
            }
            // Parse it like ss://method:password@host:port
            return ServerConfig::from_url(&decoded_body);
        }

        let (method, pwd) = match parsed.password() {
            Some(password) => {
                // Plain method:password without base64 encoded

                let m = match percent_encoding::percent_decode_str(user_info).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!(
                            "failed to parse percent-encoded method in userinfo, err: {}",
                            err
                        );
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                let p = match percent_encoding::percent_decode_str(password).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!(
                            "failed to parse percent-encoded password in userinfo, err: {}",
                            err
                        );
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                (m, p)
            }
            None => {
                let account = match decode_engine(user_info, &crate::URL_SAFE_ENGINE) {
                    Ok(account) => match String::from_utf8(account) {
                        Ok(ac) => ac,
                        Err(..) => return Err(UrlParseError::InvalidAuthInfo),
                    },
                    Err(err) => {
                        error!("failed to parse UserInfo with Base64, err: {}", err);
                        return Err(UrlParseError::InvalidUserInfo);
                    }
                };

                let mut sp2 = account.splitn(2, ':');
                let (m, p) = match (sp2.next(), sp2.next()) {
                    (Some(m), Some(p)) => (m, p),
                    _ => return Err(UrlParseError::InvalidUserInfo),
                };

                (m.to_owned().into(), p.to_owned().into())
            }
        };

        let host = match parsed.host_str() {
            Some(host) => host,
            None => return Err(UrlParseError::MissingHost),
        };

        let port = parsed.port().unwrap_or(8388);

        let name_percent_encoding = parsed.fragment().unwrap_or(host);
        let name = percent_encoding::percent_decode_str(name_percent_encoding)
            .decode_utf8_lossy()
            .to_string();
        let method: CipherType =
            CipherType::from_str(&method).map_err(|_| UrlParseError::InvalidProtocol)?;

        let mut obfs_mode = None;
        let mut obfs_host = None;
        for (key, value) in parsed.query_pairs() {
            if key != "plugin" {
                continue;
            }

            let mut vsp = value.split(';');
            // only obfs-local plugin is supported
            if vsp.next() != Some("obfs-local") {
                break;
            }

            for arg in vsp {
                match arg.split_once('=') {
                    Some(("obfs", "http")) => obfs_mode = Some(ObfsMode::Http),
                    Some(("obfs-host", s)) => obfs_host = Some(s.to_string()),
                    Some(other) => error!("Unsupported plugin argument: {:?}", other),
                    None => {}
                }
            }
        }

        let obfs = match (obfs_mode, obfs_host) {
            (Some(mode), Some(host)) => Some(Obfs::new(mode, host)),
            (Some(mode), None) => Some(Obfs::new(mode, host.to_string())),
            (None, Some(_)) => {
                error!("obfs-host is set but obfs is not");
                None
            }
            (None, None) => None,
        };

        let svrconfig = ServerConfig::new(
            name,
            Address::from_str(&format!("{host}:{port}")).unwrap(),
            ServerProtocol::Shadowsocks,
            None,
            Some(pwd.to_string()),
            Some(method),
            obfs,
        );

        Ok(svrconfig)
    }
}

/// Shadowsocks URL parsing Error
#[derive(Debug, Clone)]
pub enum UrlParseError {
    ParseError(url::ParseError),
    InvalidScheme,
    InvalidUserInfo,
    InvalidProtocol,
    MissingHost,
    InvalidAuthInfo,
    InvalidServerAddr,
    InvalidQueryString,
}

impl From<url::ParseError> for UrlParseError {
    fn from(err: url::ParseError) -> UrlParseError {
        UrlParseError::ParseError(err)
    }
}

impl fmt::Display for UrlParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UrlParseError::ParseError(ref err) => fmt::Display::fmt(err, f),
            UrlParseError::InvalidScheme => write!(f, "URL must have \"ss://\" scheme"),
            UrlParseError::InvalidUserInfo => write!(f, "invalid user info"),
            UrlParseError::MissingHost => write!(f, "missing host"),
            UrlParseError::InvalidAuthInfo => write!(f, "invalid authentication info"),
            UrlParseError::InvalidServerAddr => write!(f, "invalid server address"),
            UrlParseError::InvalidQueryString => write!(f, "invalid query string"),
            UrlParseError::InvalidProtocol => write!(f, "invalid protocol"),
        }
    }
}

impl error::Error for UrlParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            UrlParseError::ParseError(ref err) => Some(err as &dyn error::Error),
            UrlParseError::InvalidScheme => None,
            UrlParseError::InvalidUserInfo => None,
            UrlParseError::InvalidProtocol => None,
            UrlParseError::MissingHost => None,
            UrlParseError::InvalidAuthInfo => None,
            UrlParseError::InvalidServerAddr => None,
            UrlParseError::InvalidQueryString => None,
        }
    }
}

impl FromStr for ServerConfig {
    type Err = UrlParseError;

    fn from_str(s: &str) -> Result<ServerConfig, Self::Err> {
        ServerConfig::from_url(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_url() -> Result<(), UrlParseError> {
        let url = "ss://YWVzLTI1Ni1nY206MTE0NTE0@1eae257e44aa9d5b.jijifun.com:30002/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dc61be5399e.microsoft.com#%E9%A6%99%E6%B8%AF-ByWave+01";
        let server_config = ServerConfig::from_str(url)?;
        assert_eq!(server_config.name, "香港-ByWave+01");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(
            server_config.obfs(),
            Some(&Obfs {
                mode: ObfsMode::Http,
                host: "c61be5399e.microsoft.com".to_string()
            })
        );
        assert_eq!(server_config.method(), Some(CipherType::Aes256Gcm));
        Ok(())
    }

    #[test]
    fn test_parse_ss_url_with_base64() -> Result<(), UrlParseError> {
        let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTozMnNzZGZAZmJub2RlLWFsbC42cHpmd2YuY29tOjU2MDAz#%5BSS%5D%20Hong%20Kong-02";
        let server_config = ServerConfig::from_str(url)?;
        assert_eq!(server_config.name, "[SS] Hong Kong-02");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        Ok(())
    }
}
