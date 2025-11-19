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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// Server address
    name: String,
    addr: Address,
    protocol: ServerProtocol,
    username: Option<String>,
    password: Option<String>,
    method: Option<CipherType>,
    obfs: Option<Obfs>,
}

// Internal struct for deserializing both Seeker and Clash formats
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ServerConfigHelper {
    // Clash format with separate server and port (must come first to avoid conflicts)
    Clash {
        name: String,
        #[serde(alias = "type")]
        protocol: ClashProtocol,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        #[serde(default)]
        #[serde(alias = "cipher")]
        #[serde(with = "cipher_type")]
        method: Option<CipherType>,
        #[serde(default)]
        obfs: Option<Obfs>,
        // Clash-specific fields we ignore
        #[serde(default)]
        _udp: Option<bool>,
    },
    // Seeker format
    Seeker {
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
        #[serde(default)]
        obfs: Option<Obfs>,
    },
}

// Clash protocol types map to our ServerProtocol
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ClashProtocol {
    Ss,
    Socks5,
    Http,
    Https,
}

impl From<ClashProtocol> for ServerProtocol {
    fn from(clash: ClashProtocol) -> Self {
        match clash {
            ClashProtocol::Ss => ServerProtocol::Shadowsocks,
            ClashProtocol::Socks5 => ServerProtocol::Socks5,
            ClashProtocol::Http => ServerProtocol::Http,
            ClashProtocol::Https => ServerProtocol::Https,
        }
    }
}

impl<'de> Deserialize<'de> for ServerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        match ServerConfigHelper::deserialize(deserializer)? {
            ServerConfigHelper::Clash {
                name,
                protocol,
                server,
                port,
                username,
                password,
                method,
                obfs,
                _udp: _,
            } => {
                let addr = Address::from_str(&format!("{server}:{port}")).map_err(|_| {
                    Error::custom(format!("invalid server address: {server}:{port}"))
                })?;
                Ok(ServerConfig {
                    name,
                    addr,
                    protocol: protocol.into(),
                    username,
                    password,
                    method,
                    obfs,
                })
            }
            ServerConfigHelper::Seeker {
                name,
                addr,
                protocol,
                username,
                password,
                method,
                obfs,
            } => Ok(ServerConfig {
                name,
                addr,
                protocol,
                username,
                password,
                method,
                obfs,
            }),
        }
    }
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

    #[test]
    fn test_parse_clash_format() {
        let yaml = r#"
name: "[SS] Hong Kong-20"
type: ss
server: example.com
port: 56020
cipher: chacha20-ietf-poly1305
password: password
udp: true
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "[SS] Hong Kong-20");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("example.com:56020").unwrap()
        );
        assert_eq!(
            server_config.method(),
            Some(CipherType::ChaCha20IetfPoly1305)
        );
        assert_eq!(server_config.password(), Some("password"));
    }

    #[test]
    fn test_parse_seeker_format() {
        let yaml = r#"
name: server-ss1
addr: domain-to-ss-server.com:8388
protocol: Shadowsocks
method: chacha20-ietf
password: password
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "server-ss1");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("domain-to-ss-server.com:8388").unwrap()
        );
        assert_eq!(server_config.method(), Some(CipherType::ChaCha20Ietf));
        assert_eq!(server_config.password(), Some("password"));
    }

    #[test]
    fn test_parse_clash_socks5_format() {
        let yaml = r#"
name: "My SOCKS5"
type: socks5
server: 127.0.0.1
port: 1080
username: myuser
password: mypass
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "My SOCKS5");
        assert_eq!(server_config.protocol(), ServerProtocol::Socks5);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("127.0.0.1:1080").unwrap()
        );
        assert_eq!(server_config.username(), Some("myuser"));
        assert_eq!(server_config.password(), Some("mypass"));
    }

    #[test]
    fn test_parse_seeker_format_with_server_alias() {
        // Test using 'server' alias instead of 'addr'
        let yaml = r#"
name: server-ss-alias
server: example.com:8388
protocol: Shadowsocks
method: aes-256-gcm
password: mypassword
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "server-ss-alias");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("example.com:8388").unwrap()
        );
        assert_eq!(server_config.method(), Some(CipherType::Aes256Gcm));
        assert_eq!(server_config.password(), Some("mypassword"));
    }

    #[test]
    fn test_parse_seeker_format_with_type_alias() {
        // Test using 'type' alias instead of 'protocol'
        let yaml = r#"
name: server-http
addr: 127.0.0.1:1087
type: Http
username: user
password: pass
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "server-http");
        assert_eq!(server_config.protocol(), ServerProtocol::Http);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("127.0.0.1:1087").unwrap()
        );
        assert_eq!(server_config.username(), Some("user"));
        assert_eq!(server_config.password(), Some("pass"));
    }

    #[test]
    fn test_parse_seeker_format_with_cipher_alias() {
        // Test using 'cipher' alias instead of 'method'
        let yaml = r#"
name: server-ss-cipher
addr: server.example.com:8388
protocol: Shadowsocks
cipher: chacha20-ietf-poly1305
password: secret
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "server-ss-cipher");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("server.example.com:8388").unwrap()
        );
        assert_eq!(
            server_config.method(),
            Some(CipherType::ChaCha20IetfPoly1305)
        );
        assert_eq!(server_config.password(), Some("secret"));
    }

    #[test]
    fn test_parse_seeker_format_with_all_aliases() {
        // Test using all aliases together
        let yaml = r#"
name: server-all-alias
server: test.com:9999
type: Shadowsocks
cipher: aes-128-gcm
password: test123
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "server-all-alias");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("test.com:9999").unwrap()
        );
        assert_eq!(server_config.method(), Some(CipherType::Aes128Gcm));
        assert_eq!(server_config.password(), Some("test123"));
    }

    #[test]
    fn test_parse_mixed_aliases_and_original() {
        // Test mixing aliases and original field names
        let yaml = r#"
name: server-mixed
server: mixed.com:7777
protocol: Shadowsocks
cipher: aes-256-gcm
password: mixed123
"#;
        let server_config: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server_config.name(), "server-mixed");
        assert_eq!(server_config.protocol(), ServerProtocol::Shadowsocks);
        assert_eq!(
            server_config.addr(),
            &Address::from_str("mixed.com:7777").unwrap()
        );
        assert_eq!(server_config.method(), Some(CipherType::Aes256Gcm));
        assert_eq!(server_config.password(), Some("mixed123"));
    }

    #[test]
    fn test_parse_protocol_aliases() {
        // Test protocol alias variations
        let test_cases = vec![
            ("http", ServerProtocol::Http),
            ("https", ServerProtocol::Https),
            ("socks5", ServerProtocol::Socks5),
            ("ss", ServerProtocol::Shadowsocks),
        ];

        for (alias, expected) in test_cases {
            let yaml = format!(
                r#"
name: test-{alias}
addr: 127.0.0.1:8080
protocol: {alias}
"#
            );
            let server_config: ServerConfig = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(
                server_config.protocol(),
                expected,
                "Failed for alias: {alias}"
            );
        }
    }
}
