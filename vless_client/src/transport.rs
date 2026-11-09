use config::{ServerConfig, WebSocketOptions};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use tcp_connection::tls::{connect_tls, get_tls_connector};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::websocket::WebSocketIo;

pub(crate) trait Transport: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Transport for T {}
pub(crate) type BoxedTransport = Box<dyn Transport>;

#[derive(Clone)]
pub(crate) struct TransportOptions {
    pub tls: bool,
    pub reality: Option<crate::reality::Options>,
    websocket: Option<(String, WebSocketOptions)>,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            tls: true,
            reality: None,
            websocket: None,
        }
    }
}

impl TransportOptions {
    pub fn from_config(config: &ServerConfig) -> Result<Self> {
        let websocket = match config.network() {
            "tcp" => None,
            "ws" => Some((
                config.addr().to_string(),
                config.ws_opts().cloned().unwrap_or_default(),
            )),
            network => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("unsupported VLESS network: {network}"),
                ));
            }
        };
        if config.flow().is_some() && (websocket.is_some() || !config.tls_enabled()) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "VLESS Vision requires TCP with TLS",
            ));
        }
        let reality = config
            .reality_opts()
            .map(|options| {
                if websocket.is_some() || !config.tls_enabled() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "REALITY requires TCP with TLS",
                    ));
                }
                crate::reality::Options::parse(options, config.client_fingerprint())
            })
            .transpose()?;
        Ok(Self {
            tls: config.tls_enabled(),
            reality,
            websocket,
        })
    }

    pub async fn connect(
        &self,
        server: SocketAddr,
        sni: &str,
        insecure: bool,
    ) -> Result<BoxedTransport> {
        let tcp = TcpStream::connect(server).await?;
        let stream: BoxedTransport = if self.tls {
            let name =
                rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(|error| {
                    Error::new(ErrorKind::InvalidInput, format!("invalid SNI: {error}"))
                })?;
            let connector = match &self.reality {
                Some(options) => tokio_rustls::TlsConnector::from(options.tls_config()?),
                None => get_tls_connector(insecure),
            };
            Box::new(connect_tls(&connector, name, tcp).await?)
        } else {
            Box::new(tcp)
        };
        match &self.websocket {
            Some((authority, options)) => Ok(Box::new(
                WebSocketIo::connect(stream, authority, options, self.tls).await?,
            )),
            None => Ok(stream),
        }
    }
}

pub(crate) fn server_name(config: &ServerConfig) -> Result<&str> {
    config
        .sni()
        .or_else(|| config.addr().hostname())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "sni or domain must be set for vless protocol",
            )
        })
}

pub(crate) fn user_id(config: &ServerConfig) -> Result<&str> {
    config.username().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "uuid must be set for vless protocol",
        )
    })
}
