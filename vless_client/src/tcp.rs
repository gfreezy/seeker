use crate::protocol::{encode_vless_request, CMD_TCP, VLESS_VERSION};
use crate::tls::{get_tls_config, get_tls_connector};
use crate::vision_stream::VisionStream;
use bytes::BytesMut;
use config::Address;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::info;
use uuid::Uuid;

fn normalize_flow(flow: Option<&str>) -> Result<Option<&'static str>> {
    match flow {
        None | Some("") => Ok(None),
        Some("xtls-rprx-vision") | Some("xtls-rprx-vision-udp443") => Ok(Some("xtls-rprx-vision")),
        Some(other) => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("unsupported VLESS flow: {other}"),
        )),
    }
}

enum Inner {
    /// Vision mode: manual TLS + Vision padding/unpadding + direct copy
    Vision(Box<VisionStream<TcpStream>>),
    /// Plain VLESS: tokio-rustls handles TLS transparently
    Plain(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

pub struct VlessTcpStream {
    inner: Inner,
}

impl VlessTcpStream {
    pub async fn connect(
        server: SocketAddr,
        sni: &str,
        addr: Address,
        uuid: &str,
        flow: Option<&str>,
        insecure: bool,
    ) -> Result<Self> {
        let flow = normalize_flow(flow)?;
        let is_vision = flow == Some("xtls-rprx-vision");

        let uuid_parsed =
            Uuid::parse_str(uuid).map_err(|e| Error::other(format!("invalid VLESS uuid: {e}")))?;

        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| Error::other(format!("invalid SNI: {e}")))?;

        // Build VLESS request header
        let mut header_buf = BytesMut::with_capacity(128);
        encode_vless_request(&uuid_parsed, CMD_TCP, &addr, flow, &mut header_buf)?;

        if is_vision {
            // Vision mode: drive TLS handshake manually so all reads go through
            // our deframer, avoiding buffer sync issues with tokio-rustls.
            let tcp_stream = TcpStream::connect(server).await?;

            let tls_config = get_tls_config(insecure);
            let session = ClientConnection::new(tls_config, server_name.clone())
                .map_err(|e| Error::other(format!("TLS session init: {e}")))?;

            let mut vision =
                VisionStream::new_client(tcp_stream, session, *uuid_parsed.as_bytes());

            // Manual TLS handshake through external deframer
            vision.handshake().await?;

            // Send VLESS header through the TLS session
            vision.send_vless_header(&header_buf).await?;

            info!(
                server = %server,
                sni,
                flow = "xtls-rprx-vision",
                addr = %addr,
                "VLESS Vision connected"
            );

            Ok(Self {
                inner: Inner::Vision(Box::new(vision)),
            })
        } else {
            // Plain VLESS: use tokio-rustls for TLS (no manual management needed)
            let connector = get_tls_connector(insecure);
            let tcp_stream = TcpStream::connect(server).await?;
            let mut tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(Error::other)?;

            tls_stream.write_all(&header_buf).await?;
            tls_stream.flush().await?;

            // Read VLESS response header
            let mut resp = [0u8; 2];
            tls_stream.read_exact(&mut resp).await?;
            if resp[0] != VLESS_VERSION {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("VLESS: unexpected response version {:#04x}", resp[0]),
                ));
            }
            let addons_len = resp[1] as usize;
            if addons_len > 0 {
                let mut addons = vec![0u8; addons_len];
                tls_stream.read_exact(&mut addons).await?;
            }

            info!(
                server = %server,
                sni,
                flow = "none",
                addr = %addr,
                "VLESS plain connected"
            );

            Ok(Self {
                inner: Inner::Plain(Box::new(tls_stream)),
            })
        }
    }
}

impl AsyncRead for VlessTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Vision(s) => Pin::new(s).poll_read(cx, buf),
            Inner::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VlessTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::Vision(s) => Pin::new(s).poll_write(cx, buf),
            Inner::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Vision(s) => Pin::new(s).poll_flush(cx),
            Inner::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Vision(s) => Pin::new(s).poll_shutdown(cx),
            Inner::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_flow;

    #[test]
    fn test_normalize_flow() {
        assert_eq!(normalize_flow(None).unwrap(), None);
        assert_eq!(normalize_flow(Some("")).unwrap(), None);
        assert_eq!(
            normalize_flow(Some("xtls-rprx-vision")).unwrap(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            normalize_flow(Some("xtls-rprx-vision-udp443")).unwrap(),
            Some("xtls-rprx-vision")
        );
        assert!(normalize_flow(Some("unsupported-flow")).is_err());
    }
}
