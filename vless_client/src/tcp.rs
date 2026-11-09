use crate::protocol::{CMD_TCP, VLESS_VERSION, encode_vless_request};
use crate::transport::{BoxedTransport, TransportOptions, server_name, user_id};
use crate::vision_stream::VisionStream;
use bytes::BytesMut;
use config::{Address, ServerConfig};
use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tcp_connection::tls::get_tls_config;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
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

/// Plain VLESS stream wrapper that defers reading the VLESS response header
/// until the first `poll_read`. Xray sends the response header lazily —
/// prepended to the first data from the target — so we must not block
/// on it during connect().
struct PlainVlessStream {
    stream: BoxedTransport,
    response_pending: bool,
    /// Buffer for accumulating partial VLESS response header bytes
    response_buf: [u8; 257],
    response_buf_len: usize,
}

impl PlainVlessStream {
    fn new(stream: BoxedTransport) -> Self {
        Self {
            stream,
            response_pending: true,
            response_buf: [0u8; 257],
            response_buf_len: 0,
        }
    }

    /// Try to read and parse the VLESS response header.
    /// Returns Ready(Ok(())) when the response has been fully consumed.
    fn poll_read_response(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        // Read the 2-byte response header (version + addons_len)
        while self.response_buf_len < 2 {
            let mut buf = ReadBuf::new(&mut self.response_buf[self.response_buf_len..2]);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "EOF reading VLESS response header",
                )));
            }
            self.response_buf_len += n;
        }

        let version = self.response_buf[0];
        if version != VLESS_VERSION {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData,
                format!("VLESS: unexpected response version {version:#04x}"),
            )));
        }

        let response_len = 2 + self.response_buf[1] as usize;
        // Keep partial addons across Pending, including across WS messages.
        while self.response_buf_len < response_len {
            let mut buf = ReadBuf::new(&mut self.response_buf[self.response_buf_len..response_len]);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "EOF reading VLESS response addons",
                )));
            }
            self.response_buf_len += n;
        }

        self.response_pending = false;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for PlainVlessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // First read: consume the VLESS response header
        if this.response_pending {
            ready!(this.poll_read_response(cx))?;
        }

        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PlainVlessStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

enum Inner {
    /// Vision mode: manual TLS + Vision padding/unpadding + direct copy
    Vision(Box<VisionStream<TcpStream>>),
    /// Plain VLESS over TCP, TLS or WebSocket, with lazy response header reading.
    Plain(Box<PlainVlessStream>),
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
        Self::connect_inner(
            server,
            sni,
            addr,
            uuid,
            flow,
            insecure,
            TransportOptions::default(),
        )
        .await
    }

    pub async fn connect_with_config(
        server: SocketAddr,
        addr: Address,
        config: &ServerConfig,
    ) -> Result<Self> {
        Self::connect_inner(
            server,
            server_name(config)?,
            addr,
            user_id(config)?,
            config.flow().map(|flow| flow.as_str()),
            config.insecure(),
            TransportOptions::from_config(config)?,
        )
        .await
    }

    async fn connect_inner(
        server: SocketAddr,
        sni: &str,
        addr: Address,
        uuid: &str,
        flow: Option<&str>,
        insecure: bool,
        transport: TransportOptions,
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

            // Browser-like ALPN for Vision fingerprint mimicry.
            let tls_config = match &transport.reality {
                Some(options) => options.tls_config()?,
                None => get_tls_config(insecure, &[b"h2", b"http/1.1"]),
            };
            let mut session = ClientConnection::new(tls_config, server_name.clone())
                .map_err(|e| Error::other(format!("TLS session init: {e}")))?;
            session.set_buffer_limit(None);

            let mut vision = VisionStream::new_client(tcp_stream, session, *uuid_parsed.as_bytes());

            // Manual TLS handshake through external deframer
            vision.handshake().await?;
            if transport.reality.is_some() {
                info!(group = ?vision.negotiated_group(), "REALITY server authenticated");
            }

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
            // Plain VLESS uses the configured TCP, TLS or WebSocket transport.
            // VLESS response header is read lazily on first poll_read, because
            // Xray sends it prepended to the first target response data.
            let mut stream = transport.connect(server, sni, insecure).await?;

            stream.write_all(&header_buf).await?;
            stream.flush().await?;

            info!(
                server = %server,
                sni,
                flow = "none",
                addr = %addr,
                "VLESS plain connected"
            );

            Ok(Self {
                inner: Inner::Plain(Box::new(PlainVlessStream::new(stream))),
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
