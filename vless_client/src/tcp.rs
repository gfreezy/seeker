use crate::protocol::{encode_vless_request, CMD_TCP, VLESS_VERSION};
use crate::vision::VisionFilter;
use bytes::BytesMut;
use config::Address;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};
use uuid::Uuid;

static CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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

fn get_tls_connector(insecure: bool) -> TlsConnector {
    use std::sync::OnceLock;
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    static CONNECTOR_INSECURE: OnceLock<TlsConnector> = OnceLock::new();

    let lock = if insecure {
        &CONNECTOR_INSECURE
    } else {
        &CONNECTOR
    };
    lock.get_or_init(|| {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        if insecure {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }

        TlsConnector::from(Arc::new(tls_config))
    })
    .clone()
}

pub struct VlessTcpStream {
    id: u64,
    conn: TlsStream<TcpStream>,
    /// XTLS-Vision padding filter (None for plain VLESS).
    vision: Option<VisionFilter>,
    /// Whether VLESS response header has been consumed.
    response_header_parsed: bool,
    response_header_buf: Vec<u8>,
    /// Buffered unpadded data from reads.
    read_buf: Vec<u8>,
    read_offset: usize,
    /// Pending padded Vision frame that must be fully written before accepting new input.
    write_buf: Vec<u8>,
    write_offset: usize,
    write_pending_plain_len: usize,
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
        let connector = get_tls_connector(insecure);
        let flow = normalize_flow(flow)?;

        let uuid_parsed =
            Uuid::parse_str(uuid).map_err(|e| Error::other(format!("invalid VLESS uuid: {e}")))?;

        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| Error::other(format!("invalid SNI: {e}")))?;

        let tcp_stream = TcpStream::connect(server).await?;
        let mut tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(Error::other)?;

        let is_vision = flow == Some("xtls-rprx-vision");

        // Build and send VLESS request header immediately (like Trojan/VMess do)
        let mut header_buf = BytesMut::with_capacity(128);
        encode_vless_request(&uuid_parsed, CMD_TCP, &addr, flow, &mut header_buf);

        let vision = if is_vision {
            Some(VisionFilter::new(*uuid_parsed.as_bytes()))
        } else {
            None
        };

        let id = CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tls_stream.write_all(&header_buf).await?;
        tls_stream.flush().await?;
        info!(
            id,
            server = %server,
            sni,
            flow = flow.unwrap_or("none"),
            addr = %addr,
            header_len = header_buf.len(),
            vision = is_vision,
            "VLESS connected, header sent"
        );
        Ok(VlessTcpStream {
            id,
            conn: tls_stream,
            vision,
            response_header_parsed: false,
            response_header_buf: Vec::new(),
            read_buf: Vec::new(),
            read_offset: 0,
            write_buf: Vec::new(),
            write_offset: 0,
            write_pending_plain_len: 0,
        })
    }

    /// Consume the VLESS response header lazily on first read.
    /// Format: version(1) + addons_len(1) + addons(N)
    fn poll_read_response_header(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        // Need at least 2 bytes (version + addons_len)
        while self.response_header_buf.len() < 2 {
            let need = 2 - self.response_header_buf.len();
            let mut tmp = vec![0u8; need];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.conn).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "VLESS: EOF reading response header",
                )));
            }
            self.response_header_buf.extend_from_slice(&tmp[..n]);
        }

        // Read addons if any
        let addons_len = self.response_header_buf[1] as usize;
        let total = 2 + addons_len;
        while self.response_header_buf.len() < total {
            let need = total - self.response_header_buf.len();
            let mut tmp = vec![0u8; need];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.conn).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "VLESS: EOF reading response addons",
                )));
            }
            self.response_header_buf.extend_from_slice(&tmp[..n]);
        }

        if self.response_header_buf[0] != VLESS_VERSION {
            let err_msg = format!(
                "VLESS: unexpected response version {:#04x}, expected {:#04x}. Raw header bytes: {:02x?}",
                self.response_header_buf[0], VLESS_VERSION, &self.response_header_buf
            );
            warn!(id = self.id, "{}", err_msg);
            return Poll::Ready(Err(Error::new(ErrorKind::InvalidData, err_msg)));
        }

        let addons_len = self.response_header_buf[1] as usize;
        debug!(
            id = self.id,
            version = self.response_header_buf[0],
            addons_len,
            "VLESS response header parsed"
        );
        self.response_header_parsed = true;
        Poll::Ready(Ok(()))
    }

    /// Drain buffered read data into caller's buf. Returns true if data was copied.
    fn drain_read_buf(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_offset >= self.read_buf.len() {
            return false;
        }
        let remaining = &self.read_buf[self.read_offset..];
        let to_copy = remaining.len().min(buf.remaining());
        if to_copy == 0 {
            return false;
        }
        buf.put_slice(&remaining[..to_copy]);
        self.read_offset += to_copy;
        if self.read_offset >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_offset = 0;
        }
        true
    }

    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<usize>>> {
        while self.write_offset < self.write_buf.len() {
            match Pin::new(&mut self.conn).poll_write(cx, &self.write_buf[self.write_offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "VLESS: zero bytes written",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_offset += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(None));
        }

        let plain_len = self.write_pending_plain_len;
        self.write_buf.clear();
        self.write_offset = 0;
        self.write_pending_plain_len = 0;
        Poll::Ready(Ok(Some(plain_len)))
    }
}

impl AsyncRead for VlessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let me = &mut *self;

        // Drain buffered data first
        if me.drain_read_buf(buf) {
            return Poll::Ready(Ok(()));
        }

        // Parse response header on first read (like VMess does)
        if !me.response_header_parsed {
            ready!(me.poll_read_response_header(cx))?;
        }

        // Check if Vision is in direct copy mode — the server has switched
        // its writer to raw TCP (bypassing outer TLS), so we must also read
        // directly from the underlying TcpStream.
        if let Some(vision) = &me.vision {
            if vision.read_direct_copy {
                let (tcp, _tls) = me.conn.get_mut();
                return Pin::new(tcp).poll_read(cx, buf);
            }
        }

        // Read from connection
        let mut tmp = vec![0u8; 16384];
        let mut rb = ReadBuf::new(&mut tmp);
        ready!(Pin::new(&mut me.conn).poll_read(cx, &mut rb))?;
        let filled = rb.filled().len();
        if filled == 0 {
            return Poll::Ready(Ok(())); // EOF
        }
        let chunk = &tmp[..filled];

        // Apply Vision unpadding if active
        let data = if let Some(vision) = &mut me.vision {
            let unpadded = vision.unpad(chunk);
            if unpadded.is_empty() {
                debug!(
                    id = me.id,
                    raw_len = filled,
                    "VLESS read: unpad returned empty, waiting for more data"
                );
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            debug!(
                id = me.id,
                raw_len = filled,
                unpadded_len = unpadded.len(),
                "VLESS read: unpadded"
            );
            unpadded
        } else {
            chunk.to_vec()
        };

        // Copy to caller, buffer overflow
        let to_copy = data.len().min(buf.remaining());
        buf.put_slice(&data[..to_copy]);
        if to_copy < data.len() {
            me.read_buf = data;
            me.read_offset = to_copy;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VlessTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let me = &mut *self;

        if me.write_offset < me.write_buf.len() {
            return me
                .poll_write_pending(cx)
                .map(|res| res.map(|written| written.unwrap_or(0)));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Apply Vision padding if active
        if let Some(vision) = &mut me.vision {
            if !vision.write_direct_copy && vision.write_is_padding {
                me.write_buf = vision.pad(buf);
                me.write_offset = 0;
                me.write_pending_plain_len = buf.len();
                debug!(
                    id = me.id,
                    plain_len = buf.len(),
                    padded_len = me.write_buf.len(),
                    "VLESS write: padded"
                );
                return me
                    .poll_write_pending(cx)
                    .map(|res| res.map(|written| written.unwrap_or(0)));
            }
        }

        Pin::new(&mut me.conn).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub(crate) struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
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
