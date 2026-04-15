use crate::protocol::{encode_trojan_request, hash_password, CMD_CONNECT};
use bytes::BytesMut;
use config::Address;
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tcp_connection::tls::get_tls_connector;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub struct TrojanTcpStream {
    conn: Arc<Mutex<TlsStream<TcpStream>>>,
}

impl TrojanTcpStream {
    pub async fn connect(
        server: SocketAddr,
        sni: &str,
        addr: Address,
        password: &str,
        insecure: bool,
    ) -> Result<Self> {
        let connector = get_tls_connector(insecure);
        Self::connect_with_connector(server, sni, addr, password, connector).await
    }

    pub async fn connect_with_connector(
        server: SocketAddr,
        sni: &str,
        addr: Address,
        password: &str,
        connector: TlsConnector,
    ) -> Result<Self> {
        let tcp_stream = TcpStream::connect(server).await?;
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid SNI: {e}")))?;
        let mut tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(Error::other)?;

        let password_hash = hash_password(password);
        let mut buf = BytesMut::with_capacity(128);
        encode_trojan_request(&password_hash, CMD_CONNECT, &addr, &mut buf);
        tls_stream.write_all(&buf).await?;

        Ok(TrojanTcpStream {
            conn: Arc::new(Mutex::new(tls_stream)),
        })
    }
}

impl AsyncRead for TrojanTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut *self.get_mut().conn.lock()).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrojanTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut *self.get_mut().conn.lock()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut *self.get_mut().conn.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut *self.get_mut().conn.lock()).poll_shutdown(cx)
    }
}
