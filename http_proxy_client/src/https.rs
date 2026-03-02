use config::Address;
use parking_lot::Mutex;
use std::io::Error;
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::native_tls;
use tokio_native_tls::TlsConnector;
use tokio_native_tls::TlsStream;

#[derive(Debug, Clone)]
pub struct HttpsProxyTcpStream {
    conn: Arc<Mutex<TlsStream<TcpStream>>>,
}

impl HttpsProxyTcpStream {
    pub async fn connect(
        proxy_server: SocketAddr,
        proxy_server_domain: &str,
        addr: Address,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        let connector = TlsConnector::from(native_tls::TlsConnector::new().unwrap());
        Self::connect_with_connector(
            proxy_server,
            proxy_server_domain,
            addr,
            username,
            password,
            connector,
        )
        .await
    }

    pub async fn connect_with_connector(
        proxy_server: SocketAddr,
        proxy_server_domain: &str,
        addr: Address,
        username: Option<&str>,
        password: Option<&str>,
        connector: TlsConnector,
    ) -> Result<Self> {
        let stream = TcpStream::connect(proxy_server).await?;
        let mut conn = connector
            .connect(proxy_server_domain, stream)
            .await
            .map_err(std::io::Error::other)?;
        let authorization = match (username, password) {
            (Some(username), Some(password)) => base64::encode(format!("{username}:{password}")),
            _ => "".to_string(),
        };
        let mut req_buf = vec![format!("CONNECT {addr} HTTP/1.1")];
        if !authorization.is_empty() {
            req_buf.push(format!("Proxy-Authorization: basic {authorization}"));
        }
        req_buf.push(format!("Host: {addr}"));
        req_buf.push("\r\n".to_string());
        let req: String = req_buf.join("\r\n");
        conn.write_all(req.as_bytes()).await?;
        let mut buf = vec![0; 1500];
        let size = conn.read(&mut buf).await?;
        let resp = String::from_utf8_lossy(&buf[..size]);
        if !resp.trim().starts_with("HTTP/1.1 2") {
            return Err(Error::new(ErrorKind::NotConnected, resp));
        }
        Ok(HttpsProxyTcpStream {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl AsyncRead for HttpsProxyTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut *self.get_mut().conn.lock()).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpsProxyTcpStream {
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
