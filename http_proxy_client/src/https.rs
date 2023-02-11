use async_std::io::prelude::{Read, ReadExt, Write, WriteExt};
use async_std::net::{SocketAddr, TcpStream};
use async_std::task::{Context, Poll};
use async_tls::client::TlsStream;
use async_tls::TlsConnector;
use config::Address;
use parking_lot::Mutex;
use std::io::Error;
use std::io::{ErrorKind, Result};
use std::pin::Pin;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct HttpsProxyTcpStream {
    conn: Arc<Mutex<TlsStream<TcpStream>>>,
}

impl HttpsProxyTcpStream {
    pub async fn connect(
        proxy_server: SocketAddr,
        proxy_server_domain: String,
        addr: Address,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        let connector = TlsConnector::default();
        let stream = TcpStream::connect(proxy_server).await?;
        let mut conn = connector.connect(proxy_server_domain, stream).await?;
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

impl Read for HttpsProxyTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut &*self).poll_read(cx, buf)
    }
}

impl Write for HttpsProxyTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut &*self).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &*self).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &*self).poll_close(cx)
    }
}

impl Read for &HttpsProxyTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut *self.conn.lock()).poll_read(cx, buf)
    }
}

impl Write for &HttpsProxyTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut *self.conn.lock()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut *self.conn.lock()).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut *self.conn.lock()).poll_close(cx)
    }
}
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use async_std::io::prelude::{ReadExt, WriteExt};
//     use async_std::task::block_on;
//     use std::net::ToSocketAddrs;
//
//     #[test]
//     fn test_req_twitter() -> Result<()> {
//         block_on(async {
//             let proxy_domain = "";
//             let port = 443;
//             let proxy_server = format!("{}:{}", proxy_domain, port);
//             let username = Some("");
//             let password = Some("");
//             let target_host = "twitter.com";
//             let stream = HttpsProxyTcpStream::connect(
//                 proxy_server.to_socket_addrs().unwrap().next().unwrap(),
//                 proxy_domain.to_string(),
//                 Address::DomainNameAddress(target_host.to_string(), 443),
//                 username,
//                 password,
//             )
//             .await
//             .expect("connect proxy error");
//
//             let connector: TlsConnector = TlsConnector::default();
//
//             let mut conn = connector
//                 .connect(target_host, stream)
//                 .await
//                 .expect("connect proxy domain");
//
//             conn.write_all(
//                 format!(
//                     "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n",
//                     target_host
//                 )
//                 .as_bytes(),
//             )
//             .await?;
//             let mut resp = vec![0; 1024];
//             let size = conn.read(&mut resp).await?;
//
//             let resp_text = String::from_utf8_lossy(&resp[..size]).to_string();
//             eprintln!("{}", &resp_text);
//             assert!(resp_text.contains("HTTP/1.1"));
//             Ok(())
//         })
//     }
// }
