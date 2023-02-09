use async_std::io::prelude::{Read, ReadExt, Write, WriteExt};
use async_std::net::{SocketAddr, TcpStream};
use async_std::task::{Context, Poll};
use config::Address;
use std::io::{ErrorKind, Result};
use std::pin::Pin;

#[derive(Debug, Clone)]
pub struct HttpProxyTcpStream {
    conn: TcpStream,
}

impl HttpProxyTcpStream {
    pub async fn connect(
        proxy_server: SocketAddr,
        addr: Address,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self> {
        let mut conn = TcpStream::connect(proxy_server).await?;
        let authorization = match (username, password) {
            (Some(username), Some(password)) => base64::encode(format!("{username}:{password}")),
            _ => "".to_string(),
        };
        let mut req_buf = vec![format!("CONNECT {addr} HTTP/1.1")];
        if !authorization.is_empty() {
            req_buf.push(format!("Proxy-Authorization: Basic {authorization}"));
        }
        req_buf.push(format!("Host: {addr}"));
        req_buf.push("\r\n".to_string());
        let req: String = req_buf.join("\r\n");
        conn.write_all(req.as_bytes()).await?;
        let mut buf = vec![0; 1500];
        let size = conn.read(&mut buf).await?;
        let resp = String::from_utf8_lossy(&buf[..size]);
        if !resp.trim().starts_with("HTTP/1.1 2") {
            return Err(ErrorKind::NotConnected.into());
        }
        Ok(HttpProxyTcpStream { conn })
    }
}

impl Read for HttpProxyTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut &self.conn).poll_read(cx, buf)
    }
}

impl Write for HttpProxyTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut &self.conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &self.conn).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &self.conn).poll_close(cx)
    }
}

impl Read for &HttpProxyTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut &self.conn).poll_read(cx, buf)
    }
}

impl Write for &HttpProxyTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut &self.conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &self.conn).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut &self.conn).poll_close(cx)
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
//     fn test_req_baidu() -> Result<()> {
//         block_on(async {
//             let proxy_server = "";
//             let username = Some("");
//             let password = Some("");
//             let mut conn = HttpProxyTcpStream::connect(
//                 proxy_server.to_socket_addrs().unwrap().next().unwrap(),
//                 Address::DomainNameAddress("twitter.com".to_string(), 80),
//                 username,
//                 password,
//             )
//             .await?;
//             conn.write_all(r#"GET / HTTP/1.1\r\nHost: twitter.com\r\n\r\n"#.as_bytes())
//                 .await?;
//             let mut resp = vec![0; 1024];
//             let size = conn.read(&mut resp).await?;
//             let resp_text = String::from_utf8_lossy(&resp[..size]).to_string();
//             assert!(dbg!(resp_text).contains("HTTP/1.1"));
//             Ok(())
//         })
//     }
// }
