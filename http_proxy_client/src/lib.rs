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
    pub async fn connect(proxy_server: SocketAddr, addr: Address) -> Result<Self> {
        let mut conn = TcpStream::connect(proxy_server).await?;
        conn.write_all(format!("CONNECT {} HTTP/1.1\r\n\r\n", addr).as_bytes())
            .await?;
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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use async_std::io::prelude::{ReadExt, WriteExt};
//     use async_std::task::block_on;
//
//     #[test]
//     fn test_req_baidu() -> Result<()> {
//         block_on(async {
//             let mut conn = HttpProxyTcpStream::connect(
//                 "127.0.0.1:1087".parse().unwrap(),
//                 Address::DomainNameAddress("twitter.com".to_string(), 80),
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
