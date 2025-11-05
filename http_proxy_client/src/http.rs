use config::Address;
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
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

impl AsyncRead for HttpProxyTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpProxyTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::ToSocketAddrs;

    #[ignore]
    #[tokio::test]
    async fn test_req_baidu() -> Result<()> {
        let proxy_server = "";
        let username = Some("");
        let password = Some("");
        let mut conn = HttpProxyTcpStream::connect(
            proxy_server.to_socket_addrs().unwrap().next().unwrap(),
            Address::DomainNameAddress("twitter.com".to_string(), 80),
            username,
            password,
        )
        .await?;
        conn.write_all(r#"GET / HTTP/1.1\r\nHost: twitter.com\r\n\r\n"#.as_bytes())
            .await?;
        let mut resp = vec![0; 1024];
        let size = conn.read(&mut resp).await?;
        let resp_text = String::from_utf8_lossy(&resp[..size]).to_string();
        assert!(dbg!(resp_text).contains("HTTP/1.1"));
        Ok(())
    }
}
