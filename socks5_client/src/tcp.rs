use crate::types::{
    Address, Command, HandshakeRequest, HandshakeResponse, Reply, TcpRequestHeader,
    TcpResponseHeader, SOCKS5_AUTH_METHOD_NONE,
};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct Socks5TcpStream {
    conn: TcpStream,
}

impl Socks5TcpStream {
    pub async fn connect(socks5_server: SocketAddr, addr: Address) -> Result<Self> {
        let mut conn = TcpStream::connect(socks5_server).await?;
        let handshake_req = HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_NONE]);
        handshake_req.write_to(&mut conn).await?;
        let handshake_resp = HandshakeResponse::read_from(&mut conn).await?;
        if handshake_resp.chosen_method != SOCKS5_AUTH_METHOD_NONE {
            return Err(Error::new(ErrorKind::InvalidData, "response methods error"));
        }

        let req_header = TcpRequestHeader::new(Command::TcpConnect, addr.clone());
        req_header.write_to(&mut conn).await?;
        let resp_header = TcpResponseHeader::read_from(&mut conn).await?;
        if resp_header.reply != Reply::Succeeded {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("reply error: {:?}", resp_header.reply),
            ));
        }

        Ok(Socks5TcpStream { conn })
    }
}

impl AsyncRead for Socks5TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for Socks5TcpStream {
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
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_req_baidu() -> Result<()> {
        let mut conn = Socks5TcpStream::connect(
            "127.0.0.1:1086".parse().unwrap(),
            Address::DomainNameAddress("t.cn".to_string(), 80),
        )
        .await?;
        conn.write_all(r#"GET / HTTP/1.1\r\nHost: t.cn\r\n\r\n"#.as_bytes())
            .await?;
        let mut resp = vec![0; 1024];
        let size = conn.read(&mut resp).await?;
        let resp_text = String::from_utf8_lossy(&resp[..size]).to_string();
        assert!(resp_text.contains("HTTP/1.1"));
        Ok(())
    }
}
