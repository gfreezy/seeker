use async_std::io::{Read, Write};
use async_std::net::TcpStream;
use socks5_client::Socks5TcpStream;
use ssclient::SSTcpStream;
use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Clone)]
pub enum Connection {
    Direct(TcpStream),
    Socks5(Socks5TcpStream),
    Shadowsocks(SSTcpStream),
}

impl Read for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        match &mut *self {
            Connection::Direct(conn) => Pin::new(conn).poll_read(cx, buf),
            Connection::Socks5(conn) => Pin::new(conn).poll_read(cx, buf),
            Connection::Shadowsocks(conn) => Pin::new(conn).poll_read(cx, buf),
        }
    }
}
impl Write for Connection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        match &mut *self {
            Connection::Direct(conn) => Pin::new(conn).poll_write(cx, buf),
            Connection::Socks5(conn) => Pin::new(conn).poll_write(cx, buf),
            Connection::Shadowsocks(conn) => Pin::new(conn).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match &mut *self {
            Connection::Direct(conn) => Pin::new(conn).poll_flush(cx),
            Connection::Socks5(conn) => Pin::new(conn).poll_flush(cx),
            Connection::Shadowsocks(conn) => Pin::new(conn).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match &mut *self {
            Connection::Direct(conn) => Pin::new(conn).poll_close(cx),
            Connection::Socks5(conn) => Pin::new(conn).poll_close(cx),
            Connection::Shadowsocks(conn) => Pin::new(conn).poll_close(cx),
        }
    }
}
