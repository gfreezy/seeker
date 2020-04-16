use async_std::io::{Read, Write};
use async_std::net::TcpStream;
use http_proxy_client::HttpProxyTcpStream;
use socks5_client::Socks5TcpStream;
use ssclient::SSTcpStream;
use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Clone)]
pub enum ProxyTcpStream {
    Direct(TcpStream),
    Socks5(Socks5TcpStream),
    HttpProxy(HttpProxyTcpStream),
    Shadowsocks(SSTcpStream),
}

impl Read for ProxyTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        match &mut *self {
            ProxyTcpStream::Direct(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStream::Socks5(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStream::Shadowsocks(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStream::HttpProxy(conn) => Pin::new(conn).poll_read(cx, buf),
        }
    }
}
impl Write for ProxyTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        match &mut *self {
            ProxyTcpStream::Direct(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStream::Socks5(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStream::Shadowsocks(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStream::HttpProxy(conn) => Pin::new(conn).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match &mut *self {
            ProxyTcpStream::Direct(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStream::Socks5(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStream::Shadowsocks(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStream::HttpProxy(conn) => Pin::new(conn).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match &mut *self {
            ProxyTcpStream::Direct(conn) => Pin::new(conn).poll_close(cx),
            ProxyTcpStream::Socks5(conn) => Pin::new(conn).poll_close(cx),
            ProxyTcpStream::Shadowsocks(conn) => Pin::new(conn).poll_close(cx),
            ProxyTcpStream::HttpProxy(conn) => Pin::new(conn).poll_close(cx),
        }
    }
}
