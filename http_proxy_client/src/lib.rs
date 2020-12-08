mod http;
mod https;

use async_std::io::{Read, Write};
use config::Address;
use http::HttpProxyTcpStream;
use https::HttpsProxyTcpStream;
use pin_project::pin_project;
use std::io::Result;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

#[pin_project(project = ProxyTcpStreamProj)]
#[derive(Debug, Clone)]
pub enum ProxyTcpStream {
    Http(#[pin] HttpProxyTcpStream),
    Https(#[pin] HttpsProxyTcpStream),
}

impl ProxyTcpStream {
    pub async fn connect(
        proxy_server: SocketAddr,
        proxy_server_domain: String,
        addr: Address,
        username: Option<&str>,
        password: Option<&str>,
        use_https: bool,
    ) -> Result<Self> {
        if use_https {
            Ok(ProxyTcpStream::Https(
                HttpsProxyTcpStream::connect(
                    proxy_server,
                    proxy_server_domain,
                    addr,
                    username,
                    password,
                )
                .await?,
            ))
        } else {
            Ok(ProxyTcpStream::Http(
                HttpProxyTcpStream::connect(proxy_server, addr, username, password).await?,
            ))
        }
    }
}

impl Read for ProxyTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        match self.project() {
            ProxyTcpStreamProj::Http(conn) => {
                let conn: Pin<&mut HttpProxyTcpStream> = conn;
                conn.poll_read(cx, buf)
            }
            ProxyTcpStreamProj::Https(conn) => {
                let conn: Pin<&mut HttpsProxyTcpStream> = conn;
                conn.poll_read(cx, buf)
            }
        }
    }
}

impl Write for ProxyTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        match self.project() {
            ProxyTcpStreamProj::Http(conn) => {
                let conn: Pin<&mut HttpProxyTcpStream> = conn;
                conn.poll_write(cx, buf)
            }
            ProxyTcpStreamProj::Https(conn) => {
                let conn: Pin<&mut HttpsProxyTcpStream> = conn;
                conn.poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.project() {
            ProxyTcpStreamProj::Http(conn) => {
                let conn: Pin<&mut HttpProxyTcpStream> = conn;
                conn.poll_flush(cx)
            }
            ProxyTcpStreamProj::Https(conn) => {
                let conn: Pin<&mut HttpsProxyTcpStream> = conn;
                conn.poll_flush(cx)
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.project() {
            ProxyTcpStreamProj::Http(conn) => {
                let conn: Pin<&mut HttpProxyTcpStream> = conn;
                conn.poll_close(cx)
            }
            ProxyTcpStreamProj::Https(conn) => {
                let conn: Pin<&mut HttpsProxyTcpStream> = conn;
                conn.poll_close(cx)
            }
        }
    }
}
