use async_std::io::{Read, Write};
use async_std::net::TcpStream;
use config::rule::Action;
use config::{Address, ServerConfig, ServerProtocol};
use http_proxy_client::{HttpProxyTcpStream, HttpsProxyTcpStream};
use socks5_client::Socks5TcpStream;
use ssclient::SSTcpStream;
use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use tcp_connection::TcpConnection;

use crate::dns_client::DnsClient;
use crate::proxy_connection::{
    next_connection_id, ProxyConnection, ProxyConnectionEventListener, StoreListener,
};
use crate::traffic::Traffic;
use async_std::task::ready;
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
enum ProxyTcpStreamInner {
    Direct(TcpStream),
    Socks5(Socks5TcpStream),
    HttpProxy(HttpProxyTcpStream),
    HttpsProxy(HttpsProxyTcpStream),
    Shadowsocks(SSTcpStream),
}

#[derive(Clone)]
pub struct ProxyTcpStream {
    id: u64,
    inner: ProxyTcpStreamInner,
    alive: Arc<AtomicBool>,
    remote_addr: Address,
    config: Option<ServerConfig>,
    traffic: Traffic,
    connect_time: Instant,
    event_listener: Option<Arc<dyn ProxyConnectionEventListener + Send + Sync>>,
}

impl ProxyTcpStream {
    #[tracing::instrument(skip(config, dns_client))]
    pub async fn connect(
        remote_addr: Address,
        config: Option<&ServerConfig>,
        dns_client: DnsClient,
    ) -> Result<ProxyTcpStream> {
        let remote_addr_clone = remote_addr.clone();
        let stream = if let Some(config) = config {
            let proxy_socket_addr = dns_client.lookup_address(config.addr()).await?;
            match config.protocol() {
                ServerProtocol::Https => {
                    let proxy_hostname = match config.addr().hostname() {
                        None => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "proxy domain must not be empty for https protocol.",
                            ))
                        }
                        Some(s) => s,
                    };
                    ProxyTcpStreamInner::HttpsProxy(
                        HttpsProxyTcpStream::connect(
                            proxy_socket_addr,
                            proxy_hostname,
                            remote_addr,
                            config.username(),
                            config.password(),
                        )
                        .await?,
                    )
                }
                ServerProtocol::Http => ProxyTcpStreamInner::HttpProxy(
                    HttpProxyTcpStream::connect(
                        proxy_socket_addr,
                        remote_addr,
                        config.username(),
                        config.password(),
                    )
                    .await?,
                ),
                ServerProtocol::Socks5 => ProxyTcpStreamInner::Socks5(
                    Socks5TcpStream::connect(proxy_socket_addr, remote_addr).await?,
                ),
                ServerProtocol::Shadowsocks => {
                    let (method, key) = match (config.method(), config.key()) {
                        (Some(m), Some(k)) => (m, k),
                        _ => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "method and password must be set for ss protocol.",
                            ))
                        }
                    };
                    let stream = if let Some(obfs) = config.obfs() {
                        TcpConnection::connect_obfs(proxy_socket_addr, obfs.host.clone(), obfs.mode)
                            .await?
                    } else {
                        TcpConnection::connect_tcp(proxy_socket_addr).await?
                    };
                    ProxyTcpStreamInner::Shadowsocks(
                        SSTcpStream::connect(stream, remote_addr, method, key).await?,
                    )
                }
            }
        } else {
            let socket_addr = dns_client.lookup_address(&remote_addr).await?;
            ProxyTcpStreamInner::Direct(TcpStream::connect(socket_addr).await?)
        };

        let event_listener: Option<Arc<dyn ProxyConnectionEventListener + Send + Sync>> =
            Some(Arc::new(StoreListener));
        let l = event_listener.clone();
        let conn = ProxyTcpStream {
            id: next_connection_id(),
            inner: stream,
            alive: Arc::new(AtomicBool::new(true)),
            remote_addr: remote_addr_clone,
            config: config.cloned(),
            traffic: Traffic::default(),
            connect_time: Instant::now(),
            event_listener: Some(Arc::new(StoreListener)),
        };
        if let Some(l) = l {
            l.on_connect(&conn);
        }
        Ok(conn)
    }
}

impl ProxyConnection for ProxyTcpStream {
    fn traffic(&self) -> Traffic {
        self.traffic.clone()
    }

    fn config(&self) -> Option<&ServerConfig> {
        self.config.as_ref()
    }

    fn has_config(&self, config: Option<&ServerConfig>) -> bool {
        self.config.as_ref() == config
    }

    fn shutdown(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Some(l) = &self.event_listener {
            l.on_shutdown(self);
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn remote_addr(&self) -> Option<&Address> {
        Some(&self.remote_addr)
    }

    fn action(&self) -> config::rule::Action {
        match self.inner {
            ProxyTcpStreamInner::Direct(_) => Action::Direct,
            ProxyTcpStreamInner::Socks5(_)
            | ProxyTcpStreamInner::HttpProxy(_)
            | ProxyTcpStreamInner::HttpsProxy(_)
            | ProxyTcpStreamInner::Shadowsocks(_) => Action::Proxy,
        }
    }

    fn connect_time(&self) -> Instant {
        self.connect_time
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn network(&self) -> &'static str {
        "tcp"
    }

    fn conn_type(&self) -> &'static str {
        match self.inner {
            ProxyTcpStreamInner::Direct(_) => "direct",
            ProxyTcpStreamInner::Socks5(_) => "socks5",
            ProxyTcpStreamInner::HttpProxy(_) => "http",
            ProxyTcpStreamInner::HttpsProxy(_) => "https",
            ProxyTcpStreamInner::Shadowsocks(_) => "ss",
        }
    }

    fn recv_bytes(&self) -> usize {
        self.traffic.received_bytes()
    }

    fn sent_bytes(&self) -> usize {
        self.traffic.sent_bytes()
    }
}

impl Read for ProxyTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        let stream = &mut *self;
        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Direct(conn) => {
                Pin::new(conn).poll_read(cx, buf)
            }
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStreamInner::HttpProxy(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStreamInner::HttpsProxy(conn) => Pin::new(conn).poll_read(cx, buf),
        });

        match ret {
            Ok(size) => {
                self.traffic.recv(size);
                if let Some(l) = &self.event_listener {
                    l.on_recv_bytes(&*self, size);
                }
                Poll::Ready(Ok(size))
            }
            e => {
                self.shutdown();
                Poll::Ready(e)
            }
        }
    }
}

impl Write for ProxyTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let stream = &mut *self;
        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Direct(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStreamInner::HttpProxy(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStreamInner::HttpsProxy(conn) => Pin::new(conn).poll_write(cx, buf),
        });
        match ret {
            Ok(size) => {
                self.traffic.send(size);
                if let Some(l) = &self.event_listener {
                    l.on_send_bytes(&*self, size);
                }
                Poll::Ready(Ok(size))
            }
            err => {
                self.shutdown();
                Poll::Ready(err)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let stream = &mut *self;
        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Direct(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStreamInner::HttpProxy(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStreamInner::HttpsProxy(conn) => Pin::new(conn).poll_flush(cx),
        });
        match ret {
            Ok(()) => Poll::Ready(Ok(())),
            err => {
                self.shutdown();
                Poll::Ready(err)
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let stream = &mut *self;
        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Direct(conn) => Pin::new(conn).poll_close(cx),
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_close(cx),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_close(cx),
            ProxyTcpStreamInner::HttpProxy(conn) => Pin::new(conn).poll_close(cx),
            ProxyTcpStreamInner::HttpsProxy(conn) => Pin::new(conn).poll_close(cx),
        });
        self.shutdown();
        Poll::Ready(ret)
    }
}
