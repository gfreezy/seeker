use crate::dns_client::DnsClient;
use async_std::net::{SocketAddr, UdpSocket};
use config::{ServerConfig, ServerProtocol};
use socks5_client::Socks5UdpSocket;
use ssclient::SSUdpSocket;
use std::io;
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
enum ProxyUdpSocketInner {
    Direct(Arc<UdpSocket>),
    Socks5(Arc<Socks5UdpSocket>),
    Shadowsocks(Arc<SSUdpSocket>),
}

#[derive(Clone)]
pub struct ProxyUdpSocket {
    inner: ProxyUdpSocketInner,
    alive: Arc<AtomicBool>,
}

impl ProxyUdpSocket {
    pub async fn new(
        config: Option<&ServerConfig>,
        alive: Arc<AtomicBool>,
        dns_client: DnsClient,
    ) -> io::Result<Self> {
        let socket = if let Some(config) = config {
            match config.protocol() {
                ServerProtocol::Socks5 => {
                    let server = dns_client.lookup_address(&config.addr()).await?;
                    ProxyUdpSocketInner::Socks5(Arc::new(Socks5UdpSocket::new(server).await?))
                }
                ServerProtocol::Shadowsocks => {
                    let server = dns_client.lookup_address(&config.addr()).await?;
                    let (method, password) = match (config.method(), config.password()) {
                        (Some(m), Some(pass)) => (m, pass.as_bytes()),
                        _ => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "method and password must be set for ss protocol.",
                            ))
                        }
                    };

                    let key = method.bytes_to_key(password);
                    let udp = SSUdpSocket::new(server, method, key).await?;
                    ProxyUdpSocketInner::Shadowsocks(Arc::new(udp))
                }
                _ => ProxyUdpSocketInner::Direct(Arc::new(UdpSocket::bind("0.0.0.0:0").await?)),
            }
        } else {
            ProxyUdpSocketInner::Direct(Arc::new(UdpSocket::bind("0.0.0.0:0").await?))
        };
        Ok(ProxyUdpSocket {
            inner: socket,
            alive,
        })
    }
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            ));
        }
        match &self.inner {
            ProxyUdpSocketInner::Direct(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocketInner::Socks5(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocketInner::Shadowsocks(socket) => socket.send_to(buf, addr).await,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            ));
        }
        match &self.inner {
            ProxyUdpSocketInner::Direct(socket) => socket.recv_from(buf).await,
            ProxyUdpSocketInner::Socks5(socket) => socket.recv_from(buf).await,
            ProxyUdpSocketInner::Shadowsocks(socket) => socket.recv_from(buf).await,
        }
    }
}
