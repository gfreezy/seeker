use crate::dns_client::DnsClient;
use crate::proxy_connection::{
    ProxyConnection, ProxyConnectionEventListener, StoreListener, next_connection_id,
};
use crate::traffic::Traffic;
use async_std::net::{SocketAddr, UdpSocket};
use config::rule::Action;
use config::{ServerConfig, ServerProtocol};
use socks5_client::Socks5UdpSocket;
use ssclient::SSUdpSocket;
use std::io;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[derive(Clone)]
enum ProxyUdpSocketInner {
    Direct(Arc<UdpSocket>),
    Socks5(Arc<Socks5UdpSocket>),
    Shadowsocks(Arc<SSUdpSocket>),
}

#[derive(Clone)]
pub struct ProxyUdpSocket {
    id: u64,
    inner: ProxyUdpSocketInner,
    alive: Arc<AtomicBool>,
    config: Option<ServerConfig>,
    traffic: Traffic,
    connect_time: Instant,
    listener: Option<Arc<dyn ProxyConnectionEventListener + Send + Sync>>,
}

impl ProxyUdpSocket {
    pub async fn new(config: Option<&ServerConfig>, dns_client: DnsClient) -> io::Result<Self> {
        let socket = if let Some(config) = config {
            match config.protocol() {
                ServerProtocol::Socks5 => {
                    let server = dns_client.lookup_address(config.addr()).await?;
                    ProxyUdpSocketInner::Socks5(Arc::new(Socks5UdpSocket::new(server).await?))
                }
                ServerProtocol::Shadowsocks => {
                    let server = dns_client.lookup_address(config.addr()).await?;
                    let (method, key) = match (config.method(), config.key()) {
                        (Some(m), Some(k)) => (m, k),
                        _ => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "method and password must be set for ss protocol.",
                            ));
                        }
                    };

                    let udp = SSUdpSocket::new(server, method, key).await?;
                    ProxyUdpSocketInner::Shadowsocks(Arc::new(udp))
                }
                protocol => {
                    return Err(Error::new(
                        ErrorKind::ConnectionRefused,
                        format!("udp not supported for {protocol:?}."),
                    ));
                }
            }
        } else {
            ProxyUdpSocketInner::Direct(Arc::new(UdpSocket::bind("0.0.0.0:0").await?))
        };
        let listener: Option<Arc<dyn ProxyConnectionEventListener + Send + Sync>> =
            Some(Arc::new(StoreListener));
        let socket = ProxyUdpSocket {
            inner: socket,
            alive: Arc::new(AtomicBool::new(true)),
            config: config.cloned(),
            traffic: Default::default(),
            connect_time: Instant::now(),
            id: next_connection_id(),
            listener: listener.clone(),
        };
        if let Some(listener) = listener {
            listener.on_connect(&socket);
        }
        Ok(socket)
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if !self.is_alive() {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyUdpSocket not alive",
            ));
        }
        let ret = match &self.inner {
            ProxyUdpSocketInner::Direct(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocketInner::Socks5(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocketInner::Shadowsocks(socket) => socket.send_to(buf, addr).await,
        };
        match ret {
            Err(_) => {
                self.shutdown();
            }
            Ok(size) => {
                self.traffic.send(size);
                if let Some(listener) = &self.listener {
                    listener.on_send_bytes(self, size);
                }
            }
        }
        ret
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if !self.is_alive() {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyUdpSocket not alive",
            ));
        }
        let ret = match &self.inner {
            ProxyUdpSocketInner::Direct(socket) => socket.recv_from(buf).await,
            ProxyUdpSocketInner::Socks5(socket) => socket.recv_from(buf).await,
            ProxyUdpSocketInner::Shadowsocks(socket) => socket.recv_from(buf).await,
        };
        match ret {
            Err(_) => {
                self.shutdown();
            }
            Ok((size, _)) => {
                self.traffic.recv(size);
                if let Some(listener) = &self.listener {
                    listener.on_recv_bytes(self, size);
                }
            }
        }
        ret
    }
}

impl ProxyConnection for ProxyUdpSocket {
    fn network(&self) -> &'static str {
        "udp"
    }
    fn traffic(&self) -> Traffic {
        self.traffic.clone()
    }

    fn action(&self) -> config::rule::Action {
        match self.inner {
            ProxyUdpSocketInner::Direct(_) => Action::Direct,
            ProxyUdpSocketInner::Socks5(_) | ProxyUdpSocketInner::Shadowsocks(_) => {
                Action::Proxy("".to_string())
            }
        }
    }

    fn config(&self) -> Option<&ServerConfig> {
        self.config.as_ref()
    }

    fn has_config(&self, config: Option<&ServerConfig>) -> bool {
        self.config.as_ref() == config
    }

    fn shutdown(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Some(listener) = &self.listener {
            listener.on_shutdown(self);
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn connect_time(&self) -> std::time::Instant {
        self.connect_time
    }

    fn conn_type(&self) -> &'static str {
        match &self.inner {
            ProxyUdpSocketInner::Direct(_) => "direct",
            ProxyUdpSocketInner::Socks5(_) => "socks5",
            ProxyUdpSocketInner::Shadowsocks(_) => "shadowsocks",
        }
    }

    fn recv_bytes(&self) -> usize {
        self.traffic.received_bytes()
    }

    fn sent_bytes(&self) -> usize {
        self.traffic.sent_bytes()
    }
}
