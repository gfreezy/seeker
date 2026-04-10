use crate::dns_client::DnsClient;
use crate::hy2_pool::get_hy2_client;
use crate::proxy_connection::{
    ProxyConnection, ProxyConnectionEventListener, StoreListener, next_connection_id,
};
use crate::traffic::Traffic;
use config::rule::Action;
use config::{ServerConfig, ServerProtocol};
use hysteria2_client::Hy2UdpSocket;
use socks5_client::Socks5UdpSocket;
use ssclient::SSUdpSocket;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::net::UdpSocket;
use trojan_client::TrojanUdpSocket;
use vless_client::VlessUdpSocket;

#[derive(Clone)]
enum ProxyUdpSocketInner {
    Direct(Arc<UdpSocket>),
    Socks5(Arc<Socks5UdpSocket>),
    Shadowsocks(Arc<SSUdpSocket>),
    Hysteria2(Arc<Hy2UdpSocket>),
    Trojan(Arc<TrojanUdpSocket>),
    Vless(Arc<VlessUdpSocket>),
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
                ServerProtocol::Hysteria2 => {
                    let server = dns_client.lookup_address(config.addr()).await?;
                    let client = get_hy2_client(config, server)?;
                    let udp = Hy2UdpSocket::new(client).await?;
                    ProxyUdpSocketInner::Hysteria2(Arc::new(udp))
                }
                ServerProtocol::Trojan => {
                    let server = dns_client.lookup_address(config.addr()).await?;
                    let sni = config
                        .sni()
                        .map(|s| s.to_string())
                        .or_else(|| config.addr().hostname().map(|s| s.to_string()))
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidData,
                                "sni or domain must be set for trojan protocol.",
                            )
                        })?;
                    let password = config.password().unwrap_or("");
                    let udp =
                        TrojanUdpSocket::new(server, &sni, password, config.insecure()).await?;
                    ProxyUdpSocketInner::Trojan(Arc::new(udp))
                }
                ServerProtocol::Vless => {
                    let server = dns_client.lookup_address(config.addr()).await?;
                    let uuid = config.username().ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidData,
                            "uuid (username) must be set for vless protocol.",
                        )
                    })?;
                    let sni = config
                        .sni()
                        .map(|s| s.to_string())
                        .or_else(|| config.addr().hostname().map(|s| s.to_string()))
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidData,
                                "sni or domain must be set for vless protocol.",
                            )
                        })?;
                    let udp =
                        VlessUdpSocket::new(server, &sni, uuid, config.flow(), config.insecure())
                            .await?;
                    ProxyUdpSocketInner::Vless(Arc::new(udp))
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
            ProxyUdpSocketInner::Hysteria2(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocketInner::Trojan(socket) => socket.send_to(buf, addr).await,
            ProxyUdpSocketInner::Vless(socket) => socket.send_to(buf, addr).await,
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
            ProxyUdpSocketInner::Hysteria2(socket) => socket.recv_from(buf).await,
            ProxyUdpSocketInner::Trojan(socket) => socket.recv_from(buf).await,
            ProxyUdpSocketInner::Vless(socket) => socket.recv_from(buf).await,
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
            ProxyUdpSocketInner::Socks5(_)
            | ProxyUdpSocketInner::Shadowsocks(_)
            | ProxyUdpSocketInner::Hysteria2(_)
            | ProxyUdpSocketInner::Trojan(_)
            | ProxyUdpSocketInner::Vless(_) => Action::Proxy("".to_string()),
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
            ProxyUdpSocketInner::Hysteria2(_) => "hy2",
            ProxyUdpSocketInner::Trojan(_) => "trojan",
            ProxyUdpSocketInner::Vless(_) => "vless",
        }
    }

    fn recv_bytes(&self) -> usize {
        self.traffic.received_bytes()
    }

    fn sent_bytes(&self) -> usize {
        self.traffic.sent_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyUdpSocket;
    use crate::dns_client::DnsClient;
    use crate::proxy_connection::ProxyConnection;
    use config::ServerConfig;
    use std::net::SocketAddr;
    use std::time::Duration;

    async fn make_dns_client() -> DnsClient {
        DnsClient::new(
            &[config::DnsServerAddr::UdpSocketAddr(
                "8.8.8.8:53".parse().unwrap(),
            )],
            Duration::from_secs(5),
        )
        .await
    }

    fn vless_server_config_japan_01() -> ServerConfig {
        let json = r#"{"name":"Japan-01","type":"vless","server":"proxy.example.com","port":10341,"uuid":"00000000-0000-0000-0000-000000000000","udp":true,"tls":true,"flow":"xtls-rprx-vision","skip-cert-verify":true,"servername":"sni.example.dev","network":"tcp"}"#;
        serde_json::from_str(json).unwrap()
    }

    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34]);
        buf.extend_from_slice(&[0x01, 0x00]);
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00);
        buf.push((qtype >> 8) as u8);
        buf.push(qtype as u8);
        buf.extend_from_slice(&[0x00, 0x01]);
        buf
    }

    #[tokio::test]
    async fn test_proxy_udp_socket_vless_dns_japan_01() {
        store::Store::setup_global_for_test();
        let config = vless_server_config_japan_01();
        let dns_client = make_dns_client().await;

        let udp = match tokio::time::timeout(
            Duration::from_secs(10),
            ProxyUdpSocket::new(Some(&config), dns_client),
        )
        .await
        {
            Ok(Ok(socket)) => socket,
            Ok(Err(e)) => panic!("ProxyUdpSocket create failed: {e}"),
            Err(_) => panic!("ProxyUdpSocket create timed out"),
        };
        eprintln!(
            "[test-vless-udp] ProxyUdpSocket created, conn_type={}",
            udp.conn_type()
        );

        let dns_query = build_dns_query("www.baidu.com", 1);
        let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();

        match tokio::time::timeout(Duration::from_secs(10), udp.send_to(&dns_query, dns_server))
            .await
        {
            Ok(Ok(size)) => eprintln!("[test-vless-udp] sent {size} bytes"),
            Ok(Err(e)) => panic!("VLESS UDP send failed: {e}"),
            Err(_) => panic!("VLESS UDP send timed out"),
        }

        let mut buf = [0u8; 512];
        let (n, from) =
            match tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf)).await {
                Ok(Ok(ret)) => ret,
                Ok(Err(e)) => panic!("VLESS UDP recv failed: {e}"),
                Err(_) => panic!("VLESS UDP recv timed out"),
            };
        eprintln!("[test-vless-udp] recv {n} bytes from {from}");

        assert_eq!(from, dns_server);
        assert!(n > 12, "DNS response too short");
        assert_eq!(buf[0], dns_query[0]);
        assert_eq!(buf[1], dns_query[1]);
        assert!(buf[2] & 0x80 != 0, "expected DNS response (QR=1)");
    }
}
