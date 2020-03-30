use crate::connection::Connection;
use async_std::io::{timeout, Read, Write};
use async_std::net::{SocketAddr, TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task::spawn;
use config::{Address, Config};
use dnsserver::create_dns_server;
use dnsserver::resolver::{resolve_domain, RuleBasedDnsResolver};
use hermesdns::DnsNetworkClient;
use socks5_client::Socks5TcpStream;
use ssclient::SSTcpStream;
use std::io;
use std::io::{ErrorKind, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, trace, trace_span};
use tracing_futures::Instrument;
use tun_nat::{run_nat, SessionManager};

#[derive(Clone)]
pub struct ProxyClient {
    config: Config,
    uid: Option<u16>,
    term: Arc<AtomicBool>,
    session_manager: SessionManager,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsNetworkClient,
}

impl ProxyClient {
    pub async fn new(config: Config, uid: Option<u16>, term: Arc<AtomicBool>) -> Self {
        let session_manager =
            run_nat(&config.tun_name, config.tun_ip, config.tun_cidr, 1300).expect("run nat");

        let resolver = run_dns_resolver(&config).await;
        Self {
            resolver,
            config,
            uid,
            term,
            session_manager,
            dns_client: DnsNetworkClient::new(0, Duration::from_secs(1)).await,
        }
    }

    async fn get_remote_conn(&self, remote_addr: &Address) -> Result<Connection> {
        let addr = self.resolve(remote_addr).await?;
        if self.probe_connectivity(addr).await {
            return Ok(Connection::Direct(TcpStream::connect(addr).await?));
        }

        if let Some(socks5_config) = &self.config.socks5_server {
            let server = self.resolve(&socks5_config.addr).await?;
            return Ok(Connection::Socks5(
                Socks5TcpStream::connect(server, remote_addr.clone()).await?,
            ));
        }

        if let Some(ss_servers) = self.config.shadowsocks_servers.clone() {
            let ss_server = ss_servers.first().unwrap();
            let server = self.resolve(ss_server.addr()).await?;
            return Ok(Connection::Shadowsocks(
                SSTcpStream::connect(
                    remote_addr.clone(),
                    server,
                    ss_server.method(),
                    ss_server.key(),
                    ss_server.connect_timeout(),
                )
                .await?,
            ));
        }

        Ok(Connection::Direct(TcpStream::connect(addr).await?))
    }

    async fn resolve(&self, addr: &Address) -> Result<SocketAddr> {
        let dns_server = self.config.dns_server.ip().to_string();
        let dns_port = self.config.dns_server.port();
        let sock_addr = match addr {
            Address::SocketAddress(addr) => *addr,
            Address::DomainNameAddress(domain, port) => {
                let ip = resolve_domain(&self.dns_client, (&dns_server, dns_port), domain).await?;
                match ip {
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("domain {} not found", &domain),
                        ))
                    }
                    Some(ip) => SocketAddr::new(ip.parse().unwrap(), *port),
                }
            }
        };
        Ok(sock_addr)
    }

    async fn probe_connectivity(&self, addr: SocketAddr) -> bool {
        timeout(self.config.probe_timeout, TcpStream::connect(addr))
            .await
            .is_ok()
    }

    async fn run_tcp_relay_server(&self) -> Result<()> {
        let listener = TcpListener::bind((self.config.tun_ip, 1300)).await?;
        let mut incoming = listener.incoming();
        loop {
            let conn = timeout(Duration::from_secs(1), async {
                incoming.next().await.transpose()
            })
            .await;
            let conn = match conn {
                Ok(Some(conn)) => conn,
                Ok(None) => break,
                Err(e) if e.kind() == ErrorKind::TimedOut => {
                    if self.term.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            let peer_addr = conn.peer_addr()?;
            let (real_src_addr, real_dest_addr) =
                self.session_manager.get_by_port(peer_addr.port());
            let resolver_clone = self.resolver.clone();
            let proxy_client = self.clone();

            trace!(
                ?peer_addr,
                ?real_src_addr,
                ?real_dest_addr,
                "new relay connection"
            );
            let ip = real_dest_addr.ip().to_string();
            let host = resolver_clone
                .lookup_host(&ip)
                .instrument(trace_span!("lookup host", ip = ?ip))
                .await
                .map(|s| Address::DomainNameAddress(s, real_dest_addr.port()))
                .unwrap_or_else(|| Address::SocketAddress(real_dest_addr.into()));
            trace!(ip = ?ip, host = ?host, "lookup host");
            match proxy_client.get_remote_conn(&host).await {
                Ok(remote_conn) => {
                    spawn(
                        async move {
                            trace!("tunneling");
                            tunnel_tcp_stream(conn, remote_conn).await?;
                            Ok::<(), io::Error>(())
                        }
                        .instrument(trace_span!(
                            "tunnel",
                            ?peer_addr,
                            ?real_src_addr,
                            ?real_dest_addr,
                            ?host,
                        )),
                    );
                }
                Err(e) => {
                    error!(?e, "get remote conn error");
                }
            }
        }
        Ok::<(), io::Error>(())
    }

    pub async fn run(&self) {
        self.run_tcp_relay_server().await.unwrap()
    }
}

async fn tunnel_tcp_stream<T1: Read + Write + Unpin + Clone, T2: Read + Write + Unpin + Clone>(
    mut conn1: T1,
    mut conn2: T2,
) -> Result<()> {
    let mut conn1_clone = conn1.clone();
    let mut conn2_clone = conn2.clone();
    let f1 = async {
        let mut buf = vec![0; 1500];
        loop {
            let size = conn1.read(&mut buf).await?;
            if size == 0 {
                break Ok(());
            }
            conn2.write_all(&buf[..size]).await?;
        }
    };
    let f2 = async {
        let mut buf = vec![0; 1500];
        loop {
            let size = conn2_clone.read(&mut buf).await?;
            if size == 0 {
                break Ok(());
            }
            conn1_clone.write_all(&buf[..size]).await?;
        }
    };
    f1.race(f2).await
}

async fn run_dns_resolver(config: &Config) -> RuleBasedDnsResolver {
    let (dns_server, resolver) = create_dns_server(
        "dns.db",
        config.dns_listen.clone(),
        config.dns_start_ip,
        config.rules.clone(),
        (config.dns_server.ip().to_string(), config.dns_server.port()),
    )
    .await;
    println!("Spawn DNS server");
    spawn(
        dns_server
            .run_server()
            .instrument(trace_span!("dns_server.run_server")),
    );
    resolver
}
