use crate::REDIR_LISTEN_PORT;
use crate::dns_client::DnsClient;
use crate::probe_connectivity::ProbeConnectivity;
use crate::proxy_udp_socket::ProxyUdpSocket;
use crate::relay_tcp_stream::relay_tcp_stream;
use crate::relay_udp_socket::relay_udp_socket;
use crate::server_chooser::ServerChooser;
use async_std::future::pending;
use async_std::io::timeout;
use async_std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use async_std::task::{JoinHandle, spawn};
use async_std::{prelude::*, task};
use async_std_resolver::AsyncStdResolver;
use config::rule::Action;
use config::{Address, Config};
use dnsserver::create_dns_server;
use dnsserver::resolver::RuleBasedDnsResolver;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

use std::net::IpAddr;

use std::sync::Arc;
use tracing::{error, instrument, trace, trace_span};
use tracing_futures::Instrument;
use tun_nat::{SessionManager, run_nat};

pub(crate) type UdpManager = Arc<RwLock<HashMap<u16, (ProxyUdpSocket, SocketAddr, Address)>>>;

pub struct ProxyClient {
    config: Config,
    uid: Option<u32>,
    connectivity: ProbeConnectivity,
    // When in redir mode, session_manager is None
    session_manager: Option<SessionManager>,
    udp_manager: UdpManager,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsClient,
    server_chooser: ServerChooser,
    nat_join_handle: Option<JoinHandle<()>>,
    dns_server_join_handle: Option<JoinHandle<()>>,
    chooser_join_handle: Option<JoinHandle<()>>,
}

impl ProxyClient {
    pub async fn new(config: Config, uid: Option<u32>, show_stats: bool) -> Self {
        let additional_cidrs = config.rules.additional_cidrs();

        let (session_manager, nat_join_handle) = if !config.redir_mode {
            let (session_manager, blocking_join_handle) = run_nat(
                &config.tun_name,
                config.tun_ip,
                config.tun_cidr,
                REDIR_LISTEN_PORT,
                &additional_cidrs,
                config.queue_number,
                config.threads_per_queue,
            )
            .expect("run nat");
            let nat_join_handle = task::spawn_blocking(move || match blocking_join_handle.join() {
                Ok(()) => tracing::info!("nat stopped"),
                Err(e) => tracing::error!("nat stopped with error: {:?}", e),
            });
            (Some(session_manager), Some(nat_join_handle))
        } else {
            (None, None)
        };

        let dns_client = DnsClient::new(&config.dns_servers, config.dns_timeout).await;

        let (resolver, dns_server_join_handle) =
            run_dns_resolver(&config, dns_client.resolver()).await;

        let chooser = ServerChooser::new(config.clone(), dns_client.clone(), show_stats).await;
        let chooser_clone = chooser.clone();
        let chooser_join_handle = spawn(async move {
            chooser_clone
                .run_background_tasks()
                .instrument(tracing::trace_span!("ServerChooser.run_background_tasks"))
                .await
                .unwrap()
        });

        Self {
            resolver,
            connectivity: ProbeConnectivity::new(chooser.clone(), config.probe_timeout),
            udp_manager: Arc::new(RwLock::new(HashMap::new())),
            dns_client,
            config,
            uid,
            session_manager,
            server_chooser: chooser,
            nat_join_handle,
            dns_server_join_handle: Some(dns_server_join_handle),
            chooser_join_handle: Some(chooser_join_handle),
        }
    }

    async fn run_tcp_relay_server(&self) -> Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", REDIR_LISTEN_PORT))
            .await
            .inspect_err(|_e| {
                eprintln!("error: bind to {REDIR_LISTEN_PORT}");
            })?;
        let mut incoming = listener.incoming();
        while let Some(Ok(conn)) = incoming.next().await {
            let session_manager = self.session_manager.clone();
            let resolver = self.resolver.clone();
            let dns_client = self.dns_client.clone();
            let config = self.config.clone();
            let server_chooser = self.server_chooser.clone();
            let connectivity = self.connectivity.clone();
            let uid = self.uid;
            let Ok(peer_addr) = conn.peer_addr() else {
                continue;
            };
            trace!(peer_addr = ?peer_addr, "new connection");
            let session_port = peer_addr.port();

            let (real_src, real_dest, host) = match (config.redir_mode, &session_manager) {
                (true, _) => {
                    let Some(original_addr) = get_original_addr_from_socket(&conn) else {
                        panic!("redir mode is not supported on this platform");
                    };
                    let host = resolver
                        .lookup_host(&original_addr.ip().to_string())
                        .map(|s| Address::DomainNameAddress(s, original_addr.port()))
                        .unwrap_or_else(|| Address::SocketAddress(original_addr));
                    (peer_addr, original_addr, host)
                }
                (false, Some(session_manager)) => {
                    let Ok(ret) = get_real_src_real_dest_and_host(
                        session_port,
                        session_manager,
                        &resolver,
                        &dns_client,
                        &config,
                    )
                    .await
                    else {
                        continue;
                    };
                    ret
                }
                (false, None) => panic!("session manager is None in non-redir mode"),
            };

            tracing::info!("real_src: {real_src:?}, real_desc: {real_dest:?}, host: {host:?}");

            spawn(async move {
                let _ = relay_tcp_stream(
                    conn,
                    real_src,
                    real_dest,
                    host,
                    config,
                    server_chooser,
                    connectivity,
                    uid,
                    || {
                        if let Some(session_manager) = &session_manager {
                            session_manager.update_activity_for_port(session_port)
                        } else {
                            true
                        }
                    },
                )
                .await;
                if let Some(session_manager) = &session_manager {
                    session_manager.recycle_port(session_port);
                }
            });
        }
        Ok::<(), std::io::Error>(())
    }

    pub async fn run(mut self) {
        let chooser_join_handle = self.chooser_join_handle.take();
        let dns_server_join_handle = self.dns_server_join_handle.take();
        let nat_join_handle = self.nat_join_handle.take();
        let ret = self
            .run_tcp_relay_server()
            .instrument(tracing::trace_span!("ProxyClient.run_tcp_relay_server"))
            .race(async {
                if !self.config.redir_mode {
                    let ret = self
                        .run_udp_relay_server()
                        .instrument(tracing::trace_span!("ProxyClient.run_udp_relay_server"))
                        .await;
                    if let Err(e) = &ret {
                        tracing::error!(?e, "run udp relay server error");
                    }
                    ret
                } else {
                    pending::<Result<()>>().await
                }
            })
            .race(async move {
                if let Some(chooser_join_handle) = chooser_join_handle {
                    chooser_join_handle.await;
                } else {
                    pending::<()>().await;
                }
                Ok(())
            })
            .race(async move {
                if let Some(dns_server_join_handle) = dns_server_join_handle {
                    dns_server_join_handle.await;
                } else {
                    pending::<()>().await;
                };
                Ok(())
            })
            .race(async move {
                if let Some(nat_join_handle) = nat_join_handle {
                    nat_join_handle.await;
                } else {
                    pending::<()>().await;
                }
                Ok(())
            })
            .await;
        ret.expect("run proxy client");
    }

    async fn get_proxy_udp_socket(
        &self,
        tun_socket: Arc<UdpSocket>,
        tun_addr: SocketAddr,
    ) -> Result<(ProxyUdpSocket, SocketAddr, Address)> {
        let port = tun_addr.port();
        if let Some(r) = self.udp_manager.read().get(&port) {
            return Ok(r.clone());
        }

        let Some(session_manager) = self.session_manager.clone() else {
            return Err(Error::new(
                ErrorKind::Other,
                "session manager not initialized",
            ));
        };
        relay_udp_socket(
            tun_socket,
            tun_addr,
            session_manager,
            self.resolver.clone(),
            self.dns_client.clone(),
            self.config.clone(),
            self.server_chooser.clone(),
            self.connectivity.clone(),
            self.uid,
            self.udp_manager.clone(),
        )
        .await
    }

    async fn run_udp_relay_server(&self) -> Result<()> {
        assert!(
            !self.config.redir_mode,
            "UDP is not supported in redir mode, skipping"
        );
        let udp_listener = Arc::new(UdpSocket::bind(format!("0.0.0.0:{REDIR_LISTEN_PORT}")).await?);
        let mut buf = vec![0; 2000];
        loop {
            let (size, peer_addr) = udp_listener.recv_from(&mut buf).await.map_err(|e| {
                error!(?e, "udp recv error");
                e
            })?;
            assert!(size < 2000);
            let session_port = peer_addr.port();

            let tun_socket = udp_listener.clone();
            let (proxy_udp_socket, real_dest, host) =
                match self.get_proxy_udp_socket(tun_socket, peer_addr).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!(?e, "get proxy udp socket error: {:?}", e);
                        continue;
                    }
                };
            let ret = timeout(
                self.config.write_timeout,
                proxy_udp_socket.send_to(&buf[..size], real_dest),
            )
            .await;
            if let Err(e) = ret {
                error!("send udp packet error {}: {:?}", host, e);
                if let Some(session_manager) = &self.session_manager {
                    session_manager.recycle_port(session_port);
                }
            }
        }
    }
}

#[instrument(skip(real_src, real_dest, connectivity, config), ret)]
pub(crate) async fn get_action_for_addr(
    real_src: SocketAddr,
    real_dest: SocketAddr,
    addr: &Address,
    config: &Config,
    connectivity: &ProbeConnectivity,
    user_id: Option<u32>,
) -> Result<Action> {
    let mut pass_proxy = false;
    let (domain, ip) = match &addr {
        // 如果是 IP 说明是用户手动改了路由表，必须要走代理。
        Address::SocketAddress(sock_addr) => (None, Some(sock_addr.ip())),
        Address::DomainNameAddress(domain, _port) => {
            (Some(domain.to_string()), Some(real_dest.ip()))
        }
    };
    if let Some(uid) = user_id {
        if !socket_addr_belong_to_user(real_src, uid)? {
            pass_proxy = true;
        }
    }
    let action = if pass_proxy {
        Action::Direct
    } else {
        config
            .rules
            .action_for_domain(domain.as_deref(), ip)
            .unwrap_or_else(|| config.rules.default_action())
    };

    if let Action::Probe(name) = action {
        return Ok(connectivity.probe_connectivity(real_dest, addr, name).await);
    }

    Ok(action)
}

async fn run_dns_resolver(
    config: &Config,
    resolver: AsyncStdResolver,
) -> (RuleBasedDnsResolver, JoinHandle<()>) {
    let (dns_server, resolver) = create_dns_server(
        config.dns_listens.clone(),
        config.tun_bypass_direct,
        config.rules.clone(),
        resolver,
    )
    .await;
    let handle = spawn(async {
        dns_server
            .run_server()
            .instrument(trace_span!("Dns_server.run_server"))
            .await
    });
    (resolver, handle)
}

#[cfg(target_arch = "x86_64")]
fn socket_addr_belong_to_user(addr: SocketAddr, uid: u32) -> Result<bool> {
    use sysconfig::SocketInfo;
    let user_socks: HashMap<i32, Vec<SocketInfo>> = sysconfig::list_user_proc_socks(uid)?;
    Ok(user_socks
        .values()
        .any(|sockets| sockets.iter().any(|s| s.local == addr)))
}

#[cfg(not(target_arch = "x86_64"))]
fn socket_addr_belong_to_user(_addr: SocketAddr, _uid: u32) -> Result<bool> {
    Ok(true)
}

pub(crate) async fn get_real_src_real_dest_and_host(
    session_port: u16,
    session_manager: &SessionManager,
    resolver: &RuleBasedDnsResolver,
    dns_client: &DnsClient,
    config: &Config,
) -> Result<(SocketAddr, SocketAddr, Address)> {
    let (real_src, real_dest) = match session_manager.get_by_port(session_port) {
        Some(s) => s,
        None => {
            error!("session manager not found port");
            return Err(Error::new(
                std::io::ErrorKind::Other,
                "session manager not found port",
            ));
        }
    };

    trace!(src = ?real_src, dest = ?real_dest, "get real src and dest");
    let IpAddr::V4(src_ipv4) = real_src.ip() else {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "only support ipv4",
        ));
    };
    let IpAddr::V4(dest_ipv4) = real_dest.ip() else {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "only support ipv4",
        ));
    };
    let is_src_tun_ip = config.tun_cidr.contains_addr(&src_ipv4);
    let is_dest_tun_ip = config.tun_cidr.contains_addr(&dest_ipv4);

    let ip = dest_ipv4.to_string();
    let host_optional = resolver
        .lookup_host(&ip)
        .map(|s| Address::DomainNameAddress(s, real_dest.port()));

    let host = match (host_optional, is_src_tun_ip, is_dest_tun_ip) {
        (Some(h), _, _) => h,

        // 如果 src 是 tun 的 ip 且 dest 不是 tun ip，说明是指定了 ip 的访问。
        (None, true, false) => Address::SocketAddress(real_dest),

        // 如果不是 tun 的 ip，没有找到对应的域名，说明是非法的访问，需要忽略。
        _ => {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                format!("no host found for tun ip: {ip}"),
            ));
        }
    };

    trace!(dest_host = ?host, "new relay connection");

    let sock_addr = match dns_client
        .lookup_address(&host)
        .instrument(tracing::trace_span!("lookup_address", ?host))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            error!(?e, ?host, "error resolve dns");
            return Err(Error::new(
                std::io::ErrorKind::Other,
                format!("resolve dns error: {host}"),
            ));
        }
    };

    trace!(ip = ?ip, host = ?host, "lookup host");
    Ok((real_src, sock_addr, host))
}

// get original addr from socket use SO_ORIGINAL_DST
#[cfg(target_os = "linux")]
fn get_original_addr_from_socket(conn: &TcpStream) -> Option<SocketAddr> {
    // When in redir mode, we get the original destination from the socket option.

    use std::net::Ipv4Addr;
    let original_dst = nix::sys::socket::getsockopt(&conn, nix::sys::socket::sockopt::OriginalDst)
        .expect("get original dst");
    // convert sockaddr_in to SocketAddress
    // sin_addr, sin_port are stored in network edian
    let original_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(u32::from_be(original_dst.sin_addr.s_addr))),
        u16::from_be(original_dst.sin_port),
    );
    Some(original_addr)
}

#[cfg(target_os = "macos")]
fn get_original_addr_from_socket(_conn: &TcpStream) -> Option<SocketAddr> {
    None
}
