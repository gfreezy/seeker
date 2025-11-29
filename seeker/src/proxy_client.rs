use crate::REDIR_LISTEN_PORT;
use crate::dns_client::DnsClient;
use crate::icmp_relay::IcmpRelay;
use crate::network_monitor::spawn_network_monitor;
use crate::probe_connectivity::ProbeConnectivity;
use crate::relay_tcp_stream::relay_tcp_stream;
use crate::relay_udp_socket::relay_udp_socket;
use crate::server_chooser::{CandidateUdpSocket, ServerChooser};
use config::rule::Action;
use config::{Address, Config};
use dnsserver::create_dns_server;
use dnsserver::resolver::RuleBasedDnsResolver;
use hickory_resolver::TokioResolver;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::future::pending;
use std::io::{Error, Result};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use std::net::IpAddr;

use std::sync::Arc;
use tracing::{error, instrument, trace, trace_span};
use tracing_futures::Instrument;
use tun_nat::{SessionManager, run_nat_with_icmp};

pub(crate) type UdpManager = Arc<RwLock<HashMap<u16, (CandidateUdpSocket, SocketAddr, Address)>>>;

struct BackgroundTasks {
    nat: Option<JoinHandle<()>>,
    dns: JoinHandle<()>,
    chooser: JoinHandle<()>,
    network_change_rx: mpsc::UnboundedReceiver<()>,
}

pub struct ProxyClient {
    config: Config,
    uid: Option<u32>,
    connectivity: ProbeConnectivity,
    session_manager: Option<SessionManager>,
    udp_manager: UdpManager,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsClient,
    server_chooser: ServerChooser,
    background_tasks: Option<BackgroundTasks>,
    #[allow(dead_code)]
    icmp_relay: Option<IcmpRelay>,
}

impl ProxyClient {
    pub async fn new(config: Config, uid: Option<u32>, show_stats: bool) -> Self {
        let dns_client = DnsClient::new(&config.dns_servers, config.dns_timeout).await;
        let (session_manager, nat_handle, icmp_relay) = setup_nat(&config, &dns_client);
        let (resolver, dns_handle) = setup_dns_server(&config, dns_client.resolver()).await;
        let (server_chooser, chooser_handle) =
            setup_server_chooser(config.clone(), dns_client.clone(), show_stats).await;

        let (network_change_tx, network_change_rx) = mpsc::unbounded_channel();
        spawn_network_monitor(network_change_tx);

        Self {
            connectivity: ProbeConnectivity::new(server_chooser.clone(), config.probe_timeout),
            udp_manager: Arc::new(RwLock::new(HashMap::new())),
            resolver,
            dns_client,
            config,
            uid,
            session_manager,
            server_chooser,
            background_tasks: Some(BackgroundTasks {
                nat: nat_handle,
                dns: dns_handle,
                chooser: chooser_handle,
                network_change_rx,
            }),
            icmp_relay,
        }
    }

    async fn run_tcp_relay_server(&self) -> Result<()> {
        let listener = TcpListener::bind(("0.0.0.0", REDIR_LISTEN_PORT))
            .await
            .inspect_err(|_e| {
                eprintln!("error: bind to {REDIR_LISTEN_PORT}");
            })?;
        loop {
            let (conn, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
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

            let session_manager_clone = session_manager.clone();
            tokio::task::spawn(async move {
                let _ = relay_tcp_stream(
                    conn,
                    real_src,
                    real_dest,
                    host,
                    config,
                    server_chooser,
                    connectivity,
                    uid,
                    move || {
                        if let Some(session_manager) = &session_manager_clone {
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
    }

    pub async fn run(mut self) {
        let Some(tasks) = self.background_tasks.take() else {
            panic!("run() called without background tasks");
        };

        let network_change_task = run_network_change_handler(
            tasks.network_change_rx,
            self.server_chooser.clone(),
            self.udp_manager.clone(),
        );

        let ret = tokio::select! {
            r = self.run_tcp_relay_server().instrument(trace_span!("run_tcp_relay_server")) => r,
            r = self.run_udp_relay_server_if_enabled() => r,
            r = wait_for_handle(Some(tasks.chooser)) => r,
            r = wait_for_handle(Some(tasks.dns)) => r,
            r = wait_for_handle(tasks.nat) => r,
            _ = network_change_task => {
                tracing::info!("Network change handler exited");
                Ok(())
            }
        };
        ret.expect("run proxy client");
    }

    async fn run_udp_relay_server_if_enabled(&self) -> Result<()> {
        if self.config.redir_mode {
            return pending::<Result<()>>().await;
        }
        self.run_udp_relay_server()
            .instrument(trace_span!("run_udp_relay_server"))
            .await
            .inspect_err(|e| tracing::error!(?e, "run udp relay server error"))
    }

    async fn get_proxy_udp_socket(
        &self,
        tun_socket: Arc<UdpSocket>,
        tun_addr: SocketAddr,
    ) -> Result<(CandidateUdpSocket, SocketAddr, Address)> {
        let port = tun_addr.port();
        if let Some(r) = self.udp_manager.read().get(&port) {
            return Ok(r.clone());
        }

        let Some(session_manager) = self.session_manager.clone() else {
            return Err(Error::other("session manager not initialized"));
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
            let (candidate_udp_socket, real_dest, host) =
                match self.get_proxy_udp_socket(tun_socket, peer_addr).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!(?e, "get proxy udp socket error: {:?}", e);
                        continue;
                    }
                };
            let proxy_udp_socket = candidate_udp_socket.socket;
            let ret = timeout(
                self.config.write_timeout,
                proxy_udp_socket.send_to(&buf[..size], real_dest),
            )
            .await;
            if let Err(e) = ret {
                error!("send udp packet error {}: {:?}", host, e);
                if let Some(performance_tracker) = self
                    .server_chooser
                    .get_performance_tracker(&candidate_udp_socket.proxy_group_name)
                    && let Some(server_config) = candidate_udp_socket.server_config
                {
                    performance_tracker.add_result(&server_config, None, false);
                }
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
    if let Some(uid) = user_id
        && !socket_addr_belong_to_user(real_src, uid)?
    {
        pass_proxy = true;
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

fn setup_nat(
    config: &Config,
    dns_client: &DnsClient,
) -> (
    Option<SessionManager>,
    Option<JoinHandle<()>>,
    Option<IcmpRelay>,
) {
    if config.redir_mode {
        return (None, None, None);
    }

    let additional_cidrs = config.rules.additional_cidrs();

    // Create ICMP channel for ping support (only request, reply goes directly)
    let (icmp_request_tx, icmp_request_rx) = crossbeam_channel::unbounded();

    let (session_manager, nat_join_handle) = run_nat_with_icmp(
        &config.tun_name,
        config.tun_ip,
        config.tun_cidr,
        REDIR_LISTEN_PORT,
        &additional_cidrs,
        config.queue_number,
        config.threads_per_queue,
        Some(icmp_request_tx),
    )
    .expect("run nat");

    // Start ICMP relay (replies go directly to client, not through TUN)
    let icmp_relay = match IcmpRelay::start(icmp_request_rx, dns_client.clone()) {
        Ok(relay) => {
            tracing::info!("ICMP relay started for ping support");
            Some(relay)
        }
        Err(e) => {
            tracing::warn!("Failed to start ICMP relay: {}. Ping will not work.", e);
            None
        }
    };

    let handle = tokio::task::spawn(async move {
        while !nat_join_handle.is_finished() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });

    (Some(session_manager), Some(handle), icmp_relay)
}

async fn setup_dns_server(
    config: &Config,
    resolver: TokioResolver,
) -> (RuleBasedDnsResolver, JoinHandle<()>) {
    let (dns_server, resolver) = create_dns_server(
        config.dns_listens.clone(),
        config.tun_bypass_direct,
        config.rules.clone(),
        resolver,
    )
    .await;
    let handle = tokio::task::spawn(async {
        dns_server
            .run_server()
            .instrument(trace_span!("Dns_server.run_server"))
            .await
    });
    (resolver, handle)
}

async fn setup_server_chooser(
    config: Config,
    dns_client: DnsClient,
    show_stats: bool,
) -> (ServerChooser, JoinHandle<()>) {
    let chooser = ServerChooser::new(config, dns_client, show_stats).await;
    let chooser_clone = chooser.clone();
    let handle = tokio::task::spawn(async move {
        chooser_clone
            .run_background_tasks()
            .instrument(trace_span!("ServerChooser.run_background_tasks"))
            .await
            .unwrap()
    });
    (chooser, handle)
}

async fn run_network_change_handler(
    mut rx: mpsc::UnboundedReceiver<()>,
    server_chooser: ServerChooser,
    udp_manager: UdpManager,
) {
    const DEBOUNCE_DURATION: std::time::Duration = std::time::Duration::from_secs(1);

    while let Some(()) = rx.recv().await {
        // Debounce: wait and drain any additional events
        loop {
            tokio::select! {
                _ = tokio::time::sleep(DEBOUNCE_DURATION) => break,
                result = rx.recv() => {
                    if result.is_none() {
                        return;
                    }
                }
            }
        }

        println!("Network change detected, resetting all connections");
        server_chooser.reset_all();
        udp_manager.write().clear();
        tracing::info!("Connection reset completed");
    }
}

async fn wait_for_handle(handle: Option<JoinHandle<()>>) -> Result<()> {
    match handle {
        Some(h) => h.await.unwrap(),
        None => pending::<()>().await,
    }
    Ok(())
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
            return Err(Error::other("session manager not found port"));
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
            return Err(Error::other(format!("resolve dns error: {host}")));
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
