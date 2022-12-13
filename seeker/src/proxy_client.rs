use crate::dns_client::DnsClient;
use crate::probe_connectivity::ProbeConnectivity;
use crate::proxy_udp_socket::ProxyUdpSocket;
use crate::relay_tcp_stream::relay_tcp_stream;
use crate::server_chooser::ServerChooser;
use async_std::io::timeout;
use async_std::net::{SocketAddr, TcpListener, UdpSocket};
use async_std::task::{spawn, JoinHandle};
use async_std::{prelude::*, task};
use async_std_resolver::AsyncStdResolver;
use config::rule::Action;
use config::{Address, Config};
use dnsserver::create_dns_server;
use dnsserver::resolver::RuleBasedDnsResolver;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::{Error, Result};

use std::sync::Arc;
use tracing::{error, instrument, trace, trace_span};
use tracing_futures::Instrument;
use tun_nat::{run_nat, SessionManager};

pub struct ProxyClient {
    config: Config,
    uid: Option<u32>,
    connectivity: ProbeConnectivity,
    session_manager: SessionManager,
    udp_manager: Arc<RwLock<HashMap<u16, (ProxyUdpSocket, SocketAddr)>>>,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsClient,
    server_chooser: Arc<ServerChooser>,
    nat_join_handle: Option<JoinHandle<()>>,
    dns_server_join_handle: Option<JoinHandle<()>>,
    chooser_join_handle: Option<JoinHandle<()>>,
}

impl ProxyClient {
    pub async fn new(config: Config, uid: Option<u32>) -> Self {
        let additional_cidrs = config.rules.additional_cidrs();
        let (session_manager, blocking_join_handle) = run_nat(
            &config.tun_name,
            config.tun_ip,
            config.tun_cidr,
            1300,
            &additional_cidrs,
        )
        .expect("run nat");
        let nat_join_handle = task::spawn_blocking(move || match blocking_join_handle.join() {
            Ok(()) => tracing::info!("nat stopped"),
            Err(e) => tracing::error!("nat stopped with error: {:?}", e),
        });

        let dns_client = DnsClient::new(&config.dns_servers, config.dns_timeout).await;

        let (resolver, dns_server_join_handle) =
            run_dns_resolver(&config, dns_client.resolver()).await;

        let ping_urls = config.ping_urls.clone();
        let chooser = Arc::new(
            ServerChooser::new(
                config.servers.clone(),
                dns_client.clone(),
                ping_urls,
                config.ping_timeout,
            )
            .await,
        );
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
            connectivity: ProbeConnectivity::new(config.probe_timeout),
            udp_manager: Arc::new(RwLock::new(HashMap::new())),
            dns_client,
            config,
            uid,
            session_manager,
            server_chooser: chooser,
            nat_join_handle: Some(nat_join_handle),
            dns_server_join_handle: Some(dns_server_join_handle),
            chooser_join_handle: Some(chooser_join_handle),
        }
    }

    async fn choose_proxy_udp_socket(
        &self,
        original_addr: SocketAddr,
        sock_addr: SocketAddr,
        remote_addr: &Address,
    ) -> Result<ProxyUdpSocket> {
        let action = get_action_for_addr(
            original_addr,
            sock_addr,
            remote_addr,
            &self.config,
            &self.connectivity,
            self.uid,
        )
        .await?;

        retry_timeout!(
            self.config.connect_timeout,
            self.config.max_connect_errors,
            self.server_chooser.candidate_udp_socket(action)
        )
        .await
    }

    async fn run_tcp_relay_server(&self) -> Result<()> {
        let listener = TcpListener::bind((self.config.tun_ip, 1300)).await?;
        let mut incoming = listener.incoming();
        while let Some(Ok(conn)) = incoming.next().await {
            let session_manager = self.session_manager.clone();
            let resolver = self.resolver.clone();
            let dns_client = self.dns_client.clone();
            let config = self.config.clone();
            let server_chooser = self.server_chooser.clone();
            let connectivity = self.connectivity.clone();
            let uid = self.uid;

            spawn(async move {
                let _ = relay_tcp_stream(
                    conn,
                    session_manager,
                    resolver,
                    dns_client,
                    config,
                    server_chooser,
                    connectivity,
                    uid,
                )
                .await;
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
                let ret = self
                    .run_udp_relay_server()
                    .instrument(tracing::trace_span!("ProxyClient.run_udp_relay_server"))
                    .await;
                if let Err(e) = &ret {
                    tracing::error!(?e, "run udp relay server error");
                }
                ret
            })
            .race(async move {
                if let Some(chooser_join_handle) = chooser_join_handle {
                    chooser_join_handle.await
                };
                Ok(())
            })
            .race(async move {
                if let Some(dns_server_join_handle) = dns_server_join_handle {
                    dns_server_join_handle.await;
                };
                Ok(())
            })
            .race(async move {
                if let Some(nat_join_handle) = nat_join_handle {
                    nat_join_handle.await;
                };
                Ok(())
            })
            .await;
        tracing::error!(?ret, "run error");
        ret.expect("run");
    }

    fn get_udp_socket_and_dest_addr(&self, port: u16) -> Option<(ProxyUdpSocket, SocketAddr)> {
        let (real_src, real_dest) = self.session_manager.get_by_port(port)?;
        trace!(?real_src, ?real_dest, "new udp relay packet");

        self.udp_manager.read().get(&port).cloned()
    }

    async fn new_udp_socket(&self, port: u16) -> Result<(ProxyUdpSocket, SocketAddr)> {
        let (real_src, real_dest) = match self.session_manager.get_by_port(port) {
            Some(s) => s,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "session manager not found port",
                ))
            }
        };

        trace!(?real_src, ?real_dest, "new udp relay packet");

        if let Some(r) = self.udp_manager.read().get(&port) {
            return Ok(r.clone());
        }

        let ip = real_dest.ip().to_string();
        let host = self
            .resolver
            .lookup_host(&ip)
            .map(|s| Address::DomainNameAddress(s, real_dest.port()))
            .unwrap_or_else(|| Address::SocketAddress(real_dest));
        let sock_addr = self.dns_client.lookup_address(&host).await?;
        let socket = self
            .choose_proxy_udp_socket(real_src, sock_addr, &host)
            .await?;
        self.udp_manager
            .write()
            .insert(port, (socket.clone(), sock_addr));
        Ok((socket, sock_addr))
    }

    async fn run_udp_relay_server(&self) -> Result<()> {
        let udp_listener = Arc::new(UdpSocket::bind("0.0.0.0:1300").await?);
        let recv_timeout = self.config.read_timeout;
        let write_timeout = self.config.write_timeout;
        let mut buf = vec![0; 2000];
        loop {
            let (size, peer_addr) = udp_listener.recv_from(&mut buf).await.map_err(|e| {
                error!(?e, "udp recv error");
                e
            })?;
            assert!(size < 2000);
            let session_port = peer_addr.port();
            let (socket, dest_addr) = match self.get_udp_socket_and_dest_addr(session_port) {
                None => {
                    let (socket, dest_addr) = match self.new_udp_socket(session_port).await {
                        Ok(r) => r,
                        Err(e) => {
                            error!(?e, "new udp socket");
                            continue;
                        }
                    };
                    let socket_clone = socket.clone();
                    let udp_listener_clone = udp_listener.clone();

                    let udp_manager = self.udp_manager.clone();
                    let session_manager = self.session_manager.clone();
                    spawn(async move {
                        let _: Result<()> = async {
                            let mut buf = vec![0; 2000];
                            loop {
                                session_manager.update_activity_for_port(session_port);
                                let (recv_size, _peer) =
                                    timeout(recv_timeout, socket_clone.recv_from(&mut buf)).await?;
                                assert!(recv_size < 2000);
                                let send_size = timeout(
                                    write_timeout,
                                    udp_listener_clone.send_to(&buf[..size], peer_addr),
                                )
                                .await?;
                                assert_eq!(send_size, size);
                            }
                        }
                        .await;
                        let _ = udp_manager.write().remove(&peer_addr.port());
                        session_manager.recycle_port(session_port);
                    });
                    (socket, dest_addr)
                }
                Some(r) => r,
            };
            match timeout(write_timeout, socket.send_to(&buf[..size], dest_addr)).await {
                Ok(send_size) => {
                    assert_eq!(size, send_size);
                }
                Err(e) => error!(?e, "send to {}", dest_addr),
            };
            self.session_manager.update_activity_for_port(session_port);
        }
    }
}

#[instrument(skip(real_src, real_dest, config, connectivity), ret)]
pub(crate) async fn get_action_for_addr(
    real_src: SocketAddr,
    real_dest: SocketAddr,
    addr: &Address,
    config: &Config,
    connectivity: &ProbeConnectivity,
    user_id: Option<u32>,
) -> Result<Action> {
    let mut pass_proxy = false;
    let domain_or_ip = match &addr {
        // 如果是 IP 说明是用户手动改了路由表，必须要走代理。
        Address::SocketAddress(sock_addr) => sock_addr.ip().to_string(),
        Address::DomainNameAddress(domain, _port) => domain.to_string(),
    };
    if let Some(uid) = user_id {
        if !socket_addr_belong_to_user(real_src, uid)? {
            pass_proxy = true;
        }
    }
    let mut action = if pass_proxy {
        Action::Direct
    } else {
        config
            .rules
            .action_for_domain(&domain_or_ip)
            .unwrap_or_else(|| config.rules.default_action())
    };

    if action == Action::Probe {
        if connectivity.probe_connectivity(real_dest, addr).await {
            action = Action::Direct;
        } else {
            action = Action::Proxy;
        }
    }

    Ok(action)
}

async fn run_dns_resolver(
    config: &Config,
    resolver: AsyncStdResolver,
) -> (RuleBasedDnsResolver, JoinHandle<()>) {
    let (dns_server, resolver) = create_dns_server(
        "dns.db",
        config.dns_listen.clone(),
        config.dns_start_ip,
        config.tun_bypass_direct,
        config.rules.clone(),
        resolver,
    )
    .await;
    println!("Spawn DNS server");
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

    let ip = real_dest.ip().to_string();
    let host = resolver
        .lookup_host(&ip)
        .map(|s| Address::DomainNameAddress(s, real_dest.port()))
        .unwrap_or_else(|| Address::SocketAddress(real_dest));

    trace!(dest_host = ?host, "new relay connection");

    let sock_addr = match dns_client
        .lookup_address(&host)
        .instrument(tracing::trace_span!("lookup_address", ?host))
        .await
    {
        Ok(a) => a,
        Err(e) => {
            error!(?e, ?host, "error resolve dns");
            return Err(Error::new(std::io::ErrorKind::Other, "resolve dns error"));
        }
    };

    trace!(ip = ?ip, host = ?host, "lookup host");
    Ok((real_src, sock_addr, host))
}
