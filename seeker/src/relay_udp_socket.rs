use std::net::SocketAddr;
use std::sync::Arc;

use async_std::io::timeout;
use async_std::net::UdpSocket;
use async_std::task::spawn;
use config::{Address, Config};
use dnsserver::resolver::RuleBasedDnsResolver;
use tun_nat::SessionManager;

use crate::dns_client::DnsClient;
use crate::probe_connectivity::ProbeConnectivity;
use crate::proxy_client::{UdpManager, get_action_for_addr, get_real_src_real_dest_and_host};
use crate::proxy_connection::ProxyConnection;
use crate::server_chooser::{CandidateUdpSocket, ServerChooser};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_udp_socket(
    tun_socket: Arc<UdpSocket>,
    tun_addr: SocketAddr,
    session_manager: SessionManager,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsClient,
    config: Config,
    server_chooser: ServerChooser,
    connectivity: ProbeConnectivity,
    user_id: Option<u32>,
    udp_manager: UdpManager,
) -> std::io::Result<(CandidateUdpSocket, SocketAddr, Address)> {
    let session_port = tun_addr.port();
    let (real_src, real_dest, host) = get_real_src_real_dest_and_host(
        session_port,
        &session_manager,
        &resolver,
        &dns_client,
        &config,
    )
    .await?;
    tracing::debug!(?real_src, ?real_dest, ?host, "new udp connection");
    let candidate_udp_socket = choose_proxy_udp_socket(
        real_src,
        real_dest,
        &host,
        &config,
        &server_chooser,
        &connectivity,
        user_id,
    )
    .await?;

    tracing::debug!("new udp connection successfully, {}", host);
    let proxy_socket = candidate_udp_socket.socket.clone();
    let candidate_udp_socket_clone = candidate_udp_socket.clone();
    let host_clone = host.clone();
    let udp_manager_clone = udp_manager.clone();
    spawn(async move {
        let ret: std::io::Result<()> = async {
            let mut buf = vec![0; 2000];
            loop {
                if !session_manager.update_activity_for_port(session_port) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("port recycled, {host_clone}"),
                    ));
                }
                let (recv_size, _peer) =
                    timeout(config.read_timeout, proxy_socket.recv_from(&mut buf)).await?;
                assert!(recv_size < 2000);
                let send_size = timeout(
                    config.write_timeout,
                    tun_socket.send_to(&buf[..recv_size], tun_addr),
                )
                .await?;
                assert_eq!(send_size, recv_size);
            }
        }
        .await;
        if ret.is_err()
            && let Some(performance_tracker) =
                server_chooser.get_performance_tracker(&candidate_udp_socket_clone.proxy_group_name)
            && let Some(server_config) = &candidate_udp_socket_clone.server_config
        {
            performance_tracker.add_result(server_config, None, false);
        }
        session_manager.recycle_port(session_port);
        udp_manager_clone.write().remove(&session_port);
        candidate_udp_socket_clone.socket.shutdown();
    });

    udp_manager.write().insert(
        session_port,
        (candidate_udp_socket.clone(), real_dest, host.clone()),
    );

    Ok((candidate_udp_socket, real_dest, host))
}

async fn choose_proxy_udp_socket(
    real_src: SocketAddr,
    real_dest: SocketAddr,
    remote_addr: &Address,
    config: &Config,
    server_chooser: &ServerChooser,
    connectivity: &ProbeConnectivity,
    user_id: Option<u32>,
) -> std::io::Result<CandidateUdpSocket> {
    let action = get_action_for_addr(
        real_src,
        real_dest,
        remote_addr,
        config,
        connectivity,
        user_id,
    )
    .await?;
    tracing::debug!(?action, ?remote_addr, "udp action");

    retry_timeout!(
        config.connect_timeout,
        config.max_connect_errors,
        server_chooser.candidate_udp_socket(action.clone())
    )
    .await
}
