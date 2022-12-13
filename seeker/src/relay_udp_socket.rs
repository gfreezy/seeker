use std::net::SocketAddr;
use std::sync::Arc;

use async_std::io::timeout;
use async_std::net::UdpSocket;
use async_std::prelude::*;
use config::{Address, Config};
use dnsserver::resolver::RuleBasedDnsResolver;
use tun_nat::SessionManager;

use crate::dns_client::DnsClient;
use crate::probe_connectivity::ProbeConnectivity;
use crate::proxy_client::{get_action_for_addr, get_real_src_real_dest_and_host};
use crate::proxy_udp_socket::ProxyUdpSocket;
use crate::server_chooser::ServerChooser;

pub(crate) async fn relay_udp_socket(
    tun_socket: UdpSocket,
    tun_addr: SocketAddr,
    mut recv_buf: Vec<u8>,
    mut recv_size: usize,
    session_manager: SessionManager,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsClient,
    config: Config,
    server_chooser: Arc<ServerChooser>,
    connectivity: ProbeConnectivity,
    user_id: Option<u32>,
) -> std::io::Result<()> {
    tun_socket.connect(tun_addr).await?;
    assert!(recv_size < 2000);
    let session_port = tun_addr.port();
    let (real_src, real_dest, host) =
        get_real_src_real_dest_and_host(session_port, &session_manager, &resolver, &dns_client)
            .await?;
    let proxy_socket = choose_proxy_udp_socket(
        real_src,
        real_dest,
        &host,
        &config,
        &server_chooser,
        &connectivity,
        user_id,
    )
    .await?;

    let f1 = async {
        loop {
            let send_size = timeout(
                config.write_timeout,
                proxy_socket.send_to(&recv_buf[..recv_size], real_dest),
            )
            .await?;
            assert_eq!(send_size, recv_size);
            recv_size = timeout(config.read_timeout, tun_socket.recv(&mut recv_buf)).await?;
            assert!(recv_size < 2000);
            session_manager.update_activity_for_port(session_port);
        }
    };

    let f2 = async {
        let mut buf = vec![0; 2000];
        loop {
            session_manager.update_activity_for_port(session_port);
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
    };

    let _: std::io::Result<()> = f1.race(f2).await;

    session_manager.recycle_port(session_port);
    Ok(())
}

async fn choose_proxy_udp_socket(
    real_src: SocketAddr,
    real_dest: SocketAddr,
    remote_addr: &Address,
    config: &Config,
    server_chooser: &ServerChooser,
    connectivity: &ProbeConnectivity,
    user_id: Option<u32>,
) -> std::io::Result<ProxyUdpSocket> {
    let action = get_action_for_addr(
        real_src,
        real_dest,
        remote_addr,
        config,
        connectivity,
        user_id,
    )
    .await?;

    retry_timeout!(
        config.connect_timeout,
        config.max_connect_errors,
        server_chooser.candidate_udp_socket(action)
    )
    .await
}
