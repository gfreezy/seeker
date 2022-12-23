use anyhow::Result;
use async_std::io::{timeout, Read, Write};
use async_std::net::TcpStream;
use async_std::prelude::*;
use config::{Address, Config};
use dnsserver::resolver::RuleBasedDnsResolver;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, instrument, trace};
use tun_nat::SessionManager;

use crate::dns_client::DnsClient;
use crate::probe_connectivity::ProbeConnectivity;
use crate::proxy_client::{get_action_for_addr, get_real_src_real_dest_and_host};
use crate::proxy_connection::ProxyConnection;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::server_chooser::ServerChooser;

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub(crate) async fn relay_tcp_stream(
    conn: TcpStream,
    session_manager: SessionManager,
    resolver: RuleBasedDnsResolver,
    dns_client: DnsClient,
    config: Config,
    server_chooser: Arc<ServerChooser>,
    connectivity: ProbeConnectivity,
    user_id: Option<u32>,
) -> Result<()> {
    let peer_addr = conn.peer_addr().map_err(|e| {
        tracing::error!(?e, "tunnel tcp stream");
        e
    })?;
    trace!(peer_addr = ?peer_addr, "new connection");
    let session_port = peer_addr.port();
    let (real_src, real_dest, host) = get_real_src_real_dest_and_host(
        session_port,
        &session_manager,
        &resolver,
        &dns_client,
        &config,
    )
    .await?;

    let remote_conn = match choose_proxy_tcp_stream(
        real_src,
        real_dest,
        &host,
        &config,
        &server_chooser,
        &connectivity,
        user_id,
    )
    .await
    {
        Ok(remote_conn) => remote_conn,
        Err(e) => {
            error!(?host, ?e, "connect remote error");
            return Err(e);
        }
    };

    let ret = tunnel_tcp_stream(
        conn,
        remote_conn.clone(),
        session_manager,
        session_port,
        config.read_timeout,
        config.write_timeout,
    )
    .await;
    if let Err(e) = ret {
        info!(?e, "tunnel tcp stream");
    }
    remote_conn.shutdown();
    Ok(())
}

#[instrument(skip(
    original_addr,
    sock_addr,
    config,
    server_chooser,
    connectivity,
    user_id
))]
async fn choose_proxy_tcp_stream(
    original_addr: SocketAddr,
    sock_addr: SocketAddr,
    remote_addr: &Address,
    config: &Config,
    server_chooser: &ServerChooser,
    connectivity: &ProbeConnectivity,
    user_id: Option<u32>,
) -> Result<ProxyTcpStream> {
    let action = get_action_for_addr(
        original_addr,
        sock_addr,
        remote_addr,
        config,
        connectivity,
        user_id,
    )
    .await?;
    trace!(?action, "selected action");
    Ok(retry_timeout!(
        config.connect_timeout,
        config.max_connect_errors,
        server_chooser.candidate_tcp_stream(remote_addr.clone(), action)
    )
    .await?)
}

async fn tunnel_tcp_stream<T1: Read + Write + Unpin + Clone, T2: Read + Write + Unpin + Clone>(
    mut conn1: T1,
    mut conn2: T2,
    session_manager: SessionManager,
    session_port: u16,
    read_timeout: Duration,
    write_timeout: Duration,
) -> std::io::Result<()> {
    let mut conn1_clone = conn1.clone();
    let mut conn2_clone = conn2.clone();
    let f1 = async {
        let mut buf = vec![0; 1500];
        loop {
            if !session_manager.update_activity_for_port(session_port) {
                break Err(std::io::ErrorKind::ConnectionAborted.into());
            }
            let size = timeout(read_timeout, conn1.read(&mut buf)).await?;
            if size == 0 {
                break Ok(());
            }
            timeout(write_timeout, conn2.write_all(&buf[..size])).await?;
        }
    };
    let f2 = async {
        let mut buf = vec![0; 1500];
        loop {
            if !session_manager.update_activity_for_port(session_port) {
                break Err(std::io::ErrorKind::ConnectionAborted.into());
            }
            let size = timeout(read_timeout, conn2_clone.read(&mut buf)).await?;
            if size == 0 {
                break Ok(());
            }
            timeout(write_timeout, conn1_clone.write_all(&buf[..size])).await?;
        }
    };
    let ret = f1.race(f2).await;
    if let Err(e) = &ret {
        tracing::error!(?e, "tunnel tcp stream");
    }
    session_manager.recycle_port(session_port);
    ret
}
