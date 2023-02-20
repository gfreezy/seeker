use anyhow::Result;
use async_std::io::{timeout, Read, Write};
use async_std::net::TcpStream;
use async_std::prelude::*;
use config::{Address, Config};

use std::net::SocketAddr;

use std::sync::Arc;
use std::time::Duration;
use tracing::{error, instrument, trace};



use crate::probe_connectivity::ProbeConnectivity;
use crate::proxy_client::{get_action_for_addr};
use crate::proxy_connection::ProxyConnection;
use crate::proxy_tcp_stream::ProxyTcpStream;
use crate::server_chooser::ServerChooser;

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub(crate) async fn relay_tcp_stream(
    conn: TcpStream,
    real_src: SocketAddr,
    real_dest: SocketAddr,
    host: Address,
    config: Config,
    server_chooser: Arc<ServerChooser>,
    connectivity: ProbeConnectivity,
    user_id: Option<u32>,
    on_update_activity: impl Fn() -> bool,
) -> Result<()> {
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
        &host,
        conn,
        remote_conn.clone(),
        config.read_timeout,
        config.write_timeout,
        on_update_activity,
    )
    .await;
    if let Err(e) = &ret {
        tracing::error!(?e, ?host, "tunnel tcp stream");
    } else {
        tracing::info!("tunnel tcp stream: recycle port, host: {host}, error: {ret:?}");
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
    _host: &Address,
    mut conn1: T1,
    mut conn2: T2,
    read_timeout: Duration,
    write_timeout: Duration,
    on_update_activity: impl Fn() -> bool,
) -> std::io::Result<()> {
    let mut conn1_clone = conn1.clone();
    let mut conn2_clone = conn2.clone();
    let f1 = async {
        let mut buf = vec![0; 1500];
        loop {
            if !on_update_activity() {
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
            if !on_update_activity() {
                break Err(std::io::ErrorKind::ConnectionAborted.into());
            }
            let size = timeout(read_timeout, conn2_clone.read(&mut buf)).await?;
            if size == 0 {
                break Ok(());
            }
            timeout(write_timeout, conn1_clone.write_all(&buf[..size])).await?;
        }
    };
    f1.race(f2).await
}
