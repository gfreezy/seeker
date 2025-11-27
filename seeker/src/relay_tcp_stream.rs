use anyhow::Result;
use config::{Address, Config};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use std::net::SocketAddr;

use std::time::Duration;
use tracing::{error, instrument, trace};

use crate::probe_connectivity::ProbeConnectivity;
use crate::proxy_client::get_action_for_addr;
use crate::server_chooser::{CandidateTcpStream, ServerChooser};

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub(crate) async fn relay_tcp_stream(
    conn: TcpStream,
    real_src: SocketAddr,
    real_dest: SocketAddr,
    host: Address,
    config: Config,
    server_chooser: ServerChooser,
    connectivity: ProbeConnectivity,
    user_id: Option<u32>,
    on_update_activity: impl Fn() -> bool + Send + 'static,
) -> Result<()> {
    let candidate_tcp_stream = choose_proxy_tcp_stream(
        real_src,
        real_dest,
        &host,
        &config,
        &server_chooser,
        &connectivity,
        user_id,
    )
    .await;
    let candidate_tcp_stream = match candidate_tcp_stream {
        Ok(candidate_tcp_stream) => candidate_tcp_stream,
        Err(e) => {
            error!(?host, ?e, "connect remote error");
            return Err(e);
        }
    };
    let remote_conn = candidate_tcp_stream.stream;
    let ret = tunnel_tcp_stream(
        &host,
        conn,
        remote_conn,
        config.read_timeout,
        config.idle_timeout,
        config.write_timeout,
        on_update_activity,
    )
    .await;

    let performance_tracker =
        server_chooser.get_performance_tracker(&candidate_tcp_stream.proxy_group_name);

    if let Err(e) = &ret {
        tracing::error!(?e, ?host, "tunnel tcp stream");
        if let Some(performance_tracker) = performance_tracker
            && let Some(server_config) = candidate_tcp_stream.server_config
        {
            performance_tracker.add_result(&server_config, None, false);
        }
    } else {
        tracing::info!("tunnel tcp stream: recycle port, host: {host}");
    }
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
) -> Result<CandidateTcpStream> {
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
        server_chooser.candidate_tcp_stream(remote_addr.clone(), action.clone())
    )
    .await?)
}

async fn tunnel_tcp_stream<
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
>(
    _host: &Address,
    conn1: T1,
    conn2: T2,
    read_timeout: Duration,
    idle_timeout: Duration,
    write_timeout: Duration,
    on_update_activity: impl Fn() -> bool + Send + 'static,
) -> std::io::Result<()> {
    let (mut conn1_read, mut conn1_write) = tokio::io::split(conn1);
    let (mut conn2_read, mut conn2_write) = tokio::io::split(conn2);

    let on_update_activity = std::sync::Arc::new(on_update_activity);
    let on_update_activity_clone = on_update_activity.clone();

    let f1 = async move {
        let mut buf = vec![0; 1600];
        let mut first_read = true;
        loop {
            if !on_update_activity() {
                break Err(std::io::ErrorKind::ConnectionAborted.into());
            }
            let current_timeout = if first_read {
                first_read = false;
                read_timeout
            } else {
                idle_timeout
            };
            let size = timeout(current_timeout, conn1_read.read(&mut buf)).await??;
            if size == 0 {
                break Ok(());
            }
            timeout(write_timeout, conn2_write.write_all(&buf[..size])).await??;
        }
    };
    let f2 = async move {
        let mut buf = vec![0; 1600];
        let mut first_read = true;
        loop {
            if !on_update_activity_clone() {
                break Err(std::io::ErrorKind::ConnectionAborted.into());
            }
            let current_timeout = if first_read {
                first_read = false;
                read_timeout
            } else {
                idle_timeout
            };
            let size = timeout(current_timeout, conn2_read.read(&mut buf)).await??;
            if size == 0 {
                break Ok(());
            }
            timeout(write_timeout, conn1_write.write_all(&buf[..size])).await??;
        }
    };
    tokio::select! {
        result = f1 => result,
        result = f2 => result,
    }
}
