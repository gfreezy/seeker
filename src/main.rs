#![feature(async_await)]

mod tun;
mod ssclient;

use tun::{Addr, Tun, SocketBuf};
use futures::{executor, TryFutureExt, AsyncWriteExt, AsyncReadExt, AsyncRead, AsyncWrite};
use futures::future::FutureExt;
use log::debug;
use std::env;
use std::io;
use shadowsocks::{ServerConfig, ServerAddr};
use shadowsocks::crypto::CipherType;
use std::time::Duration;
use futures::executor::LocalPool;
use std::collections::HashMap;
use smoltcp::wire::{IpAddress, Ipv4Address};
use std::net::{SocketAddr, SocketAddrV4, IpAddr, Ipv4Addr};
use smoltcp::wire::IpEndpoint;
use futures::compat::{AsyncRead01CompatExt, AsyncWrite01CompatExt, Future01CompatExt};
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite};
use std::io::Read;
use futures::task::{SpawnExt, Spawn, LocalSpawnExt};
use tokio::prelude::Future;


fn main() -> io::Result<()> {
    env_logger::init();
    better_panic::install();

    let args = env::args().collect::<Vec<String>>();
    let name = &args[1];
    let mut tun = Tun::new(dbg!(&args[1]));

    let mut local_pool = LocalPool::new();
    let mut local_spawner = local_pool.spawner();
    let srv_cfg = ServerConfig::new(
        ServerAddr::DomainName("jp1.edge.mithril.to".to_string(), 14187),
        "rixCloud".to_string(),
        CipherType::ChaCha20Ietf,
        Some(Duration::from_secs(30)),
        None);
    let mut client = ssclient::SSClient::new(srv_cfg, &mut local_spawner);

    let fut = async move {
        debug!("begin start");
        loop {
            debug!("loop start");
            let mut tx_data = Vec::new();
            let rx_data: Vec<SocketBuf> = tun.recv().await?;
            for socket_buf in rx_data {
                match socket_buf {
                    SocketBuf::Tcp(Addr { src, dst }, mut buf) => {
                        debug!(
                            "src: {}, dst: {}, buf: {}",
                            src,
                            dst,
                            String::from_utf8_lossy(&buf)
                        );
                        if buf.is_empty() {
                            continue;
                        }
                        let (mut r, mut w) = client.connect_to_remote(to_socket_addr(dst)).await.unwrap();
                        w.await?.write_all(&buf).compat().await.unwrap();
                        let size = r.await?.read(&mut buf).unwrap();
                        buf.truncate(size);
                        tx_data.push(SocketBuf::Tcp(Addr { src: dst, dst: src }, buf))
                    }
                    SocketBuf::Udp(Addr { src, dst }, buf) => {
                        debug!(
                            "src: {}, dst: {}, buf: {}",
                            src,
                            dst,
                            String::from_utf8_lossy(&buf)
                        );
                        tx_data.push(SocketBuf::Udp(Addr { src: dst, dst: src }, buf))
                    }
                }
            }
            debug!("tun.send");
            tun.send(tx_data).await?;
        }
        Ok(())
    };
    local_spawner.spawn_local(fut.map(|_: io::Result<()>| ()));
    local_pool.run();
    Ok(())
}

fn to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    match endpoint.addr {
        IpAddress::Ipv4(addr) => {
            let a: Ipv4Addr = addr.into();
            (a, endpoint.port).into()
        },
        _ => {unreachable!()},
    }
}
