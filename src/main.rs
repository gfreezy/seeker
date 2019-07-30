#![feature(async_await)]
#![feature(impl_trait_in_bindings)]

mod tun;
mod ssclient;

use tun::{Addr, Tun, SocketBuf};
use futures::{FutureExt, TryFutureExt, Future};
use log::debug;
use std::env;
use std::io;
use shadowsocks::{ServerConfig, ServerAddr};
use shadowsocks::crypto::CipherType;
use std::time::Duration;
use smoltcp::wire::{IpAddress};
use std::net::{SocketAddr, Ipv4Addr};
use smoltcp::wire::IpEndpoint;
use futures::compat::{Future01CompatExt};
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite};
use std::io::Read;
use tokio::runtime::current_thread::block_on_all;


fn main() -> io::Result<()> {
    env_logger::init();
    better_panic::install();

    let args = env::args().collect::<Vec<String>>();
    let _name = &args[1];
    let mut tun = Tun::new(dbg!(&args[1]));

    let srv_cfg = ServerConfig::new(
        ServerAddr::DomainName("jp1.edge.mithril.to".to_string(), 14187),
        "rixCloud".to_string(),
        CipherType::ChaCha20Ietf,
        Some(Duration::from_secs(30)),
        None);


    let fut: impl Future<Output = io::Result<()>> = async move {
        let mut client = ssclient::SSClient::new(srv_cfg);
        let exit = false;
        debug!("begin start");
        while !exit {
            debug!("loop start");
            let mut tx_data = Vec::new();
            let rx_data: Vec<SocketBuf> = tun.recv().compat().await?;
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
                        let (r, w) = client.connect_to_remote(to_socket_addr(dst)).compat().await?;
                        w.compat().await?.write_all(&buf).compat().await.unwrap();
                        let size = r.compat().await?.read(&mut buf).unwrap();
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
            tun.send(tx_data).compat().await?;
        }

        Ok(())
    };
    block_on_all(fut.unit_error()
        .boxed_local()
        .compat()).unwrap();
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
