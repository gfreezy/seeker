mod ssclient;
mod tun;

use crate::ssclient::SSClient;
use crate::tun::socket::TunSocket;
use crate::tun::{bg_send, listen};
use shadowsocks::crypto::CipherType;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite};
use shadowsocks::{ServerAddr, ServerConfig};
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpEndpoint;
use std::env;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::future::lazy;
use tokio::prelude::{AsyncRead, Future, Stream};
use tokio::runtime::current_thread::{run, spawn};

fn main() -> io::Result<()> {
    env_logger::init();
    better_panic::install();

    let args = env::args().collect::<Vec<String>>();
    let _name = &args[1];

    let srv_cfg = ServerConfig::new(
        ServerAddr::DomainName("sg2.edge.bgp.app".to_string(), 14187),
        "rixCloud".to_string(),
        CipherType::ChaCha20Ietf,
        Some(Duration::from_secs(30)),
        None,
    );

    run(lazy(|| {
        let client = Arc::new(SSClient::new(srv_cfg));

        spawn(bg_send().map_err(|_| ()));

        listen()
            .for_each(move |socket| {
                let client = client.clone();
                spawn(lazy(move || -> Box<dyn Future<Item = (), Error = ()>> {
                    match socket {
                        TunSocket::Tcp(socket) => {
                            let remote_addr = dbg!(socket.local_addr());
                            let (reader, writer) = socket.split();
                            Box::new(
                                client
                                    .handle_connect(
                                        (reader, writer),
                                        Address::SocketAddress(remote_addr),
                                    )
                                    .map_err(|_| ()),
                            )
                        }
                        TunSocket::Udp(socket) => {
                            let buf = vec![0; 1000];
                            Box::new(
                                socket
                                    .recv_dgram(buf)
                                    .and_then(|(socket, mut buf, size, addr)| {
                                        buf.truncate(size);
                                        socket.send_dgram(buf, addr)
                                    })
                                    .map(|_| ())
                                    .map_err(|_| ()),
                            )
                        }
                    }
                }));
                Ok(())
            })
            .map_err(|_| ())
    }));

    Ok(())
}
