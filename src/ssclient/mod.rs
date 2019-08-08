pub mod ahead;
pub mod stream;
pub mod tcp;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

use crate::ssclient::tcp::{connect_proxy_server, DecryptedHalf, EncryptedHalf};
use crate::tun::socket::TunTcpSocket;
use log::debug;
use log::error;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::{proxy_server_handshake, tunnel, DecryptedRead, EncryptedWrite};
use shadowsocks::ServerConfig;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::prelude::future::lazy;
use tokio::prelude::Future;
use tokio::runtime::current_thread::spawn;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::AsyncResolver;

pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    async_resolver: AsyncResolver,
}

impl SSClient {
    pub fn new(server_config: ServerConfig) -> Self {
        //        let config = ResolverConfig::new();
        //        let options = ResolverOpts::default();
        //        let (resolver, background) = AsyncResolver::new(config, options);
        let (resolver, background) = AsyncResolver::from_system_conf().unwrap();
        spawn(background.map(|_| ()));
        SSClient {
            srv_cfg: Arc::new(server_config),
            async_resolver: resolver,
        }
    }

    pub fn handle_connect(
        &self,
        (r, w): (ReadHalf<TunTcpSocket>, WriteHalf<TunTcpSocket>),
        addr: Address,
    ) -> impl Future<Item = (), Error = io::Error> + Send {
        let cfg = self.srv_cfg.clone();
        let timeout = cfg.timeout();
        connect_proxy_server(self.srv_cfg.clone(), &self.async_resolver)
            .and_then(move |stream| {
                debug!("connected remote stream");
                proxy_server_handshake(stream, cfg, addr)
            })
            .and_then(move |(srv_r, srv_w)| {
                debug!("proxy server handshake successfully");
                let rhalf = srv_r
                    .and_then(move |svr_r| svr_r.copy_timeout_opt(w, timeout))
                    .map_err(|e| {
                        error!("copy srv to local: {:#?}", e);
                        e
                    });
                let whalf = srv_w
                    .and_then(move |svr_w| svr_w.copy_timeout_opt(r, timeout))
                    .map_err(|e| {
                        error!("copy local to srv: {:#?}", e);
                        e
                    });
                tunnel(whalf, rhalf)
            })
    }
}
