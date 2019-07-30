pub mod ahead;
pub mod stream;
pub mod tcp;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

use crate::ssclient::tcp::{
    connect_proxy_server, proxy_server_handshake, DecryptedHalf, EncryptedHalf,
};
use log::debug;
use shadowsocks::ServerConfig;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::prelude::future::lazy;
use tokio::prelude::Future;
use tokio::runtime::current_thread::spawn;
use trust_dns_resolver::AsyncResolver;

pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    async_resolver: AsyncResolver,
}

impl SSClient {
    pub fn new(server_config: ServerConfig) -> Self {
        let (resolver, background) = AsyncResolver::from_system_conf().unwrap();
        spawn(background.map(|_| ()));
        SSClient {
            srv_cfg: Arc::new(server_config),
            async_resolver: resolver,
        }
    }

    pub fn connect_to_remote(
        &mut self,
        addr: SocketAddr,
    ) -> impl Future<
        Item = (
            impl Future<Item = DecryptedHalf<TcpStream>, Error = io::Error> + Send,
            impl Future<Item = EncryptedHalf<TcpStream>, Error = io::Error> + Send,
        ),
        Error = io::Error,
    > + Send {
        let cfg = self.srv_cfg.clone();
        connect_proxy_server(self.srv_cfg.clone(), &self.async_resolver).and_then(move |stream| {
            debug!("connect remote stream");
            lazy(move || proxy_server_handshake(stream, cfg, addr.into()))
        })
    }
}
