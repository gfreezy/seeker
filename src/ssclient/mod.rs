pub mod ahead;
pub mod stream;
pub mod tcp;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

use crate::ssclient::tcp::{
    connect_proxy_server, proxy_server_handshake, DecryptedHalf, EncryptedHalf,
};
use crate::tun::Addr;
use futures::{
    compat::Future01CompatExt,
    executor::LocalSpawner,
    future::{lazy, TryFutureExt},
    task::{LocalSpawn, SpawnExt},
    FutureExt, TryStreamExt,
};
use log::trace;
use shadowsocks::relay::boxed_future;
use shadowsocks::{Config, ConfigType, ServerAddr, ServerConfig};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::prelude::Future as Future01;
use trust_dns_resolver::AsyncResolver;

pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    async_resolver: AsyncResolver,
}

impl SSClient {
    pub fn new(server_config: ServerConfig, local_spawner: &mut LocalSpawner) -> Self {
        let (resolver, background) = AsyncResolver::from_system_conf().unwrap();
        local_spawner
            .spawn(background.compat().map(|e| {
                dbg!(e);
                ()
            }))
            .unwrap();
        SSClient {
            srv_cfg: Arc::new(server_config),
            async_resolver: resolver,
        }
    }

    pub fn connect_to_remote(
        &mut self,
        addr: SocketAddr,
    ) -> impl Future<
        Output = io::Result<(
            impl Future<Output = io::Result<DecryptedHalf<TcpStream>>> + Send,
            impl Future<Output = io::Result<EncryptedHalf<TcpStream>>> + Send,
        )>,
    > + Send {
        let cfg = self.srv_cfg.clone();
        connect_proxy_server(self.srv_cfg.clone(), &self.async_resolver)
            .compat()
            .and_then(move |stream| {
                lazy(move |_| {
                    let (r, w) = proxy_server_handshake(stream, cfg, addr.into())?;
                    Ok((r.compat(), w.compat()))
                })
            })
    }
}
