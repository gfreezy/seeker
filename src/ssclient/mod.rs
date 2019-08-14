pub mod ahead;
mod crypto_io;
pub mod stream;
pub mod tcp;
pub mod udp;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

use crate::ssclient::crypto_io::{decrypt_payload, encrypt_payload};
use crate::ssclient::tcp::connect_proxy_server;
use crate::ssclient::udp::{PacketStream, MAXIMUM_UDP_PAYLOAD_SIZE};
use crate::tun::socket::{TunTcpSocket, TunUdpSocket};
use log::debug;
use log::error;
use shadowsocks::relay::boxed_future;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::{
    proxy_server_handshake, tunnel, DecryptedRead, EncryptedWrite, TimeoutFuture,
};
use shadowsocks::{ServerAddr, ServerConfig};
use std::io;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::prelude::{Future, FutureExt, Stream};
use tokio::runtime::current_thread::spawn;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::AsyncResolver;

pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    async_resolver: AsyncResolver,
}

impl SSClient {
    pub fn new(server_config: ServerConfig) -> Self {
        let nameserver_config_group =
            NameServerConfigGroup::from_ips_clear(&["114.114.114.114".parse().unwrap()], 53);
        let config = ResolverConfig::from_parts(None, vec![], nameserver_config_group);
        let options = ResolverOpts::default();
        let (resolver, background) = AsyncResolver::new(config, options);
        //        let (resolver, background) = AsyncResolver::from_system_conf().unwrap();
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

    pub fn handle_packets(
        &self,
        socket: TunUdpSocket,
        addr: Address,
    ) -> impl Future<Item = (), Error = io::Error> + Send {
        let svr_cfg = self.srv_cfg.clone();

        resolve(&self.async_resolver, svr_cfg.clone()).and_then(|remote_addr| {
            PacketStream::new(socket.clone()).for_each(move |(pkt, src)| {
                let addr = addr.clone();
                let addr2 = addr.clone();
                let svr_cfg_cloned = svr_cfg.clone();
                let svr_cfg_cloned_cloned = svr_cfg.clone();
                let socket = socket.clone();
                let timeout = *svr_cfg.udp_timeout();

                const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
                let svr_cfg = svr_cfg_cloned_cloned;
                let local_addr = "0.0.0.0:0".parse().unwrap();
                let remote_udp = UdpSocket::bind(&local_addr).unwrap();
                let mut buf = vec![];
                addr.write_to_buf(&mut buf);
                buf.extend_from_slice(&pkt);
                let payload = encrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf).unwrap();
                debug!(
                    "UDP ASSOCIATE {} -> {}, payload length {} bytes",
                    src,
                    addr,
                    payload.len()
                );
                let to = timeout.unwrap_or(DEFAULT_TIMEOUT);

                let rel = remote_udp
                    .send_dgram(payload, &remote_addr)
                    .timeout(to)
                    .map_err(move |err| match err.into_inner() {
                        Some(e) => e,
                        None => {
                            error!(
                                "Udp associate sending datagram {} -> {} timed out in {:?}",
                                src, addr, to
                            );
                            io::Error::new(io::ErrorKind::TimedOut, "udp send timed out")
                        }
                    })
                    .map(|(remote_udp, _)| (remote_udp, addr2))
                    .and_then(move |(remote_udp, addr)| {
                        let buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
                        let to = timeout.unwrap_or(DEFAULT_TIMEOUT);
                        let caddr = addr.clone();
                        remote_udp
                            .recv_dgram(buf)
                            .timeout(to)
                            .map_err(move |err| match err.into_inner() {
                                Some(e) => e,
                                None => {
                                    error!(
                                        "Udp associate waiting datagram {} <- {} timed out in {:?}",
                                        src, caddr, to
                                    );
                                    io::Error::new(io::ErrorKind::TimedOut, "udp recv timed out")
                                }
                            })
                            .and_then(move |(_remote_udp, buf, n, _from)| {
                                let svr_cfg = svr_cfg_cloned;
                                decrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf[..n])
                            })
                            .map(|payload| (payload, addr))
                    })
                    .and_then(move |(payload, addr)| {
                        Address::read_from(Cursor::new(payload))
                            .map_err(From::from)
                            .map(|(cur, ..)| (cur, addr))
                    })
                    .and_then(move |(mut cur, addr)| {
                        let payload_len = cur.get_ref().len() - cur.position() as usize;
                        debug!(
                            "UDP ASSOCIATE {} <- {}, payload length {} bytes",
                            src, addr, payload_len
                        );
                        let mut data = vec![];
                        let size = cur.read_to_end(&mut data).unwrap();
                        debug!("UDP payload size: {}", size);
                        data.truncate(size);
                        socket.send_dgram(data, src)
                    })
                    .map(|_| ());

                tokio::spawn(rel.map_err(|err| {
                    error!("Error occurs in UDP relay: {}", err);
                }));

                Ok(())
            })
        })
    }
}

/// Resolve address to IP
pub fn resolve(
    async_resolver: &AsyncResolver,
    svr_cfg: Arc<ServerConfig>,
) -> impl Future<Item = SocketAddr, Error = io::Error> + Send {
    let svr_addr = svr_cfg.addr();
    match svr_addr {
        ServerAddr::SocketAddr(addr) => boxed_future(futures::finished(*addr)),
        ServerAddr::DomainName(domain, port) => {
            let port = *port;
            let fut = async_resolver
                .lookup_ip(domain.as_str())
                .map_err(|e| {
                    debug!("resolve error: {}", e);
                    e.into()
                })
                .map(move |ips| {
                    let ip = ips.into_iter().next().unwrap();
                    debug!("resolve ss server: {}", ip);
                    SocketAddr::new(ip, port)
                });
            boxed_future(try_timeout(fut, svr_cfg.timeout()))
        }
    }
}

pub fn try_timeout<T, F>(
    fut: F,
    dur: Option<Duration>,
) -> impl Future<Item = T, Error = io::Error> + Send
where
    F: Future<Item = T, Error = io::Error> + Send + 'static,
    T: 'static,
{
    use tokio::prelude::*;

    match dur {
        Some(dur) => TimeoutFuture::Wait(fut.timeout(dur)),
        _ => TimeoutFuture::Direct(fut),
    }
}
