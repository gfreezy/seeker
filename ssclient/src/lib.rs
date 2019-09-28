pub mod ahead;
pub mod crypto;
mod crypto_io;
pub mod stream;
pub mod tcp;
pub mod udp;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

use crate::tun::socket::{TunTcpSocket, TunUdpSocket};
use crypto_io::{decrypt_payload, encrypt_payload};
use futures::stream::SplitSink;
use shadowsocks::relay::boxed_future;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::{
    proxy_server_handshake, tunnel, DecryptedRead, EncryptedWrite, TimeoutFuture,
};
use shadowsocks::{ServerAddr, ServerConfig};
use std::collections::HashMap;
use std::io;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tcp::connect_proxy_server;
use tokio::codec::BytesCodec;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{UdpFramed, UdpSocket};
use tokio::prelude::{Future, FutureExt, Sink, Stream};
use tokio::runtime::current_thread::spawn;
use tracing::{debug, debug_span, error, info, info_span};
use tracing_futures::Instrument;
use trust_dns_resolver::AsyncResolver;
use udp::PacketStream;

pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    async_resolver: AsyncResolver,
    remote_udp_map: Arc<Mutex<HashMap<(SocketAddr, u16), SplitSink<UdpFramed<BytesCodec>>>>>,
}

impl SSClient {
    pub fn new(server_config: Arc<ServerConfig>, async_resolver: AsyncResolver) -> Self {
        SSClient {
            srv_cfg: server_config,
            async_resolver,
            remote_udp_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn handle_connect(
        &self,
        (r, w): (ReadHalf<TunTcpSocket>, WriteHalf<TunTcpSocket>),
        addr: Address,
    ) -> impl Future<Item = (), Error = io::Error> + Send {
        let cfg = self.srv_cfg.clone();
        let timeout = Some(Duration::from_secs(30));
        connect_proxy_server(self.srv_cfg.clone(), &self.async_resolver)
            .instrument(info_span!("connect_proxy_server"))
            .and_then(move |stream| {
                debug!("connected remote stream");
                proxy_server_handshake(stream, cfg, addr)
                    .instrument(debug_span!("proxy_server_handshake"))
            })
            .and_then(move |(srv_r, srv_w)| {
                info!("proxy server handshake successfully");
                let rhalf = srv_r
                    .and_then(move |svr_r| {
                        svr_r
                            .copy_timeout_opt(w, timeout)
                            .instrument(debug_span!("copy_srv_to_local"))
                    })
                    .map_err(|e| {
                        debug!("copy srv to local: {:#?}", e);
                        e
                    });
                let whalf = srv_w
                    .and_then(move |svr_w| {
                        svr_w
                            .copy_timeout_opt(r, timeout)
                            .instrument(debug_span!("copy_local_to_srv"))
                    })
                    .map_err(|e| {
                        debug!("copy local to srv: {:#?}", e);
                        e
                    });
                tunnel(whalf, rhalf).then(|s| {
                    info!("finish connection");
                    s
                })
            })
    }

    pub fn handle_packets(
        &self,
        socket: TunUdpSocket,
        addr: Address,
    ) -> impl Future<Item = (), Error = io::Error> + Send {
        let svr_cfg = self.srv_cfg.clone();
        let svr_cfg2 = svr_cfg.clone();
        let map = self.remote_udp_map.clone();

        resolve_remote_server(&self.async_resolver, svr_cfg2).and_then(move |remote_addr| {
            PacketStream::new(socket.clone()).for_each(move |(pkt, src)| {
                let addr = addr.clone();
                let svr_cfg_cloned = svr_cfg.clone();
                let svr_cfg_cloned_cloned = svr_cfg.clone();
                let socket = socket.clone();
                let timeout = *svr_cfg.udp_timeout();

                const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
                let svr_cfg = svr_cfg_cloned_cloned;
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
                let mut locked_map = map.try_lock().unwrap();
                let key = (src, remote_addr.port());
                let remote_udp = if let Some(udp) = locked_map.remove(&key) {
                    udp
                } else {
                    let local_addr = "0.0.0.0:0".parse().unwrap();
                    let remote_udp = UdpSocket::bind(&local_addr).unwrap();
                    let udp_framed = UdpFramed::new(remote_udp, BytesCodec::new());
                    let (sink, source) = udp_framed.split();

                    spawn(
                        source
                            .for_each(move |(buf, _remote_src)| {
                                let socket = socket.clone();
                                let svr_cfg = svr_cfg_cloned.clone();
                                let payload =
                                    decrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf).unwrap();
                                Address::read_from(Cursor::new(payload))
                                    .map_err(|_| io::ErrorKind::Other.into())
                                    .and_then(move |(mut cur, addr)| {
                                        let payload_len =
                                            cur.get_ref().len() - cur.position() as usize;
                                        debug!(
                                            "UDP ASSOCIATE {} <- {}, payload length {} bytes",
                                            src, addr, payload_len
                                        );
                                        let mut data = vec![];
                                        let size = cur.read_to_end(&mut data).unwrap();
                                        debug!("UDP payload size: {}", size);
                                        data.truncate(size);
                                        socket.clone().send_dgram(data, src)
                                    })
                                    .map(|_| ())
                            })
                            .map(|_| ())
                            .map_err(|_| ()),
                    );
                    debug!("new tokio udp socket");
                    sink
                };

                let map2 = map.clone();
                let rel = remote_udp
                    .send((payload.into(), remote_addr))
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
                    .map(move |sink| {
                        let mut m = map2.try_lock().unwrap();
                        m.insert(key, sink);
                    });

                spawn(rel.map_err(|err| {
                    error!("Error occurs in UDP relay: {}", err);
                }));

                Ok(())
            })
        })
    }
}

/// Resolve address to IP
pub fn resolve_remote_server(
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
                    info!("resolve ss server: {}", ip);
                    SocketAddr::new(ip, port)
                });
            boxed_future(try_timeout(fut, svr_cfg.timeout()))
        }
    }
    .instrument(info_span!("resolve_remote_server"))
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
