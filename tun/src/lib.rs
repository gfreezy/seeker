pub mod iface;
pub mod phy;

#[macro_use]
pub mod socket;

use crate::socket::TunSocket;
use futures::{ready, AsyncRead, AsyncWrite, Stream};
use iface::ethernet::{Interface, InterfaceBuilder};
use iface::phony_socket::PhonySocket;
use lazy_static::lazy_static;
use parking_lot::Mutex;
use smoltcp::socket::{Socket, SocketHandle, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::IpCidr;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::io::Result;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use sysconfig::setup_ip;
use tracing::{debug, error};

lazy_static! {
    static ref TUN: Mutex<Option<Tun>> = Mutex::new(None);
}

pub struct Tun {
    iface: Interface<'static, PhonySocket>,
    tun: phy::TunSocket,
    sockets: SocketSet<'static, 'static, 'static>,
    new_sockets: Vec<TunSocket>,
    socket_read_tasks: HashMap<SocketHandle, Option<Waker>>,
    socket_write_tasks: HashMap<SocketHandle, Option<Waker>>,
    tun_write_task: Option<Waker>,
    to_terminate: Arc<AtomicBool>,
}

impl Tun {
    pub fn setup(
        tun_name: String,
        tun_ip: Ipv4Addr,
        tun_cidr: IpCidr,
        to_terminate: Arc<AtomicBool>,
    ) {
        let tun = phy::TunSocket::new(tun_name.as_str());
        let tun_name = tun.name().unwrap();
        setup_ip(
            &tun_name,
            tun_ip.to_string().as_str(),
            tun_cidr.to_string().as_str(),
        );

        let device = PhonySocket::new(tun.mtu().unwrap());
        let ip_addrs = vec![tun_cidr];
        let iface = InterfaceBuilder::new(device)
            .ip_addrs(ip_addrs)
            .any_ip(true)
            .finalize();

        let sockets = SocketSet::new(vec![]);
        let new_sockets = Vec::new();
        let tun = Tun {
            iface,
            tun,
            sockets,
            new_sockets,
            socket_read_tasks: HashMap::new(),
            socket_write_tasks: HashMap::new(),
            tun_write_task: None,
            to_terminate,
        };
        let _ = TUN
            .try_lock_for(Duration::from_secs(1))
            .unwrap()
            .replace(tun);
    }

    pub fn listen() -> TunListen {
        TunListen
    }

    pub fn bg_send() -> TunWrite {
        TunWrite
    }
}

pub struct TunListen;

#[derive(Debug, Eq, PartialEq, Hash)]
enum Handle {
    Tcp(SocketHandle),
    Udp(SocketHandle),
}

impl TunListen {
    fn may_recv_tun_handles(mut_tun: &mut Tun) -> HashSet<Handle> {
        mut_tun
            .sockets
            .iter()
            .filter_map(|s| match s {
                Socket::Tcp(s) => {
                    if s.may_recv() {
                        Some(Handle::Tcp(s.handle()))
                    } else {
                        None
                    }
                }
                Socket::Udp(s) => {
                    if s.is_open() {
                        Some(Handle::Udp(s.handle()))
                    } else {
                        None
                    }
                }
                _ => unreachable!(),
            })
            .collect::<HashSet<_>>()
    }
}

impl Stream for TunListen {
    type Item = Result<TunSocket>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        debug!("TunListen.poll");
        loop {
            let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
            let mut_tun = guard.as_mut().expect("no tun setup");

            if mut_tun.to_terminate.load(Ordering::Relaxed) {
                return Poll::Ready(None);
            }

            debug!("TunListen.poll start loop");
            if let Some(s) = mut_tun.new_sockets.pop() {
                debug!("new socket: {}", s);
                return Poll::Ready(Some(Ok(s)));
            }

            let before_handles = TunListen::may_recv_tun_handles(mut_tun);

            {
                let mut lower = mut_tun.iface.device_mut().lower();
                let mut buf = vec![0; mut_tun.tun.mtu().unwrap()];
                let size = ready!(Pin::new(&mut mut_tun.tun).poll_read(cx, &mut buf)).unwrap();
                debug!("tun poll_read size {}", size);
                lower.rx.enqueue_slice(&buf[..size]);
                debug!("lower.rx size: {}", lower.rx.len());
            }

            match mut_tun
                .iface
                .poll_read(&mut mut_tun.sockets, Instant::now())
            {
                Ok(_) => {
                    debug!("tun.iface.poll_read success");
                }
                Err(e) => {
                    error!("poll_read error: {}, poll again", e);
                }
            };

            if let Some(waker) = mut_tun.tun_write_task.take() {
                debug!("notify TunWrite");
                waker.wake();
            }

            for mut socket in mut_tun.sockets.iter_mut() {
                match &mut *socket {
                    Socket::Tcp(ref mut s) => {
                        //                                debug!("tcp socket {} state: {}.", s.handle(), s.state());
                        if s.is_open() {
                            // notify can recv or notify to be closed
                            if s.can_recv() || !s.may_recv() {
                                //                                        debug!("tcp socket {} can recv or close.", s.handle());
                                if let Some(t) = mut_tun.socket_read_tasks.get_mut(&s.handle()) {
                                    if let Some(waker) = t.take() {
                                        debug!(
                                            "notify tcp socket {} for read or close",
                                            s.handle()
                                        );
                                        waker.wake();
                                    }
                                }
                            }
                        }
                    }
                    Socket::Udp(s) => {
                        debug!("udp socket {}.", s.handle());
                        if s.is_open() && s.can_recv() {
                            debug!("udp socket {} can recv.", s.handle());
                            if let Some(t) = mut_tun.socket_read_tasks.get_mut(&s.handle()) {
                                debug!("udp socket {} get task {:?}.", s.handle(), &t);
                                if let Some(waker) = t.take() {
                                    debug!("notify udp socket {} for read", s.handle());
                                    waker.wake();
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }

            debug!("TunListen.poll sockets.prune");
            mut_tun.sockets.prune();

            let after_handles = TunListen::may_recv_tun_handles(mut_tun);
            let new_sockets = after_handles
                .difference(&before_handles)
                .map(|h| match h {
                    Handle::Tcp(h) => unsafe { TunSocket::new_tcp_socket(*h) },
                    Handle::Udp(h) => unsafe { TunSocket::new_udp_socket(*h) },
                })
                .collect();

            mut_tun.new_sockets = new_sockets;
        }
    }
}

pub struct TunWrite;

impl TunWrite {
    fn poll_write_sockets_to_phoney_socket(
        cx: &mut Context<'_>,
        tun: &mut Tun,
    ) -> Poll<Result<()>> {
        let processed_any = match tun.iface.poll_write(&mut tun.sockets, Instant::now()) {
            Ok(processed) => {
                debug!("tun.iface.poll_write successfully");
                processed
            }
            Err(e) => {
                error!("poll_read error: {}, poll again.", e);
                return Poll::Ready(Ok(()));
            }
        };

        debug!("TunWrite processed_any: {}", processed_any);

        for socket in tun.sockets.iter_mut() {
            match &*socket {
                Socket::Tcp(s) => {
                    //                    debug!("tcp socket {} state: {}.", s.handle(), s.state());
                    if s.can_send() {
                        //                        debug!("tcp socket {} can send", s.handle());
                        if let Some(t) = tun.socket_write_tasks.get_mut(&s.handle()) {
                            if let Some(waker) = t.take() {
                                debug!("notify tcp socket {} for write", s.handle());
                                waker.wake();
                            }
                        }
                    }
                }
                Socket::Udp(s) => {
                    if s.can_send() {
                        //                        debug!("udp socket {} can send.", s.handle());
                        if let Some(t) = tun.socket_read_tasks.get_mut(&s.handle()) {
                            if let Some(waker) = t.take() {
                                debug!("notify udp socket {} for write", s.handle());
                                waker.wake();
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        if !processed_any {
            debug!("TunWrite NotReady");
            tun.tun_write_task = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

impl Future for TunWrite {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let mut guard = TUN.try_lock_for(Duration::from_secs(5)).unwrap();
            let mut_tun = guard.as_mut().expect("no tun setup");
            {
                let mut lower = mut_tun.iface.device_mut().lower();
                let buf = lower.tx.dequeue_one();
                match buf {
                    Ok(buf) => {
                        debug!("lower.tx.dequeue_one, size: {}", buf.len());

                        let size =
                            ready!(Pin::new(&mut mut_tun.tun).poll_write(cx, buf.as_slice()))
                                .unwrap();
                        assert_eq!(size, buf.len());
                        debug!("write {} bytes to tun.", size);
                        continue;
                    }
                    Err(smoltcp::Error::Exhausted) => {}
                    Err(err) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            err.to_string(),
                        )))
                    }
                }
            }

            if mut_tun.to_terminate.load(Ordering::Relaxed) {
                return Poll::Ready(Ok(()));
            }

            let ret = TunWrite::poll_write_sockets_to_phoney_socket(cx, mut_tun);
            match ret {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::net::TcpStream;
    use async_std::task;
    use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
    use smoltcp::wire::IpAddress;
    use std::net::SocketAddr;

    #[test]
    fn test_accept_tcp() {
        let to_terminate = Arc::new(AtomicBool::new(false));
        Tun::setup(
            "utun4".to_string(),
            Ipv4Addr::new(10, 0, 0, 1),
            IpCidr::new(IpAddress::v4(10, 0, 0, 0), 24),
            to_terminate.clone(),
        );

        task::block_on(async move {
            task::spawn(Tun::bg_send());

            task::spawn(async move {
                let mut stream = Tun::listen();
                match stream.next().await {
                    Some(Ok(TunSocket::Tcp(mut s))) => {
                        assert_eq!(s.local_addr(), "10.0.0.2:80".parse::<SocketAddr>().unwrap());
                        let mut buf = vec![0; 1024];
                        let size = s.read(&mut buf).await.unwrap();
                        assert_eq!(size, 5);
                        assert_eq!(&buf[..size], "hello".as_bytes());
                    }
                    _ => panic!(),
                }
            });

            let mut stream = TcpStream::connect("10.0.0.2:80").await.unwrap();
            stream.write_all("hello".as_bytes()).await.unwrap();

            task::sleep(Duration::from_secs(1)).await;
        });
    }
}
