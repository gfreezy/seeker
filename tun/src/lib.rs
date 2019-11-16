use std::collections::HashMap;
use std::future::Future;
use std::io::Result;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use futures::{ready, AsyncRead, AsyncWrite, Stream};
use parking_lot::Mutex;
use smoltcp::socket::{Socket, SocketHandle, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::Ipv4Cidr;
use tracing::{debug, error, trace};

use iface::ethernet::{Interface, InterfaceBuilder};
use iface::phony_socket::PhonySocket;
use lazy_static::lazy_static;
use sysconfig::setup_ip;

use crate::socket::TunSocket;

pub mod iface;
pub mod phy;

#[macro_use]
pub mod socket;

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
        tun_cidr: Ipv4Cidr,
        to_terminate: Arc<AtomicBool>,
    ) {
        let tun = phy::TunSocket::new(tun_name.as_str());
        let tun_name = tun.name();
        if cfg!(target_os = "macos") {
            setup_ip(
                tun_name,
                tun_ip.to_string().as_str(),
                tun_cidr.to_string().as_str(),
            );
        } else {
            let new_ip = Ipv4Cidr::from_netmask(tun_ip.into(), tun_cidr.netmask()).unwrap();
            setup_ip(
                tun_name,
                new_ip.to_string().as_str(),
                tun_cidr.to_string().as_str(),
            );
        }

        let device = PhonySocket::new(tun.mtu());
        let ip_addrs = vec![tun_cidr.into()];
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

#[derive(Debug, PartialEq)]
enum Handle {
    Tcp(SocketHandle),
    Udp(SocketHandle),
}

impl TunListen {
    fn may_recv_tun_handles(mut_tun: &mut Tun, handles: &mut Vec<Handle>) {
        for s in mut_tun.sockets.iter() {
            match s {
                Socket::Tcp(s) if s.may_recv() => {
                    handles.push(Handle::Tcp(s.handle()));
                }
                Socket::Udp(s) if s.is_open() => {
                    handles.push(Handle::Udp(s.handle()));
                }
                _ => {}
            }
        }
    }
}

impl Stream for TunListen {
    type Item = Result<TunSocket>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut guard = TUN.try_lock_for(Duration::from_secs(1)).unwrap();
        let mut_tun = guard.as_mut().expect("no tun setup");
        let size = mut_tun.sockets.iter().count();
        let mut before_handle = Vec::with_capacity(size);
        let mut after_handle = Vec::with_capacity(size);

        loop {
            if mut_tun.to_terminate.load(Ordering::Relaxed) {
                return Poll::Ready(None);
            }

            if let Some(s) = mut_tun.new_sockets.pop() {
                trace!("new socket accepted: {}", s);
                return Poll::Ready(Some(Ok(s)));
            }

            TunListen::may_recv_tun_handles(mut_tun, &mut before_handle);

            {
                let phony_socket = mut_tun.iface.device_mut();
                let mut total_size = 0;
                while let Some(buf) = phony_socket.populate_rx() {
                    let size = match Pin::new(&mut mut_tun.tun).poll_read(cx, buf) {
                        Poll::Ready(Ok(size)) => {
                            buf.truncate(size);
                            trace!("tun.poll_read size {}", size);
                            size
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                        Poll::Pending => {
                            buf.clear();
                            if total_size > 0 {
                                trace!("tun.poll_read will block, total read size: {}", total_size);
                                break;
                            } else {
                                return Poll::Pending;
                            }
                        }
                    };
                    total_size += size;
                }
            }

            match mut_tun
                .iface
                .poll_read(&mut mut_tun.sockets, Instant::now())
            {
                Ok(_) => {}
                Err(smoltcp::Error::Malformed) | Err(smoltcp::Error::Dropped) => {}
                Err(e) => {
                    error!("iface.poll_read error: {}, poll again", e);
                }
            };

            if let Some(waker) = mut_tun.tun_write_task.take() {
                debug!("notify tun for write");
                waker.wake();
            }

            for mut socket in mut_tun.sockets.iter_mut() {
                match &mut *socket {
                    Socket::Tcp(ref mut s) => {
                        if s.is_open() && (s.can_recv() || !s.may_recv()) {
                            if let Some(t) = mut_tun.socket_read_tasks.get_mut(&s.handle()) {
                                if let Some(waker) = t.take() {
                                    debug!("notify tcp socket {} for read", s.handle());
                                    waker.wake();
                                }
                            }
                        }
                    }

                    Socket::Udp(s) => {
                        if s.is_open() && s.can_recv() {
                            if let Some(t) = mut_tun.socket_read_tasks.get_mut(&s.handle()) {
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

            mut_tun.sockets.prune();

            TunListen::may_recv_tun_handles(mut_tun, &mut after_handle);
            for handle in &after_handle {
                if !before_handle.contains(handle) {
                    let sock = match handle {
                        Handle::Tcp(h) => unsafe { TunSocket::new_tcp_socket(*h) },
                        Handle::Udp(h) => unsafe { TunSocket::new_udp_socket(*h) },
                    };
                    mut_tun.new_sockets.push(sock);
                }
            }
            before_handle.clear();
            after_handle.clear();
        }
    }
}

pub struct TunWrite;

impl TunWrite {
    fn poll_write_sockets_to_phoney_socket(cx: &mut Context<'_>, tun: &mut Tun) -> Result<bool> {
        let processed_any = match tun.iface.poll_write(&mut tun.sockets, Instant::now()) {
            Ok(any) => any,
            Err(smoltcp::Error::Malformed) | Err(smoltcp::Error::Dropped) => true,
            Err(e) => {
                error!("poll_write error: {}, poll again", e);
                true
            }
        };

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
        }
        Ok(processed_any)
    }
}

impl Future for TunWrite {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let mut guard = TUN.try_lock_for(Duration::from_secs(5)).unwrap();
            let mut_tun = guard.as_mut().expect("no tun setup");

            if mut_tun.to_terminate.load(Ordering::Relaxed) {
                return Poll::Ready(Ok(()));
            }

            loop {
                let phony_socket = mut_tun.iface.device_mut();
                let buf = phony_socket.vacate_tx();
                match buf {
                    Some(buf) if buf.is_empty() => {}
                    Some(buf) => {
                        let size = ready!(Pin::new(&mut mut_tun.tun).poll_write(cx, &buf)).unwrap();
                        assert_eq!(size, buf.len());
                        debug!("write {} bytes to tun.", size);
                    }
                    None => break,
                }
            }

            if !TunWrite::poll_write_sockets_to_phoney_socket(cx, mut_tun)? {
                return Poll::Pending;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use async_std::io;
    use async_std::net::TcpStream;
    use async_std::task;
    use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
    use smoltcp::wire::Ipv4Address;

    use super::*;

    #[test]
    fn test_accept_tcp() {
        let to_terminate = Arc::new(AtomicBool::new(false));
        Tun::setup(
            "utun4".to_string(),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Cidr::new(Ipv4Address::new(10, 0, 0, 0), 24),
            to_terminate.clone(),
        );

        task::block_on(async move {
            task::spawn(Tun::bg_send());

            task::spawn(async move {
                let mut stream = Tun::listen();
                loop {
                    match stream.next().await {
                        Some(Ok(TunSocket::Tcp(mut s))) => {
                            assert_eq!(
                                s.local_addr(),
                                "10.0.0.2:80".parse::<SocketAddr>().unwrap()
                            );
                            let mut buf = vec![0; 1024];
                            let size = s.read(&mut buf).await.unwrap();
                            assert_eq!(size, 5);
                            assert_eq!(&buf[..size], "hello".as_bytes());
                        }
                        _ => panic!(),
                    }
                }
            });

            task::sleep(Duration::from_secs(1)).await;
            let mut stream = io::timeout(Duration::from_secs(1), TcpStream::connect("10.0.0.2:80"))
                .await
                .expect("connect 10.0.0.2:80");
            stream.write_all("hello".as_bytes()).await.unwrap();

            task::sleep(Duration::from_secs(1)).await;
        });
    }
}
