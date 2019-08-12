pub mod iface;
pub mod phy;

#[macro_use]
pub mod socket;

use iface::ethernet::{Interface, InterfaceBuilder};
use iface::phony_socket::PhonySocket;
use log::{debug, error};
use smoltcp::socket::{Socket, SocketHandle, SocketSet, TcpSocket};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;
use tokio::prelude::task::Task;
use tokio::prelude::{task::current, Async, AsyncRead, AsyncWrite, Future, Poll, Stream};

use crate::tun::phy::Error;
use crate::tun::socket::TunTcpSocket;
use socket::TunSocket;

fn setup_ip(tun_name: &str, ip: &str, dest_ip: &str) {
    let output = Command::new("ifconfig")
        .args(&[tun_name, ip, dest_ip])
        .output()
        .expect("run ifconfig");
    if !output.status.success() {
        panic!(
            "stdout: {}\nstderr: {}",
            std::str::from_utf8(&output.stdout).expect("utf8"),
            std::str::from_utf8(&output.stderr).expect("utf8")
        );
    }
    let output = Command::new("route")
        .arg("add")
        .arg("10.0.0.0/24")
        .arg(ip)
        .output()
        .expect("add route");
    if !output.status.success() {
        panic!(
            "stdout: {}\nstderr: {}",
            std::str::from_utf8(&output.stdout).expect("utf8"),
            std::str::from_utf8(&output.stderr).expect("utf8")
        );
    }
}

thread_local! {
    static TUN: RefCell<Tun> = RefCell::new(Tun::new("utun4"));
}

pub struct Tun {
    iface: Interface<'static, PhonySocket>,
    tun: phy::TunSocket,
    sockets: SocketSet<'static, 'static, 'static>,
    socket_read_tasks: HashMap<SocketHandle, Option<Task>>,
    socket_write_tasks: HashMap<SocketHandle, Option<Task>>,
    tun_write_task: Option<Task>,
}

impl Tun {
    pub fn new(tun_name: &str) -> Self {
        let tun = phy::TunSocket::new(tun_name).expect("open tun");
        let tun_name = tun.name();
        setup_ip(&tun_name, "10.0.0.1", "10.0.1.1");

        let device = PhonySocket::new(tun.mtu());
        let ip_addrs = vec![IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24)];
        let iface = InterfaceBuilder::new(device)
            .ip_addrs(ip_addrs)
            .any_ip(true)
            .finalize();

        let sockets = SocketSet::new(vec![]);
        Tun {
            iface,
            tun,
            sockets,
            socket_read_tasks: HashMap::new(),
            socket_write_tasks: HashMap::new(),
            tun_write_task: None,
        }
    }
}

pub fn listen() -> TunListen {
    TunListen {
        new_sockets: vec![],
        active_tcp_handles: HashSet::new(),
    }
}

pub fn bg_send() -> TunWrite {
    TunWrite { buf: vec![0; 1530] }
}

pub struct TunListen {
    new_sockets: Vec<TunSocket>,
    active_tcp_handles: HashSet<SocketHandle>,
}

impl TunListen {
    fn may_recv_tun_sockets(&mut self) -> HashSet<TunSocket> {
        #[derive(Debug, Eq, PartialEq, Hash)]
        enum Handle {
            Tcp(SocketHandle),
            Udp(SocketHandle),
        }

        let handles = TUN.with(|tun| {
            let mut_tun = &mut *tun.borrow_mut();
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
                        if s.can_recv() {
                            Some(Handle::Udp(s.handle()))
                        } else {
                            None
                        }
                    }
                    _ => unreachable!(),
                })
                .collect::<HashSet<_>>()
        });

        handles
            .into_iter()
            .map(|h| match h {
                Handle::Tcp(h) => TunSocket::new_tcp_socket(h),
                Handle::Udp(h) => TunSocket::new_udp_socket(h),
            })
            .collect()
    }
}

impl Stream for TunListen {
    type Item = TunSocket;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        debug!("TunListen.poll");
        loop {
            debug!("TunListen.poll start loop");
            if let Some(s) = self.new_sockets.pop() {
                debug!("new socket: {}", s);
                if let TunSocket::Tcp(_) = s {
                    self.active_tcp_handles.insert(s.handle());
                }
                return Ok(Async::Ready(Some(s)));
            } else {
                let before_sockets = self.may_recv_tun_sockets();

                try_ready!(TUN.with(|tun| {
                    let mut_tun = &mut *tun.borrow_mut();

                    {
                        let mut lower = mut_tun.iface.device_mut().lower();
                        let mut buf = vec![0; mut_tun.tun.mtu()];
                        let size = try_ready!(mut_tun.tun.poll_read(&mut buf));
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
                        Err(smoltcp::Error::Dropped) => {
                            return Ok(Async::Ready(()));
                        }
                        Err(e) => {
                            error!("poll_read error: {}, poll again", e);
                            return Ok(Async::Ready(()));
                        }
                    };

                    if let Some(task) = mut_tun.tun_write_task.take() {
                        debug!("notify TunWrite");
                        task.notify();
                    }

                    for mut socket in mut_tun.sockets.iter_mut() {
                        match &mut *socket {
                            Socket::Tcp(ref mut s) => {
                                debug!("tcp socket {} state: {}.", s.handle(), s.state());
                                if s.is_open() {
                                    if s.can_recv() {
                                        debug!("tcp socket {} can recv.", s.handle());
                                        if let Some(t) =
                                            mut_tun.socket_read_tasks.get_mut(&s.handle())
                                        {
                                            if let Some(task) = t.take() {
                                                debug!("notify tcp socket {} for read", s.handle());
                                                task.notify();
                                            }
                                        }
                                    }
                                }
                            }
                            Socket::Udp(s) => {
                                debug!("udp socket {}.", s.handle());
                                if s.is_open() {
                                    if s.can_recv() {
                                        debug!("udp socket {} can recv.", s.handle());
                                        if let Some(t) =
                                            mut_tun.socket_read_tasks.get_mut(&s.handle())
                                        {
                                            if let Some(task) = t.take() {
                                                debug!("notify udp socket {} for read", s.handle());
                                                task.notify();
                                            }
                                        }
                                    }
                                }
                            }
                            _ => unreachable!(),
                        }
                    }

                    let mut to_remove_handle = vec![];
                    for handle in &self.active_tcp_handles {
                        let mut s = mut_tun.sockets.get::<TcpSocket>(*handle);
                        if !s.may_recv() {
                            debug!("close socket {}", handle);
                            s.close();
                            to_remove_handle.push(*handle);
                            if let Some(t) = mut_tun.socket_read_tasks.get_mut(handle) {
                                if let Some(task) = t.take() {
                                    debug!("notify tcp socket {} to close", handle);
                                    task.notify();
                                }
                            }
                        }
                    }

                    for h in to_remove_handle {
                        debug!("TunListen.poll release handle: {}", h);
                        mut_tun.sockets.release(h);
                        self.active_tcp_handles.remove(&h);
                    }

                    debug!("TunListen.poll sockets.prune");
                    mut_tun.sockets.prune();

                    Ok(Async::Ready(()))
                }));

                let after_sockets = self.may_recv_tun_sockets();

                self.new_sockets = after_sockets.difference(&before_sockets).cloned().collect();
            }
        }
    }
}

pub struct TunWrite {
    buf: Vec<u8>,
}

impl TunWrite {
    fn poll_write_sockets_to_phoney_socket(tun: &mut Tun) -> Poll<(), io::Error> {
        let processed_any = match tun.iface.poll_write(&mut tun.sockets, Instant::now()) {
            Ok(processed) => {
                debug!("tun.iface.poll_write successfully");
                processed
            }
            Err(e) => {
                error!("poll_read error: {}, poll again.", e);
                return Ok(Async::Ready(()));
            }
        };

        debug!("TunWrite processed_any: {}", processed_any);

        for socket in tun.sockets.iter_mut() {
            match &*socket {
                Socket::Tcp(s) => {
                    debug!("tcp socket {} state: {}.", s.handle(), s.state());
                    if s.can_send() {
                        debug!("tcp socket {} can send", s.handle());
                        if let Some(t) = tun.socket_write_tasks.get_mut(&s.handle()) {
                            if let Some(task) = t.take() {
                                debug!("notify tcp socket {} for write", s.handle());
                                task.notify();
                            }
                        }
                    }
                }
                Socket::Udp(s) => {
                    if s.can_send() {
                        debug!("udp socket {} can send.", s.handle());
                        if let Some(t) = tun.socket_read_tasks.get_mut(&s.handle()) {
                            if let Some(task) = t.take() {
                                debug!("notify udp socket {} for write", s.handle());
                                task.notify();
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        if !processed_any {
            debug!("TunWrite NotReady");
            tun.tun_write_task = Some(current());
            return Ok(Async::NotReady);
        }
        Ok(Async::Ready(()))
    }
}

impl Future for TunWrite {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            debug!("TunWrite.poll loop: self.buf: {}", self.buf.len());
            match TUN.with(|tun| {
                let mut_tun = &mut *tun.borrow_mut();

                {
                    let mut lower = mut_tun.iface.device_mut().lower();
                    let buf = lower.tx.dequeue_one();
                    match buf {
                        Ok(buf) => {
                            debug!("lower.tx.dequeue_one, size: {}", buf.len());

                            let size = try_ready!(mut_tun.tun.poll_write(buf.as_slice()));
                            assert_eq!(size, buf.len());
                            debug!("write {} bytes to tun.", size);
                            return Ok(Async::Ready(()));
                        }
                        Err(smoltcp::Error::Exhausted) => {}
                        Err(err) => {
                            return Err(io::Error::new(io::ErrorKind::Other, err.to_string()))
                        }
                    }
                }

                TunWrite::poll_write_sockets_to_phoney_socket(&mut *mut_tun)
            }) {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => return Err(e),
                _ => {}
            }
        }
    }
}
