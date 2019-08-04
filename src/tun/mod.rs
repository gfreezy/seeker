pub mod iface;
pub mod phy;

#[macro_use]
pub mod socket;

use iface::ethernet::{Interface, InterfaceBuilder};
use iface::phony_socket::PhonySocket;
use log::debug;
use smoltcp::socket::{AnySocket, Socket, SocketHandle, SocketSet, TcpSocket, UdpSocket};
use smoltcp::time::Instant;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::{IpAddress, IpCidr};
use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;
use tokio::prelude::task::Task;
use tokio::prelude::{
    task::current, Async, AsyncRead, AsyncWrite, Future, Poll, Read, Stream, Write,
};

use socket::{TunSocket, TunTcpSocket, TunUdpSocket};

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
        setup_ip(&tun_name, "10.0.0.1", "10.0.0.100");

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
    TunWrite { buf: vec![0; 1024] }
}

pub struct TunListen {
    new_sockets: Vec<TunSocket>,
    active_tcp_handles: HashSet<SocketHandle>,
}

impl TunListen {
    fn may_recv_tun_sockets(&mut self) -> HashSet<TunSocket> {
        TUN.with(|tun| {
            let mut_tun = &mut *tun.borrow_mut();
            mut_tun
                .sockets
                .iter()
                .filter_map(|s| match s {
                    Socket::Tcp(s) => {
                        if s.may_recv() {
                            Some(TunSocket::new_tcp_socket(s.handle()))
                        } else {
                            None
                        }
                    }
                    Socket::Udp(s) => {
                        if s.can_recv() {
                            Some(TunSocket::new_udp_socket(s.handle()))
                        } else {
                            None
                        }
                    }
                    _ => unreachable!(),
                })
                .collect::<HashSet<_>>()
        })
    }
}

impl Stream for TunListen {
    type Item = TunSocket;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        debug!("TunListen.poll");
        loop {
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
                        let mut buf = vec![0; 1024];
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
                        Err(e) => {
                            debug!("poll_read error: {}, poll again", e);
                            return Ok(Async::Ready(()));
                        }
                    };

                    if let Some(task) = mut_tun.tun_write_task.take() {
                        task.notify();
                    }

                    let mut to_remove_handle = vec![];
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
                                } else {
                                    to_remove_handle.push(s.handle());
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

                    for h in to_remove_handle {
                        mut_tun.sockets.remove(h);
                        self.active_tcp_handles.remove(&h);
                    }

                    Ok(Async::Ready(()))
                }));

                TUN.with(|tun| {
                    let mut_tun = &mut *tun.borrow_mut();

                    for handle in &self.active_tcp_handles {
                        let mut s = mut_tun.sockets.get::<TcpSocket>(*handle);
                        if !s.may_recv() {
                            debug!("close socket {}", handle);
                            s.close();
                            if let Some(t) = mut_tun.socket_read_tasks.get_mut(&s.handle()) {
                                if let Some(task) = t.take() {
                                    debug!("notify udp socket {} to close", s.handle());
                                    task.notify();
                                }
                            }
                        }
                    }
                });

                let after_sockets = self.may_recv_tun_sockets();

                self.new_sockets = after_sockets.difference(&before_sockets).cloned().collect();
            }
        }
    }
}

pub struct TunWrite {
    buf: Vec<u8>,
}

impl Future for TunWrite {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            try_ready!(TUN.with(|tun| {
                let mut_tun = &mut *tun.borrow_mut();

                if self.buf.is_empty() {
                    let processed_any = match mut_tun
                        .iface
                        .poll_write(&mut mut_tun.sockets, Instant::now())
                    {
                        Ok(processed) => {
                            debug!("tun.iface.poll_write successfully");
                            processed
                        }
                        Err(e) => {
                            debug!("poll_read error: {}, poll again.", e);
                            return Ok(Async::Ready(()));
                        }
                    };

                    for socket in mut_tun.sockets.iter_mut() {
                        match &*socket {
                            Socket::Tcp(s) => {
                                if s.can_send() {
                                    debug!("tcp socket {} can send", s.handle());
                                    if let Some(t) = mut_tun.socket_write_tasks.get_mut(&s.handle())
                                    {
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
                                    if let Some(t) = mut_tun.socket_read_tasks.get_mut(&s.handle())
                                    {
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
                        mut_tun.tun_write_task = Some(current());
                        return Ok(Async::NotReady);
                    }

                    let mut lower = mut_tun.iface.device_mut().lower();
                    self.buf.resize(self.buf.capacity(), 0);
                    let size = lower.tx.dequeue_slice(&mut self.buf);
                    debug!("lower.tx.dequeue_slice: {}", size);
                    self.buf.truncate(size);
                    debug!("tun write buf {}", self.buf.len());
                }

                let size = try_ready!(mut_tun.tun.poll_write(&self.buf));
                let s2 = self.buf.drain(0..size).count();
                debug!("write {} bytes to tun.", s2);
                Ok(Async::Ready(()))
            }))
        }
    }
}
