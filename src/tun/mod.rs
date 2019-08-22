pub mod iface;
pub mod phy;

#[macro_use]
pub mod socket;

use iface::ethernet::{Interface, InterfaceBuilder};
use iface::phony_socket::PhonySocket;
use log::{debug, error};
use smoltcp::socket::{Socket, SocketHandle, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::process::Command;
use tokio::prelude::task::Task;
use tokio::prelude::{task::current, Async, AsyncRead, AsyncWrite, Future, Poll, Stream};

use socket::TunSocket;

fn setup_ip(tun_name: &str, ip: IpAddress, cidr: IpCidr) {
    let ip_s = ip.to_string();
    let output = Command::new("ifconfig")
        .args(&[tun_name, &ip_s, &ip_s])
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
        .arg(cidr.to_string())
        .arg(ip_s)
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
    static TUN: RefCell<Option<Tun>> = RefCell::new(None);
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
    pub fn setup(tun_name: String, tun_ip: IpAddress, tun_cidr: IpCidr) {
        let tun = phy::TunSocket::new(tun_name.as_str()).expect("open tun");
        let tun_name = tun.name();
        setup_ip(&tun_name, tun_ip, tun_cidr);

        let device = PhonySocket::new(tun.mtu());
        let ip_addrs = vec![tun_cidr];
        let iface = InterfaceBuilder::new(device)
            .ip_addrs(ip_addrs)
            .any_ip(true)
            .finalize();

        let sockets = SocketSet::new(vec![]);
        let tun = Tun {
            iface,
            tun,
            sockets,
            socket_read_tasks: HashMap::new(),
            socket_write_tasks: HashMap::new(),
            tun_write_task: None,
        };
        TUN.with(|cell| cell.borrow_mut().replace(tun));
    }

    pub fn listen() -> TunListen {
        TunListen {
            new_sockets: vec![],
        }
    }

    pub fn bg_send() -> TunWrite {
        TunWrite { buf: vec![0; 1530] }
    }
}

pub struct TunListen {
    new_sockets: Vec<TunSocket>,
}

#[derive(Debug, Eq, PartialEq, Hash)]
enum Handle {
    Tcp(SocketHandle),
    Udp(SocketHandle),
}

impl TunListen {
    fn may_recv_tun_handles(&mut self) -> HashSet<Handle> {
        TUN.with(|tun| {
            let mut s = tun.borrow_mut();
            let mut_tun = match *s {
                Some(ref mut tun) => tun,
                None => unreachable!(),
            };
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
        })
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
                return Ok(Async::Ready(Some(s)));
            } else {
                let before_handles = self.may_recv_tun_handles();

                try_ready!(TUN.with(|tun| {
                    let mut s = tun.borrow_mut();
                    let mut_tun = match *s {
                        Some(ref mut tun) => tun,
                        None => unreachable!(),
                    };

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
                                    // notify can recv or notify to be closed
                                    if s.can_recv() || !s.may_recv() {
                                        debug!("tcp socket {} can recv or close.", s.handle());
                                        if let Some(t) =
                                            mut_tun.socket_read_tasks.get_mut(&s.handle())
                                        {
                                            if let Some(task) = t.take() {
                                                debug!(
                                                    "notify tcp socket {} for read or close",
                                                    s.handle()
                                                );
                                                task.notify();
                                            }
                                        }
                                    }
                                }
                            }
                            Socket::Udp(s) => {
                                debug!("udp socket {}.", s.handle());
                                if s.is_open() && s.can_recv() {
                                    debug!("udp socket {} can recv.", s.handle());
                                    if let Some(t) = mut_tun.socket_read_tasks.get_mut(&s.handle())
                                    {
                                        if let Some(task) = t.take() {
                                            debug!("notify udp socket {} for read", s.handle());
                                            task.notify();
                                        }
                                    }
                                }
                            }
                            _ => unreachable!(),
                        }
                    }

                    debug!("TunListen.poll sockets.prune");
                    mut_tun.sockets.prune();

                    Ok(Async::Ready(()))
                }));

                let after_handles = self.may_recv_tun_handles();
                self.new_sockets = after_handles
                    .difference(&before_handles)
                    .map(|h| {
                        let socket = match h {
                            Handle::Tcp(h) => TunSocket::new_tcp_socket(*h),
                            Handle::Udp(h) => TunSocket::new_udp_socket(*h),
                        };

                        let handle = socket.handle();
                        // move handle to socket
                        TUN.with(|tun| {
                            debug!("release handle {}", handle);
                            tun.borrow_mut().as_mut().map(|t| t.sockets.release(handle))
                        });
                        socket
                    })
                    .collect();
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
                let mut s = tun.borrow_mut();
                let mut_tun = match *s {
                    Some(ref mut tun) => tun,
                    None => unreachable!(),
                };

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
