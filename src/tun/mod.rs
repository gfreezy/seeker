use iface::ethernet::{Interface, InterfaceBuilder};
use iface::phony_socket::PhonySocket;
use log::debug;
use phy::TunSocket;
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

pub mod iface;
pub mod phy;

macro_rules! try_ready {
    ($e:expr) => {
        match $e {
            Ok(Async::Ready(t)) => t,
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(e) => return Err(e),
        }
    };
}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Addr {
    pub src: IpEndpoint,
    pub dst: IpEndpoint,
}

#[derive(Debug, Clone)]
pub enum SocketBuf {
    Tcp(Addr, Vec<u8>),
    Udp(Addr, Vec<u8>),
}

impl SocketBuf {
    pub fn new_tcp(src: IpEndpoint, dst: IpEndpoint, buf: Vec<u8>) -> Self {
        SocketBuf::Tcp(Addr { src, dst }, buf)
    }

    pub fn new_udp(src: IpEndpoint, dst: IpEndpoint, buf: Vec<u8>) -> Self {
        SocketBuf::Udp(Addr { src, dst }, buf)
    }
}

thread_local! {
    /// Tracks the reactor for the current execution context.
    static TUN: RefCell<Tun> = RefCell::new(Tun::new("utun4"));
}

pub struct Tun {
    iface: Interface<'static, PhonySocket>,
    tun: TunSocket,
    sockets: SocketSet<'static, 'static, 'static>,
    socket_read_tasks: HashMap<SocketHandle, Option<Task>>,
    socket_write_tasks: HashMap<SocketHandle, Option<Task>>,
    tun_write_task: Option<Task>,
}

impl Tun {
    pub fn new(tun_name: &str) -> Self {
        let tun = TunSocket::new(tun_name).expect("open tun");
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
        new_handles: vec![],
        active_handles: HashSet::new(),
    }
}

pub fn bg_send() -> TunWrite {
    TunWrite { buf: vec![0; 1024] }
}

pub struct TunTcpSocket {
    pub(crate) handle: SocketHandle,
}

impl TunTcpSocket {
    pub fn new(handle: SocketHandle) -> Self {
        TunTcpSocket { handle }
    }
}

impl Read for TunTcpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug!("TunTcpSocket.read");
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            if socket.can_recv() {
                let size = socket
                    .recv_slice(buf)
                    .map_err(|e| -> io::Error { io::ErrorKind::Other.into() })?;
                Ok(size)
            } else {
                let h = socket.handle();
                t.socket_read_tasks.insert(h, Some(current()));
                Err(io::ErrorKind::WouldBlock.into())
            }
        })
    }
}

impl Write for TunTcpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug!("TunTcpSocket.write");
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            if socket.can_send() {
                let size = socket
                    .send_slice(buf)
                    .map_err(|e| -> io::Error { io::ErrorKind::Other.into() })?;
                if let Some(task) = t.tun_write_task.take() {
                    task.notify();
                }
                Ok(size)
            } else {
                let h = socket.handle();
                t.socket_write_tasks.insert(h, Some(current()));
                Err(io::ErrorKind::WouldBlock.into())
            }
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for TunTcpSocket {}
impl AsyncWrite for TunTcpSocket {
    fn shutdown(&mut self) -> Result<Async<()>, io::Error> {
        debug!("shutdown");
        Ok(Async::Ready(()))
    }
}

pub struct TunListen {
    new_handles: Vec<SocketHandle>,
    active_handles: HashSet<SocketHandle>,
}

impl TunListen {
    fn may_recv_handles(&mut self) -> HashSet<SocketHandle> {
        TUN.with(|tun| {
            let mut_tun = &mut *tun.borrow_mut();
            mut_tun
                .sockets
                .iter()
                .filter(|s| match s {
                    Socket::Tcp(s) => {
                        debug!("socket {} recv_queue: {}", s.handle(), s.recv_queue());
                        s.may_recv()
                    }
                    Socket::Udp(s) => s.can_recv(),
                    _ => unreachable!(),
                })
                .map(|s| s.handle())
                .collect::<HashSet<_>>()
        })
    }
}

impl Stream for TunListen {
    type Item = TunTcpSocket;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            if let Some(handle) = self.new_handles.pop() {
                debug!("new socket: {}", handle);
                self.active_handles.insert(handle);
                return Ok(Async::Ready(Some(TunTcpSocket::new(handle))));
            } else {
                let before_sockets = self.may_recv_handles();

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
                                debug!("socket {} state: {}.", s.handle(), s.state());
                                if s.is_open() {
                                    if s.can_recv() {
                                        debug!("socket {} can recv.", s.handle());
                                        if let Some(t) =
                                            mut_tun.socket_read_tasks.get_mut(&s.handle())
                                        {
                                            if let Some(task) = t.take() {
                                                debug!("notify {} for read", s.handle());
                                                task.notify();
                                            }
                                        }
                                    }
                                } else {
                                    to_remove_handle.push(s.handle());
                                }
                            }
                            _ => unreachable!(),
                        }
                    }

                    for h in to_remove_handle {
                        mut_tun.sockets.remove(h);
                        self.active_handles.remove(&h);
                    }

                    Ok(Async::Ready(()))
                }));

                let after_sockets = self.may_recv_handles();

                TUN.with(|tun| {
                    let mut_tun = &mut *tun.borrow_mut();

                    for handle in &self.active_handles {
                        let mut s = mut_tun.sockets.get::<TcpSocket>(*handle);
                        if !s.may_recv() {
                            debug!("close socket {}", handle);
                            s.close();
                        }
                    }
                });

                self.new_handles = after_sockets.difference(&before_sockets).copied().collect();
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
                                    debug!("can_send: {}", s.handle());
                                    if let Some(t) = mut_tun.socket_write_tasks.get_mut(&s.handle())
                                    {
                                        if let Some(task) = t.take() {
                                            debug!("notify {} for write", s.handle());
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
