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
use tokio::prelude::{Async, AsyncRead, AsyncWrite, Future, Poll, Stream};

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
        }
    }
}

pub fn listen() -> TunListen {
    TunListen {
        new_sockets: vec![],
    }
}

pub fn bg_send() -> TunWrite {
    TunWrite { buf: vec![0; 1024] }
}

pub struct TunTcpSocket {
    handle: SocketHandle,
}

impl TunTcpSocket {
    pub fn new(handle: SocketHandle) -> Self {
        TunTcpSocket { handle }
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            if socket.may_recv() {
                socket
                    .recv_slice(buf)
                    .map_err(|e| io::ErrorKind::Other.into())
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        })
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        TUN.with(|tun| {
            let mut t = tun.borrow_mut();
            let mut socket = t.sockets.get::<TcpSocket>(self.handle);
            if socket.may_send() {
                socket
                    .send_slice(buf)
                    .map_err(|e| io::ErrorKind::Other.into())
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        })
    }
}

pub struct TunListen {
    new_sockets: Vec<SocketHandle>,
}

impl Stream for TunListen {
    type Item = TunTcpSocket;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            if let Some(handle) = self.new_sockets.pop() {
                return Ok(Async::Ready(Some(TunTcpSocket::new(handle))));
            } else {
                try_ready!(TUN.with(|tun| {
                    let before_sockets = tun
                        .borrow()
                        .sockets
                        .iter()
                        .map(|s| s.handle())
                        .collect::<Vec<_>>();

                    let mut_tun = &mut *tun.borrow_mut();
                    {
                        let mut lower = mut_tun.iface.device_mut().lower();
                        let mut buf = vec![0; 1024];
                        let size = try_ready!(mut_tun.tun.poll_read(&mut buf));
                        debug!("ssclientread size {}", size);
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
                            debug!("poll_read error: {}", e);
                        }
                    };

                    let after_sockets = TUN.with(|tun| {
                        tun.borrow()
                            .sockets
                            .iter()
                            .map(|s| s.handle())
                            .collect::<Vec<_>>()
                    });

                    self.new_sockets = after_sockets
                        .into_iter()
                        .filter(|s| !before_sockets.contains(s))
                        .collect();

                    Ok(Async::Ready(()))
                }))
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
                    match mut_tun
                        .iface
                        .poll_write(&mut mut_tun.sockets, Instant::now())
                    {
                        Ok(_) => debug!("tun.iface.poll_write successfully"),
                        Err(e) => {
                            debug!("poll_read error: {}", e);
                        }
                    }

                    let mut lower = mut_tun.iface.device_mut().lower();
                    debug!("lower.tx.dequeue_many");
                    let size = lower.tx.dequeue_slice(&mut self.buf);
                    self.buf.truncate(size);
                }

                let size = try_ready!(mut_tun.tun.poll_write(&self.buf));
                let s2 = self.buf.drain(0..size).count();
                debug!("write {} bytes to tun.", s2);
                Ok(Async::Ready(()))
            }))
        }
    }
}
