use futures::{io, AsyncRead, AsyncReadExt, AsyncWrite};
use futures::{ready, Future};
use iface::ethernet::{Interface, InterfaceBuilder};
use iface::phony_socket::PhonySocket;
use log::debug;
use mio::unix::EventedFd;
use mio::{Evented, PollOpt, Ready, Token};
use phy::TunSocket;
use romio::raw::PollEvented;
use romio::raw::{AsyncReadReady, AsyncWriteReady};
use smoltcp::socket::{
    AnySocket, Socket, SocketHandle, SocketRef, SocketSet, TcpSocket, UdpSocket,
};
use smoltcp::time::Instant;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::process::Command;
use std::task::{Context, Poll};

pub mod iface;
pub mod phy;

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

#[derive(Copy, Clone, Debug, PartialEq)]
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

        let sockets = SocketSet::new(Vec::with_capacity(100));
        Tun {
            iface,
            tun,
            sockets,
        }
    }

    pub fn recv(&mut self) -> SSClientRead {
        SSClientRead {
            iface: &mut self.iface,
            tun: &mut self.tun,
            sockets: &mut self.sockets,
        }
    }

    pub fn send(&mut self, data: Vec<SocketBuf>) -> SSClientWrite {
        SSClientWrite {
            iface: &mut self.iface,
            tun: &mut self.tun,
            sockets: &mut self.sockets,
            data,
        }
    }
}

pub struct SSClientRead<'a> {
    iface: &'a mut Interface<'static, PhonySocket>,
    tun: &'a mut TunSocket,
    sockets: &'a mut SocketSet<'static, 'static, 'static>,
}

impl<'a> Future for SSClientRead<'a> {
    type Output = io::Result<Vec<SocketBuf>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let s = self.get_mut();

        {
            let mut lower = s.iface.device_mut().lower();
            lower.rx.len();
            let mut buf = vec![0; 1024];
            let size = ready!(Pin::new(&mut s.tun).poll_read(cx, &mut buf)).unwrap();
            debug!("ssclientread size {}", size);
            lower.rx.enqueue_slice(&buf[..size]);
            debug!("lower.rx size: {}", lower.rx.len());
        }

        match s.iface.poll_read(s.sockets, Instant::now()) {
            Ok(_) => {
                debug!("tun.iface.poll_read success");
            }
            Err(e) => {
                debug!("poll_read error: {}", e);
                return Poll::Pending;
            }
        };

        let mut data = vec![];
        for mut socket in s.sockets.iter_mut() {
            let mut buf = vec![0; 1024];
            match &mut *socket {
                Socket::Udp(ref mut socket) => {
                    if !socket.can_recv() {
                        debug!("skip udp socket: local: {}", socket.endpoint());
                        continue;
                    }

                    match socket.recv_slice(&mut buf) {
                        Ok((size, endpoint)) => {
                            buf.truncate(size);
                            data.push(SocketBuf::new_udp(endpoint, socket.endpoint(), buf));
                        }
                        Err(e) => {
                            debug!("udp socket recv error: {}", e);
                        }
                    };
                }
                Socket::Tcp(ref mut socket) => {
                    if !socket.may_recv() {
                        debug!(
                            "skip tcp socket local: {}, remote: {}",
                            socket.local_endpoint(),
                            socket.remote_endpoint()
                        );
                        continue;
                    }
                    match socket.recv_slice(&mut buf) {
                        Ok(size) => {
                            buf.truncate(size);
                            data.push(SocketBuf::new_tcp(
                                socket.remote_endpoint(),
                                socket.local_endpoint(),
                                buf,
                            ));
                        }
                        Err(e) => {
                            debug!("tcp socket recv error: {}", e);
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        Poll::Ready(Ok(data))
    }
}

pub struct SSClientWrite<'a> {
    iface: &'a mut Interface<'static, PhonySocket>,
    tun: &'a mut TunSocket,
    sockets: &'a mut SocketSet<'static, 'static, 'static>,
    data: Vec<SocketBuf>,
}

impl<'a> Future for SSClientWrite<'a> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        #[derive(Copy, Clone, Hash, PartialEq, Eq, Debug)]
        enum MapKey {
            Udp(IpEndpoint),
            Tcp(IpEndpoint, IpEndpoint),
        }

        let mut s = self.get_mut();

        let mut map = HashMap::with_capacity(10);
        for mut socket in s.sockets.iter_mut() {
            let (key, handle) = match &mut *socket {
                Socket::Udp(socket) => (MapKey::Udp(socket.endpoint()), socket.handle()),
                Socket::Tcp(socket) => (
                    MapKey::Tcp(socket.local_endpoint(), socket.remote_endpoint()),
                    socket.handle(),
                ),
                _ => unreachable!(),
            };
            map.insert(key, handle);
        }

        macro_rules! get_socket {
            ($key:expr, $ty:ty) => {{
                let handle = map[$key];
                s.sockets.get::<$ty>(handle)
            }};
        }

        for socket_buf in &s.data {
            match socket_buf {
                SocketBuf::Tcp(Addr { src, dst }, buf) => {
                    let mut socket = get_socket!(&MapKey::Tcp(*src, *dst), TcpSocket);
                    let size = socket.send_slice(&buf).unwrap();
                    assert_eq!(size, buf.len());
                }
                SocketBuf::Udp(Addr { src, dst }, buf) => {
                    let mut socket = get_socket!(&MapKey::Udp(*src), UdpSocket);
                    socket.send_slice(&buf, *dst).unwrap();
                }
            }
        }

        match s.iface.poll_write(s.sockets, Instant::now()) {
            Ok(_) => debug!("tun.iface.poll_write successfully"),
            Err(e) => {
                debug!("poll_read error: {}", e);
            }
        };

        let mut lower = s.iface.device_mut().lower();
        loop {
            debug!("lower.tx.dequeue_many");
            let ip_buf = lower.tx.dequeue_many(1024);
            if ip_buf.is_empty() {
                break;
            }
            let size = ready!(Pin::new(&mut s.tun).poll_write(cx, ip_buf)).unwrap();
            assert_eq!(size, ip_buf.len())
        }

        Poll::Ready(Ok(()))
    }
}
