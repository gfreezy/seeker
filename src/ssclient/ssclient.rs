use crate::iface;
use crate::iface::ethernet::{Interface, InterfaceBuilder};
use crate::phy::TunSocket;
use futures::{io, AsyncRead, AsyncWrite};
use mio::unix::EventedFd;
use mio::{Evented, PollOpt, Ready, Token};
use romio::raw::PollEvented;
use romio::raw::{AsyncReadReady, AsyncWriteReady};
use smoltcp::socket::{Socket, SocketSet};
use smoltcp::wire::{IpAddress, IpCidr};
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::process::Command;
use std::task::{Context, Poll};

struct SSClient {
    iface: PollEvented<iface::Iface>,
}

impl SSClient {
    pub fn new(tun_name: &str) -> Self {
        let device = TunSocket::new("utun4").expect("open tun");
        let tun_name = device.name();
        setup_ip(&tun_name, "10.0.0.1", "10.0.0.100");

        let fd = device.as_raw_fd();

        let ip_addrs = vec![IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24)];

        let iface = PollEvented::new(iface::Iface::new(
            InterfaceBuilder::new(device)
                .ip_addrs(ip_addrs)
                .any_ip(true)
                .finalize(),
        ));

        SSClient { iface }
    }
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

impl AsyncRead for SSClient {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.iface).poll_read(cx, buf)
    }
}

impl AsyncWrite for SSClient {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.iface).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.iface).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.iface).poll_close(cx)
    }
}

impl AsyncReadReady for SSClient {
    type Ok = mio::Ready;
    type Err = io::Error;

    fn poll_read_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Ok, Self::Err>> {
        Pin::new(&mut self.iface).poll_read_ready(cx)
    }
}

impl AsyncWriteReady for SSClient {
    type Ok = mio::Ready;
    type Err = io::Error;

    fn poll_write_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Ok, Self::Err>> {
        self.iface.poll_write_ready(cx)
    }
}
