mod iface;
mod phy;

use crate::iface::ethernet::InterfaceBuilder;
use log::debug;
use phy::drop_privileges::drop_privileges;
use phy::TunSocket;
use smoltcp::phy::wait;
use smoltcp::socket::Socket;
use smoltcp::socket::SocketSet;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use std::fmt::Write;
use std::os::unix::io::AsRawFd;
use std::process::Command;

fn main() {
    env_logger::init();
    let device = TunSocket::new("utun4").expect("open tun");
    let tun_name = device.name();
    setup_ip(&tun_name, "10.0.0.1", "10.0.0.100");

    let fd = device.as_raw_fd();

    let ip_addrs = [IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24)];

    let mut iface = InterfaceBuilder::new(device)
        .ip_addrs(ip_addrs)
        .any_ip(true)
        .finalize();

    let mut sockets = SocketSet::new(vec![]);

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        for mut socket in sockets.iter_mut() {
            match &mut *socket {
                Socket::Udp(ref mut socket) => {
                    let client = match socket.recv() {
                        Ok((data, endpoint)) => {
                            debug!(
                                "udp:6969 recv data: {:?} from {}",
                                std::str::from_utf8(data.as_ref()).unwrap(),
                                endpoint
                            );
                            Some(endpoint)
                        }
                        Err(_) => None,
                    };
                    if let Some(endpoint) = client {
                        let data = b"hello\n";
                        debug!(
                            "udp:6969 send data: {:?}",
                            std::str::from_utf8(data.as_ref()).unwrap()
                        );
                        socket.send_slice(data, endpoint).unwrap();
                    }
                }
                Socket::Tcp(ref mut socket) => {
                    if socket.can_send() {
                        debug!("tcp:6969 send greeting");
                        write!(socket, "hello2\n").unwrap();
                        debug!("tcp:6969 close");
                        socket.close();
                    }
                }
                _ => unreachable!(),
            }
        }

        wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
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
