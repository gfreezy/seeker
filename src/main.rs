mod iface;
mod phy;

use crate::iface::ethernet::InterfaceBuilder;
use iface::ethernet::Interface;
use log::debug;
use phy::drop_privileges::drop_privileges;
use phy::TunSocket;
use smoltcp::phy::wait;
use smoltcp::socket::{
    SocketSet, TcpSocket, TcpSocketBuffer, UdpPacketMetadata, UdpSocket, UdpSocketBuffer,
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    Icmpv4Packet, IpAddress, IpCidr, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket,
};
use std::fmt::Write;
use std::os::unix::io::AsRawFd;
use std::process::Command;

fn main() {
    let mut device = TunSocket::new("utun4").expect("open tun");
    let tun_name = device.name();
    setup_ip(&tun_name, "10.0.0.1", "10.0.0.1");

    let fd = device.as_raw_fd();

    let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 64]);
    let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 128]);
    let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

    let tcp1_rx_buffer = TcpSocketBuffer::new(vec![0; 64]);
    let tcp1_tx_buffer = TcpSocketBuffer::new(vec![0; 128]);
    let tcp1_socket = TcpSocket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let ip_addrs = [IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24)];

    let mut iface = InterfaceBuilder::new(device).ip_addrs(ip_addrs).finalize();

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle = sockets.add(udp_socket);
    let tcp1_handle = sockets.add(tcp1_socket);

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // udp:6969: respond "hello"
        {
            let mut socket = sockets.get::<UdpSocket>(udp_handle);
            if !socket.is_open() {
                socket.bind(6969).unwrap()
            }

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

        // tcp:6969: respond "hello"
        {
            let mut socket = sockets.get::<TcpSocket>(tcp1_handle);
            if !socket.is_open() {
                socket.listen(6969).unwrap();
            }

            if socket.can_send() {
                debug!("tcp:6969 send greeting");
                write!(socket, "hello2\n").unwrap();
                debug!("tcp:6969 close");
                socket.close();
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
}
