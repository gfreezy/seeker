#![feature(async_await)]

mod phy;
mod iface;

use std::process::Command;
use phy::TunSocket;
use phy::drop_privileges::drop_privileges;
use futures::AsyncReadExt;
use futures::io::BufReader;
use smoltcp::wire::{Ipv4Packet, TcpPacket, IpProtocol, UdpPacket, Icmpv4Packet};


#[runtime::main]
async fn main() {
    let mut tun = TunSocket::new("utun4").expect("open tun");
    dbg!(tun.mtu());
    let tun_name = tun.name().expect("get tun name");
    setup_ip(&tun_name, "10.0.0.1", "10.0.0.1");

    drop_privileges().expect("drop privileges");

    let mut tun_buf_reader = BufReader::new(tun);
    let mut buf = vec![0; 1500];
    loop {
        let mut total_size = 0;
        loop {
            let size = tun_buf_reader.read(&mut buf[total_size..]).await.expect("read");
            total_size += size;

            let packet = match Ipv4Packet::new_checked(&buf[..total_size]) {
                Ok(p) => p,
                Err(smoltcp::Error::Truncated) => {
                    continue
                }
                Err(e) => {
                    dbg!(e);
                    panic!(e);
                }
            };

            match packet.protocol() {
                IpProtocol::Tcp => {
                    let p = TcpPacket::new_checked(packet.payload()).expect("parse tcp packet");
                    println!("{}", p);
                },
                IpProtocol::Udp => {
                    let p = UdpPacket::new_checked(packet.payload()).expect("parse udp packet");
                    println!("{}", p);
                },
                IpProtocol::Icmp => {
                    let p = Icmpv4Packet::new_checked(packet.payload()).expect("parse udp packet");
                    println!("{}", p);
                },
                _ => {
                    unreachable!();
                }
            }
            break;
        }
    }
}

fn setup_ip(tun_name: &str, ip: &str, dest_ip: &str) {
    let output = Command::new("ifconfig")
        .args(&[tun_name, ip, dest_ip])
        .output().expect("run ifconfig");
    if !output.status.success() {
        panic!("stdout: {}\nstderr: {}",
               std::str::from_utf8(&output.stdout).expect("utf8"),
               std::str::from_utf8(&output.stderr).expect("utf8"));
    }
}
