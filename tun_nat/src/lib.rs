mod tun_socket;

pub use crate::tun_socket::TunSocket;
use bitvec::vec::BitVec;
use smoltcp::wire::{IpProtocol, Ipv4Packet, UdpPacket};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, SystemTime};
use sysconfig::setup_ip;

const BEGIN_PORT: u16 = 50000;
const END_PORT: u16 = 60000;
const EXPIRE_SECONDS: u64 = 10 * 60 * 1000;

pub fn run() {
    let relay_port = 1300;
    let relay_addr: Ipv4Addr = "11.0.0.1".parse().unwrap();

    let mut tun = TunSocket::new("utun4").unwrap();
    let tun_name = tun.name().unwrap();
    setup_ip(&tun_name, "11.0.0.1", "11.0.0.0/16");

    let mut session_manager = SessionManager::new(BEGIN_PORT, END_PORT);
    loop {
        let mut buf = vec![0; 1500];
        let size = tun.read(&mut buf).unwrap();
        println!("recv {} bytes", size);
        let mut ipv4_packet = Ipv4Packet::new_checked(&mut buf[..size]).unwrap();
        let src_addr = ipv4_packet.src_addr().into();
        let dest_addr = ipv4_packet.dst_addr().into();

        match ipv4_packet.protocol() {
            IpProtocol::Udp => {
                let mut udp_packet = UdpPacket::new_checked(ipv4_packet.payload_mut()).unwrap();
                let src_port = udp_packet.src_port();
                let dest_port = udp_packet.dst_port();

                // recv from relay
                if src_addr == relay_addr && src_port == relay_port {
                    let assoc = session_manager.get_by_port(dest_port);
                    udp_packet.set_src_port(assoc.dest_port);
                    udp_packet.set_dst_port(assoc.src_port);
                    ipv4_packet.set_src_addr(assoc.dest_addr.into());
                    ipv4_packet.set_dst_addr(assoc.src_addr.into());
                } else {
                    let port =
                        session_manager.new_session(src_addr, src_port, dest_addr, dest_port);
                    udp_packet.set_src_port(port);
                    udp_packet.set_dst_port(relay_port);
                    ipv4_packet.set_src_addr(dest_addr.into());
                    ipv4_packet.set_dst_addr(relay_addr.into());
                }
                ipv4_packet.fill_checksum();
            }
            _ => {}
        }
        tun.write(ipv4_packet.as_ref()).unwrap();
    }
}

struct Association {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dest_addr: Ipv4Addr,
    pub dest_port: u16,
    last_activity_ts: u64,
}

struct SessionManager {
    map: HashMap<u16, Association>,
    reverse_map: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), u16>,
    begin_port: u16,
    available_ports: BitVec,
}

impl SessionManager {
    pub fn new(begin_port: u16, end_port: u16) -> Self {
        let range = (end_port - begin_port) as usize;
        let mut ports = BitVec::with_capacity(range);
        ports.resize(range, true);

        SessionManager {
            map: HashMap::new(),
            reverse_map: HashMap::new(),
            available_ports: ports,
            begin_port,
        }
    }

    fn fetch_next_available_port(&mut self) -> u16 {
        let index = self.available_ports.iter().position(|p| *p).unwrap();
        self.available_ports.set(index, false);
        index as u16 + self.begin_port
    }

    pub fn get_by_port(&self, port: u16) -> &Association {
        self.map.get(&port).unwrap()
    }

    pub fn update_activity_for_port(&mut self, port: u16) {
        let assoc = self.map.get_mut(&port).unwrap();
        assoc.last_activity_ts = now();
    }

    pub fn new_session(
        &mut self,
        src_addr: Ipv4Addr,
        src_port: u16,
        dest_addr: Ipv4Addr,
        dest_port: u16,
    ) -> u16 {
        if let Some(port) = self
            .reverse_map
            .get(&(src_addr, src_port, dest_addr, dest_port))
        {
            return *port;
        }

        let port = self.fetch_next_available_port();

        let now = now();
        self.map.insert(
            port,
            Association {
                src_addr,
                src_port,
                dest_addr,
                dest_port,
                last_activity_ts: now,
            },
        );
        self.reverse_map
            .insert((src_addr, src_port, dest_addr, dest_port), port);

        let map = &mut self.map;
        let reverse_map = &mut self.reverse_map;
        let available_ports = &mut self.available_ports;
        let begin_port = self.begin_port;
        map.retain(|port, assoc| {
            let retain = now - assoc.last_activity_ts < EXPIRE_SECONDS;
            if !retain {
                reverse_map.remove(&(
                    assoc.src_addr,
                    assoc.src_port,
                    assoc.dest_addr,
                    assoc.dest_port,
                ));
                let idx = *port - begin_port;
                available_ports.set(idx as usize, true);
            }
            retain
        });
        port
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
