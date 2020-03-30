mod tun_socket;

use crate::tun_socket::TunSocket;
use bitvec::vec::BitVec;
use parking_lot::RwLock;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Cidr, Ipv4Packet, TcpPacket, UdpPacket};
use std::collections::HashMap;
use std::io::Result;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;
use sysconfig::setup_ip;

const BEGIN_PORT: u16 = 50000;
const END_PORT: u16 = 60000;
const EXPIRE_SECONDS: u64 = 1 * 60 * 1000;

macro_rules! route_packet {
    ($packet_ty: tt, $ipv4_packet: expr, $session_manager: expr, $relay_addr: expr, $relay_port: expr) => {{
        let src_addr = $ipv4_packet.src_addr().into();
        let dest_addr = $ipv4_packet.dst_addr().into();
        let mut packet = $packet_ty::new_checked($ipv4_packet.payload_mut()).unwrap();
        let src_port = packet.src_port();
        let dest_port = packet.dst_port();

        let (new_src_addr, new_src_port, new_dst_addr, new_dest_port) =
            if src_addr == $relay_addr && src_port == $relay_port {
                let session_manager = $session_manager.read();
                let assoc = session_manager.get_by_port(dest_port);
                (
                    assoc.dest_addr.into(),
                    assoc.dest_port,
                    assoc.src_addr.into(),
                    assoc.src_port,
                )
            } else {
                let mut session_manager = $session_manager.write();
                let port =
                    session_manager.get_or_create_session(src_addr, src_port, dest_addr, dest_port);
                session_manager.update_activity_for_port(port);
                (dest_addr.into(), port, $relay_addr.into(), $relay_port)
            };
        packet.set_src_port(new_src_port);
        packet.set_dst_port(new_dest_port);
        packet.fill_checksum(
            &IpAddress::Ipv4(new_src_addr),
            &IpAddress::Ipv4(new_dst_addr),
        );
        $ipv4_packet.set_src_addr(new_src_addr);
        $ipv4_packet.set_dst_addr(new_dst_addr);

        $ipv4_packet.fill_checksum();
        $ipv4_packet
    }};
}

pub fn run_nat(
    tun_name: &str,
    tun_ip: Ipv4Addr,
    tun_cidr: Ipv4Cidr,
    relay_port: u16,
) -> Result<SessionManager> {
    let mut tun = TunSocket::new(tun_name)?;
    let tun_name = tun.name()?;
    if cfg!(target_os = "macos") {
        setup_ip(
            &tun_name,
            tun_ip.to_string().as_str(),
            tun_cidr.to_string().as_str(),
        );
    } else {
        let new_ip =
            Ipv4Cidr::from_netmask(tun_ip.into(), tun_cidr.netmask()).expect("convert netmask");
        setup_ip(
            &tun_name,
            new_ip.to_string().as_str(),
            tun_cidr.to_string().as_str(),
        );
    }

    let relay_addr = tun_ip;

    let session_manager = Arc::new(RwLock::new(InnerSessionManager::new(BEGIN_PORT, END_PORT)));
    let sesion_mamager_clone = session_manager.clone();
    let _handle = thread::spawn(move || {
        let mut buf = vec![0; 2000];

        loop {
            let size = tun.read(&mut buf).unwrap();
            let mut ipv4_packet = match Ipv4Packet::new_checked(&mut buf[..size]) {
                Err(_) => continue,
                Ok(p) => p,
            };

            let packet = match ipv4_packet.protocol() {
                IpProtocol::Udp => route_packet!(
                    UdpPacket,
                    ipv4_packet,
                    session_manager,
                    relay_addr,
                    relay_port
                ),
                IpProtocol::Tcp => route_packet!(
                    TcpPacket,
                    ipv4_packet,
                    session_manager,
                    relay_addr,
                    relay_port
                ),
                _ => unreachable!(),
            };
            tun.write(packet.as_ref()).unwrap();
        }
    });
    Ok(SessionManager {
        inner: sesion_mamager_clone,
    })
}

pub struct Association {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dest_addr: Ipv4Addr,
    pub dest_port: u16,
    last_activity_ts: u64,
}

#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<RwLock<InnerSessionManager>>,
}

impl SessionManager {
    pub fn get_by_port(&self, port: u16) -> (SocketAddr, SocketAddr) {
        let inner = self.inner.read();
        let assoc = inner.map.get(&port).unwrap();
        (
            SocketAddr::new(assoc.src_addr.into(), assoc.src_port),
            SocketAddr::new(assoc.dest_addr.into(), assoc.dest_port),
        )
    }
}

struct InnerSessionManager {
    map: HashMap<u16, Association>,
    reverse_map: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), u16>,
    begin_port: u16,
    available_ports: BitVec,
}

impl InnerSessionManager {
    pub fn new(begin_port: u16, end_port: u16) -> Self {
        let range = (end_port - begin_port) as usize;
        let mut ports = BitVec::with_capacity(range);
        ports.resize(range, true);

        InnerSessionManager {
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

    pub fn get_or_create_session(
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
