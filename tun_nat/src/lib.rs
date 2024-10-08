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
use std::thread::{self, JoinHandle};
use std::time::SystemTime;
use sysconfig::setup_ip;

const BEGIN_PORT: u16 = 50000;
const END_PORT: u16 = 60000;
const EXPIRE_SECONDS: u64 = 24 * 60 * 60;

macro_rules! route_packet {
    ($packet_ty: tt, $ipv4_packet: expr, $session_manager: expr, $relay_addr: expr, $relay_port: expr) => {{
        let src_addr = $ipv4_packet.src_addr().into();
        let dest_addr = $ipv4_packet.dst_addr().into();
        let mut packet = $packet_ty::new_checked($ipv4_packet.payload_mut()).unwrap();
        let src_port = packet.src_port();
        let dest_port = packet.dst_port();

        if let Some((new_src_addr, new_src_port, new_dst_addr, new_dest_port)) =
            if src_addr == $relay_addr && src_port == $relay_port {
                let session_manager = $session_manager.read();
                session_manager.get_by_port(dest_port).map(|assoc| {
                    (
                        assoc.dest_addr.into(),
                        assoc.dest_port,
                        assoc.src_addr.into(),
                        assoc.src_port,
                    )
                })
            } else {
                let mut session_manager = $session_manager.write();
                let port =
                    session_manager.get_or_create_session(src_addr, src_port, dest_addr, dest_port);
                session_manager.update_activity_for_port(port);
                Some((dest_addr.into(), port, $relay_addr.into(), $relay_port))
            }
        {
            packet.set_src_port(new_src_port);
            packet.set_dst_port(new_dest_port);
            packet.fill_checksum(
                &IpAddress::Ipv4(new_src_addr),
                &IpAddress::Ipv4(new_dst_addr),
            );
            $ipv4_packet.set_src_addr(new_src_addr);
            $ipv4_packet.set_dst_addr(new_dst_addr);

            $ipv4_packet.fill_checksum();
            Some($ipv4_packet)
        } else {
            None
        }
    }};
}

pub fn run_nat(
    tun_name: &str,
    tun_ip: Ipv4Addr,
    tun_cidr: Ipv4Cidr,
    relay_port: u16,
    addition_cidrs: &[Ipv4Cidr],
) -> Result<(SessionManager, JoinHandle<()>)> {
    let mut tun = TunSocket::new(tun_name)?;
    let tun_name = tun.name()?;
    if cfg!(target_os = "macos") {
        setup_ip(
            &tun_name,
            tun_ip.to_string().as_str(),
            tun_cidr.to_string().as_str(),
            addition_cidrs.iter().map(|cidr| cidr.to_string()).collect(),
        );
    } else {
        setup_ip(
            &tun_name,
            tun_ip.to_string().as_str(),
            tun_cidr.to_string().as_str(),
            addition_cidrs.iter().map(|cidr| cidr.to_string()).collect(),
        );
    }

    let relay_addr = tun_ip;

    let session_manager = Arc::new(RwLock::new(InnerSessionManager::new(BEGIN_PORT, END_PORT)));
    let sesion_mamager_clone = session_manager.clone();
    let handle = thread::spawn(move || {
        let mut buf = vec![0; 2000];

        loop {
            let size = tun.read(&mut buf).unwrap();
            if size == 0 {
                eprintln!("tun read return 0, exit now");
                break;
            }
            let mut ipv4_packet = match Ipv4Packet::new_checked(&mut buf[..size]) {
                Err(e) => {
                    eprint!("tun_nat: new packet error: {:?}", e);
                    continue;
                }
                Ok(p) => p,
            };

            // convert relay_addr to bytes
            let relay_addr_bytes = relay_addr.octets();
            let dst_addr = ipv4_packet.dst_addr();
            if dst_addr.as_bytes() == relay_addr_bytes || dst_addr.is_broadcast() {
                tracing::info!("tun_nat: drop packet to relay_addr or broadcast");
                continue;
            }

            if let Some(packet) = match ipv4_packet.protocol() {
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
                _ => continue,
            } {
                let ret = tun.write(packet.as_ref());
                if let Err(err) = ret {
                    eprintln!("tun_nat: write packet error: {:?}", err);
                }
            }
        }
    });
    Ok((
        SessionManager {
            inner: sesion_mamager_clone,
        },
        handle,
    ))
}

pub struct Association {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dest_addr: Ipv4Addr,
    pub dest_port: u16,
    last_activity_ts: u64,
    recycling: bool,
}

#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<RwLock<InnerSessionManager>>,
}

impl SessionManager {
    pub fn get_by_port(&self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let inner = self.inner.read();
        inner.map.get(&port).map(|assoc| {
            (
                SocketAddr::new(assoc.src_addr.into(), assoc.src_port),
                SocketAddr::new(assoc.dest_addr.into(), assoc.dest_port),
            )
        })
    }

    pub fn update_activity_for_port(&self, port: u16) -> bool {
        self.inner.write().update_activity_for_port(port)
    }

    pub fn recycle_port(&self, port: u16) {
        self.inner.write().recycle_port(port);
    }
}

struct InnerSessionManager {
    map: HashMap<u16, Association>,
    reverse_map: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), u16>,
    begin_port: u16,
    next_index: u16,
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
            next_index: 0,
            begin_port,
        }
    }

    fn fetch_next_available_port(&mut self) -> u16 {
        let mut looped = false;
        let index = loop {
            if let Some(i) = self
                .available_ports
                .iter()
                .skip(self.next_index as usize)
                .position(|p| *p)
            {
                break i;
            } else if looped {
                panic!("no available port");
            } else {
                self.next_index = 0;
                looped = true;
            }
        };
        let real_index = self.next_index + index as u16;
        self.available_ports.set(real_index as usize, false);
        self.next_index = real_index + 1;
        real_index + self.begin_port
    }

    pub fn get_by_port(&self, port: u16) -> Option<&Association> {
        self.map.get(&port)
    }

    pub fn update_activity_for_port(&mut self, port: u16) -> bool {
        if let Some(assoc) = self.map.get_mut(&port) {
            // if `recycling` is true, the port is marked recycle. We shouldn't update activity ts.
            if !assoc.recycling {
                assoc.last_activity_ts = now();
                tracing::debug!(
                    "update port: {:?}, addr: {:?}, last_activity_ts: {}",
                    port,
                    (
                        assoc.src_addr,
                        assoc.src_port,
                        assoc.dest_addr,
                        assoc.dest_port,
                    ),
                    assoc.last_activity_ts
                );
                return true;
            }
        } else {
            eprintln!("update_activity_or_port: port {} not exists", port);
        }
        self.clear_expired();
        false
    }

    pub fn recycle_port(&mut self, port: u16) {
        if let Some(assoc) = self.map.get_mut(&port) {
            // we have 30 seconds to clean the connection.
            assoc.last_activity_ts = now() - EXPIRE_SECONDS + 30;
            assoc.recycling = true;
            tracing::debug!(
                "recycle port: {:?}, addr: {:?}, last_activity_ts: {}",
                port,
                (
                    assoc.src_addr,
                    assoc.src_port,
                    assoc.dest_addr,
                    assoc.dest_port,
                ),
                assoc.last_activity_ts
            );
        } else {
            tracing::warn!("recycle_port: port {} not exists", port);
        }
        self.clear_expired();
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
                recycling: false,
            },
        );
        self.reverse_map
            .insert((src_addr, src_port, dest_addr, dest_port), port);

        tracing::debug!(
            "insert port: {:?}, addr: {:?}",
            port,
            (src_addr, src_port, dest_addr, dest_port,)
        );
        self.clear_expired();
        port
    }

    fn clear_expired(&mut self) {
        let now = now();
        let map = &mut self.map;
        let reverse_map = &mut self.reverse_map;
        let available_ports = &mut self.available_ports;
        let begin_port = self.begin_port;
        map.retain(|port, assoc| {
            // when sleeping on Mac m1, subtract with overflow happens.
            let retain = now.wrapping_sub(assoc.last_activity_ts) < EXPIRE_SECONDS;
            if !retain {
                tracing::debug!(
                    "remove port: {:?}, addr: {:?}, last_activity_ts: {}",
                    port,
                    (
                        assoc.src_addr,
                        assoc.src_port,
                        assoc.dest_addr,
                        assoc.dest_port,
                    ),
                    assoc.last_activity_ts
                );
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
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
