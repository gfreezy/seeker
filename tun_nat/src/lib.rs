pub mod tun_device;

use crate::tun_device::TunDevice;
use bitvec::vec::BitVec;
use object_pool::{Pool, ReusableOwned};
use parking_lot::RwLock;
use route_manager::{Route, RouteManager};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Cidr, Ipv4Packet, TcpPacket, UdpPacket};
use std::collections::HashMap;
use std::io::Result;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

const BEGIN_PORT: u16 = 50000;
const END_PORT: u16 = 60000;
const EXPIRE_SECONDS: u64 = 24 * 60 * 60;

pub struct NatJoinHandle {
    handle: Option<JoinHandle<()>>,
    should_quit: Arc<AtomicBool>,
    tun: TunDevice,
}

impl NatJoinHandle {
    pub fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| h.is_finished())
            .unwrap_or(false)
    }
}

impl Drop for NatJoinHandle {
    fn drop(&mut self) {
        self.should_quit.store(true, Ordering::Relaxed);
        self.tun.trigger_interrupt().expect("trigger interrupt");
        if let Some(handle) = self.handle.take() {
            handle.join().expect("quit nat join handle");
        }
        tracing::info!("nat join handle dropped");
    }
}

macro_rules! route_packet {
    ($packet_ty: tt, $ipv4_packet: expr, $session_manager: expr, $relay_addr: expr, $relay_port: expr) => {{
        let src_addr = $ipv4_packet.src_addr().into();
        let dest_addr = $ipv4_packet.dst_addr().into();
        let mut packet =
            $packet_ty::new_checked($ipv4_packet.payload_mut()).expect("invalid packet");
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
        }
    }};
}

pub fn run_nat(
    tun_name: &str,
    tun_ip: Ipv4Addr,
    tun_cidr: Ipv4Cidr,
    relay_port: u16,
    addition_cidrs: &[Ipv4Cidr],
    queue_number: usize,
    threads_per_queue: usize,
) -> Result<(SessionManager, NatJoinHandle)> {
    const BUF_SIZE: usize = 2000;

    // Create TUN device with IPv4 configuration using tun-rs
    let netmask = tun_cidr.prefix_len();
    let tun = TunDevice::new_with_ipv4(tun_name, tun_ip, netmask, None)?;

    // Enable the device
    tun.set_enabled(true)?;

    // Handle additional CIDRs routing using route_manager
    if !addition_cidrs.is_empty() {
        let mut route_manager = RouteManager::new()
            .map_err(|e| std::io::Error::other(format!("Failed to create route manager: {e}")))?;

        let device_name = tun.name()?;

        for additional_cidr in addition_cidrs {
            // Convert Ipv4Cidr to IpAddr for route_manager
            // Get the network address from CIDR
            let network_addr = IpAddr::V4(additional_cidr.address());
            let gateway_addr = IpAddr::V4(tun_ip);

            let route = Route::new(network_addr, additional_cidr.prefix_len())
                .with_if_name(device_name.clone())
                .with_gateway(gateway_addr);

            if let Err(e) = route_manager.add(&route) {
                tracing::warn!("Failed to add route for CIDR {}: {}", additional_cidr, e);
            } else {
                tracing::info!(
                    "Added route for CIDR {} via {} on {}",
                    additional_cidr,
                    tun_ip,
                    device_name
                );
            }
        }
    }

    let relay_addr = tun_ip;

    let session_manager = Arc::new(RwLock::new(InnerSessionManager::new(BEGIN_PORT, END_PORT)));
    let session_manager_clone = session_manager.clone();

    // Create atomic bool to control shutdown
    let should_quit = Arc::new(AtomicBool::new(false));
    let should_quit_clone = should_quit.clone();

    // 创建内存池
    let pool = Arc::new(Pool::new(100, || vec![0u8; BUF_SIZE]));

    // 创建通道用于发送和接收数据包
    let (tx, rx) = crossbeam_channel::unbounded();
    let (processed_tx, processed_rx) = crossbeam_channel::unbounded();

    let queue_num = if cfg!(target_os = "linux") {
        queue_number.max(1)
    } else {
        1
    };

    let mut tun_queues = (0..(queue_num - 1))
        .map(|_| tun.new_queue())
        .collect::<Result<Vec<_>>>()?;
    tun_queues.push(tun.clone());
    // 创建处理线程
    let num_workers = queue_num * threads_per_queue;
    let workers: Vec<_> = (0..num_workers)
        .map(|i| {
            let rx = rx.clone();
            let processed_tx = processed_tx.clone();
            let sm = session_manager.clone();
            let should_quit = should_quit_clone.clone();
            thread::Builder::new()
                .name(format!("tun-nat-worker-{i}"))
                .spawn(move || {
                    // println!("Start tun-nat-worker-{i} thread.");
                    process_packets(rx, processed_tx, sm, relay_addr, relay_port, should_quit);
                    // println!("Exit tun-nat-worker-{i} thread");
                })
                .expect("Failed to spawn worker thread")
        })
        .collect();

    // 从 tun 读取数据
    let mut read_handles = Vec::with_capacity(queue_num);
    let mut write_handles = Vec::with_capacity(queue_num);

    for (i, tun_queue) in tun_queues.iter().enumerate() {
        let pool_clone = pool.clone();
        let tx_clone = tx.clone();
        let mut tun_clone = tun_queue.clone();
        let should_quit_read = should_quit_clone.clone();

        // Read thread for each queue
        let read_handle = thread::Builder::new()
            .name(format!("tun-nat-read-{i}"))
            .spawn(move || {
                // println!("Start tun-nat-read-{i} thread.");
                loop {
                    if should_quit_read.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut buf = pool_clone.pull_owned(|| vec![0; BUF_SIZE]);
                    // 从 pool 取出的 buf 不确定是多少，需要重新设置长度。因为 pool 里面的 buf 固定是 2000，所以这里 unsafe 设置长度是 safe 的。
                    unsafe {
                        buf.set_len(BUF_SIZE);
                    }
                    let size = match tun_clone.read(&mut buf) {
                        Ok(0) => {
                            eprintln!("tun read return 0, exit now");
                            break;
                        }
                        Ok(size) => size,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(e) => {
                            eprintln!("tun read error: {e:?}");
                            continue;
                        }
                    };

                    // 从 tun 读取到的 buf 长度是确定的，所以这里 unsafe 设置长度是 safe 的。
                    unsafe {
                        buf.set_len(size);
                    }
                    if let Err(e) = tx_clone.send(buf) {
                        eprintln!("Failed to send packet to worker: {e:?}");
                    }
                }

                drop(tx_clone); // 关闭发送端，通知所有工作线程退出

                // println!("Exit tun-nat-read-{i} thread.");
            })
            .expect("Failed to spawn read thread");

        read_handles.push(read_handle);

        // Write thread for each queue
        let processed_rx_clone = processed_rx.clone();
        let mut tun_clone = tun_queue.clone();
        let should_quit_write = should_quit_clone.clone();

        let write_handle = thread::Builder::new()
            .name(format!("tun-nat-write-{i}"))
            .spawn(move || {
                // println!("Start tun-nat-write-{i} thread.");
                loop {
                    if should_quit_write.load(Ordering::Relaxed) {
                        break;
                    }
                    match processed_rx_clone.recv() {
                        Ok(processed_buf) => {
                            let ret = tun_clone.write(&processed_buf);
                            if let Err(err) = ret {
                                if err.kind() != std::io::ErrorKind::Interrupted {
                                    eprintln!("tun_nat: write packet error: {err:?}");
                                }
                            }
                        }
                        Err(_) => {
                            // 通道已关闭，退出循环
                            break;
                        }
                    }
                }
                // println!("Exit tun-nat-write-{i} thread.");
            })
            .expect("Failed to spawn write thread");

        write_handles.push(write_handle);
    }

    // Main thread to join all worker, read, and write threads
    let handle = thread::Builder::new()
        .name("tun-nat-main".to_string())
        .spawn(move || {
            for worker in workers {
                worker.join().expect("Failed to join worker thread");
            }

            for read_handle in read_handles {
                read_handle.join().expect("Failed to join read thread");
            }

            for write_handle in write_handles {
                write_handle.join().expect("Failed to join write thread");
            }

            // println!("All tun-nat threads have exited.");
        })
        .expect("Failed to spawn main thread");

    Ok((
        SessionManager {
            inner: session_manager_clone,
        },
        NatJoinHandle {
            handle: Some(handle),
            should_quit,
            tun,
        },
    ))
}

fn process_packets(
    rx: crossbeam_channel::Receiver<ReusableOwned<Vec<u8>>>,
    processed_tx: crossbeam_channel::Sender<ReusableOwned<Vec<u8>>>,
    session_manager: Arc<RwLock<InnerSessionManager>>,
    relay_addr: Ipv4Addr,
    relay_port: u16,
    should_quit: Arc<AtomicBool>,
) {
    while !should_quit.load(Ordering::Relaxed) {
        let mut buf = match rx.recv() {
            Ok(buf) => buf,
            Err(_) => break,
        };
        let Ok(mut ipv4_packet) = Ipv4Packet::new_checked(&mut *buf) else {
            tracing::error!("tun_nat: invalid ipv4 packet");
            continue;
        };

        let relay_addr_bytes = relay_addr.octets();
        let dst_addr = ipv4_packet.dst_addr();
        if dst_addr.octets().as_slice() == relay_addr_bytes.as_slice() || dst_addr.is_broadcast() {
            tracing::info!("tun_nat: drop packet to relay_addr or broadcast");
            continue;
        }

        match ipv4_packet.next_header() {
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
            _ => {
                continue;
            }
        }
        if let Err(e) = processed_tx.send(buf) {
            eprintln!("Failed to send processed packet back: {e:?}");
        }
    }
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
            eprintln!("update_activity_or_port: port {port} not exists");
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
