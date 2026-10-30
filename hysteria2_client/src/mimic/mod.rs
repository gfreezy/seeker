//! Userspace Mimic-compatible FakeTCP transport. No eBPF programs, kernel
//! modules or kernel TCP sockets are used by this transport.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod network;
mod wire;

use config::MimicConfig;
use futures_util::task::AtomicWaker;
use parking_lot::Mutex;
use quinn::{AsyncUdpSocket, UdpPoller};
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{self, Instant};
use wire::{ACK, FIN, PSH, RST, SYN, Segment, WINDOW, WINDOW_SCALE};

#[derive(Default)]
struct Shared {
    writable: AtomicWaker,
    failure: Mutex<Option<String>>,
}

/// Presents a datagram socket to Quinn while sending Mimic-compatible IP/TCP
/// packets through a dedicated TUN interface.
pub struct MimicSocket {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    shared: Arc<Shared>,
    worker: tokio::task::JoinHandle<()>,
    local: SocketAddr,
    remote: SocketAddr,
    max_payload: usize,
}

impl std::fmt::Debug for MimicSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MimicSocket")
            .field("local", &self.local)
            .field("remote", &self.remote)
            .finish()
    }
}

impl MimicSocket {
    pub async fn connect(
        config: MimicConfig,
        remote: SocketAddr,
        obfs_password: Option<&str>,
    ) -> io::Result<Self> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let SocketAddr::V4(remote_v4) = remote else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "userspace Mimic currently requires an IPv4 server address",
            ));
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "userspace Mimic requires Linux or macOS",
        ));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let setup_config = config.clone();
            let network = tokio::task::spawn_blocking(move || {
                network::Network::open(&setup_config, remote_v4)
            })
            .await
            .map_err(io::Error::other)??;
            let local = wire::address(network.local, rand::rng().random_range(32768..61000));
            let mut connection = Connection::new(local, remote_v4, config.clone());
            let mut buffer = vec![0; 65535];
            let mut established = false;
            for _ in 0..4 {
                network
                    .device
                    .send(&connection.syn().encode(config.mtu))
                    .await?;
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match time::timeout_at(deadline, network.device.recv(&mut buffer)).await {
                        Ok(Ok(n)) => {
                            if let Some(segment) =
                                Segment::decode(&buffer[..n]).filter(|s| connection.matches(s))
                                && let Some(ack) = connection.handshake(&segment)?
                            {
                                network.device.send(&ack.encode(config.mtu)).await?;
                                established = true;
                                break;
                            }
                        }
                        Ok(Err(e)) => return Err(e),
                        Err(_) => break,
                    }
                }
                if established {
                    break;
                }
            }
            if !established {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Mimic handshake timed out; check peer Mimic, TCP firewall and forwarding/NAT",
                ));
            }
            let (outgoing, rx) = mpsc::channel(256);
            let (tx, incoming) = mpsc::channel(256);
            let shared = Arc::new(Shared::default());
            let worker_shared = shared.clone();
            let password = obfs_password.map(|s| s.as_bytes().to_vec());
            let max_payload = config.mtu as usize
                - 40
                - config.padding.max_len()
                - if password.is_some() { 8 } else { 0 };
            let worker = tokio::spawn(async move {
                let mut session = Session {
                    network,
                    connection,
                };
                let result = run(
                    &session.network,
                    &mut session.connection,
                    rx,
                    tx,
                    &worker_shared,
                    password.as_deref(),
                )
                .await;
                if let Err(error) = result {
                    tracing::warn!(%error, "Mimic transport stopped");
                    *worker_shared.failure.lock() = Some(error.to_string());
                }
                worker_shared.writable.wake();
            });
            Ok(Self {
                outgoing,
                incoming: Mutex::new(incoming),
                shared,
                worker,
                local: local.into(),
                remote,
                max_payload,
            })
        }
    }

    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    pub async fn close(&self) {
        self.worker.abort();
        while !self.worker.is_finished() {
            tokio::task::yield_now().await;
        }
    }

    fn error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            self.shared
                .failure
                .lock()
                .clone()
                .unwrap_or_else(|| "Mimic transport closed".into()),
        )
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Session {
    network: network::Network,
    connection: Connection,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for Session {
    fn drop(&mut self) {
        // Best effort: also release the peer's FakeTCP state on cancellation.
        let packet = self
            .connection
            .control(self.connection.seq, RST | ACK, vec![]);
        let _ = self
            .network
            .device
            .try_send(&packet.encode(self.connection.config.mtu));
    }
}

use rand::Rng;

impl Drop for MimicSocket {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

impl AsyncUdpSocket for MimicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(MimicPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.remote {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mimic transport is bound to one server",
            ));
        }
        if transmit.contents.len() > self.max_payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC datagram exceeds Mimic path MTU",
            ));
        }
        if transmit
            .segment_size
            .is_some_and(|n| n < transmit.contents.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mimic does not support UDP segmentation offload",
            ));
        }
        self.outgoing
            .try_send(transmit.contents.to_vec())
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                mpsc::error::TrySendError::Closed(_) => self.error(),
            })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.incoming.lock().poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                if packet.len() > bufs[0].len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Mimic receive buffer too small",
                    )));
                }
                bufs[0][..packet.len()].copy_from_slice(&packet);
                meta[0] = quinn::udp::RecvMeta {
                    addr: self.remote,
                    len: packet.len(),
                    stride: packet.len(),
                    ecn: None,
                    dst_ip: Some(self.local.ip()),
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(self.error())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn may_fragment(&self) -> bool {
        false
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[derive(Debug)]
struct MimicPoller(Arc<MimicSocket>);
impl UdpPoller for MimicPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.shared.writable.register(cx.waker());
        if self.0.outgoing.is_closed() {
            Poll::Ready(Err(self.0.error()))
        } else if self.0.outgoing.capacity() > 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

struct Connection {
    local: SocketAddrV4,
    remote: SocketAddrV4,
    config: MimicConfig,
    initial_seq: u32,
    seq: u32,
    ack: u32,
    peer_scale: u8,
    peer_window: u32,
    received: u32,
}

impl Connection {
    fn new(local: SocketAddrV4, remote: SocketAddrV4, config: MimicConfig) -> Self {
        let initial_seq: u32 = rand::random();
        Self {
            local,
            remote,
            config,
            initial_seq,
            seq: initial_seq.wrapping_add(1),
            ack: 0,
            peer_scale: 0,
            peer_window: 0,
            received: 0,
        }
    }
    fn matches(&self, s: &Segment) -> bool {
        s.src == self.remote && s.dst == self.local
    }
    fn control(&self, seq: u32, flags: u8, payload: Vec<u8>) -> Segment {
        Segment {
            src: self.local,
            dst: self.remote,
            seq,
            ack: self.ack,
            flags,
            window: if flags & SYN != 0 {
                65535
            } else {
                ((WINDOW - self.received.min(WINDOW)) >> WINDOW_SCALE) as u16
            },
            scale: WINDOW_SCALE,
            payload,
        }
    }
    fn syn(&self) -> Segment {
        self.control(self.initial_seq, SYN, vec![])
    }
    fn handshake(&mut self, s: &Segment) -> io::Result<Option<Segment>> {
        if s.flags & RST != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Mimic peer reset handshake",
            ));
        }
        if s.flags & (SYN | ACK) != SYN | ACK || s.ack != self.seq || !s.payload.is_empty() {
            return Ok(None);
        }
        self.ack = s.seq.wrapping_add(1);
        self.peer_scale = s.scale;
        self.peer_window = (s.window as u32) << self.peer_scale;
        Ok(Some(self.control(self.seq, ACK, vec![])))
    }
    fn data(&mut self, data: &[u8]) -> Segment {
        let payload = wire::mangle(data, &self.config.padding, self.seq, self.ack);
        let packet = self.control(
            self.seq,
            ACK | if data.len() < 2 { PSH } else { 0 },
            payload,
        );
        self.seq = self.seq.wrapping_add(packet.payload.len() as u32);
        self.peer_window = self.peer_window.saturating_sub(packet.payload.len() as u32);
        packet
    }
    fn receive(&mut self, s: &Segment) -> io::Result<(Option<Vec<u8>>, Option<Segment>)> {
        if s.flags & (RST | FIN) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Mimic peer closed connection",
            ));
        }
        if s.flags & ACK == 0 {
            return Ok((None, None));
        }
        if s.flags & SYN != 0 {
            // The third handshake packet may have been lost. Re-send ACK
            // without advancing our established sequence number.
            return Ok((
                None,
                if s.seq.wrapping_add(1) == self.ack {
                    Some(self.control(self.seq, ACK, vec![]))
                } else {
                    None
                },
            ));
        }
        self.peer_window = (s.window as u32) << self.peer_scale;
        if s.payload.len() < 2 && s.seq == self.ack.wrapping_sub(1) {
            return Ok((None, Some(self.control(self.seq, ACK, vec![]))));
        }
        if s.flags & PSH == 0 && s.payload.len() < 2 {
            if s.payload.len() == 1 {
                self.ack = s.seq.wrapping_add(1);
                self.received = 0;
                return Ok((None, Some(self.control(self.seq, ACK, vec![]))));
            }
            return Ok((None, None));
        }
        // No stream reassembly and no data retransmission: QUIC handles both.
        self.ack = s.seq.wrapping_add(s.payload.len() as u32);
        let data = wire::restore(&s.payload, &self.config.padding, s.seq, s.ack);
        self.received = self.received.saturating_add(s.payload.len() as u32);
        let update = if self.received >= WINDOW / 4 {
            self.received = 0;
            Some(self.control(self.seq, ACK, vec![]))
        } else {
            None
        };
        Ok((data, update))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run(
    network: &network::Network,
    conn: &mut Connection,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    incoming: mpsc::Sender<Vec<u8>>,
    shared: &Shared,
    password: Option<&[u8]>,
) -> io::Result<()> {
    let mut buffer = vec![0; 65535];
    let mut pending: Option<Vec<u8>> = None;
    let mut timer = time::interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut last_received = Instant::now();
    let mut last_probe = Instant::now() - Duration::from_secs(1);
    loop {
        if let Some(data) = pending.as_ref() {
            let required = data.len() + conn.config.padding.max_len();
            if conn.peer_window as usize >= required {
                let packet = conn.data(&pending.take().unwrap());
                network.device.send(&packet.encode(conn.config.mtu)).await?;
            } else if last_probe.elapsed() >= Duration::from_millis(100) {
                let packet = conn.control(conn.seq, ACK, vec![0]);
                network.device.send(&packet.encode(conn.config.mtu)).await?;
                conn.seq = conn.seq.wrapping_add(1);
                last_probe = Instant::now();
            }
        }
        tokio::select! {
            n = network.device.recv(&mut buffer) => {
                if let Some(segment) = Segment::decode(&buffer[..n?]).filter(|s| conn.matches(s)) {
                    last_received = Instant::now();
                    let (data, response) = conn.receive(&segment)?;
                    if let Some(response) = response { network.device.send(&response.encode(conn.config.mtu)).await?; }
                    if let Some(data) = data {
                        let data = match password {
                            Some(password) => crate::salamander::decode(&data, password),
                            None => Some(data),
                        };
                        if let Some(data) = data {
                            // UDP semantics: a full receiver drops datagrams;
                            // it must not block TCP control packets or timers.
                            if let Err(mpsc::error::TrySendError::Closed(_)) = incoming.try_send(data) { return Ok(()); }
                        }
                    }
                }
            }
            data = outgoing.recv(), if pending.is_none() => {
                shared.writable.wake();
                let Some(data) = data else { return Ok(()); };
                pending = Some(match password {
                    Some(password) => crate::salamander::encode(&data, password),
                    None => data,
                });
            }
            _ = timer.tick() => {
                if last_received.elapsed() > Duration::from_secs(210) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Mimic peer stopped responding"));
                }
                if last_received.elapsed() > Duration::from_secs(180) && last_probe.elapsed() > Duration::from_secs(10) {
                    let packet = conn.control(conn.seq.wrapping_sub(1), ACK, vec![]);
                    network.device.send(&packet.encode(conn.config.mtu)).await?;
                    last_probe = Instant::now();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        Connection::new(
            "198.19.0.2:40000".parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            MimicConfig::default(),
        )
    }

    #[test]
    fn handshake_data_reordering_and_window_probes() {
        let mut c = connection();
        let mut peer = c.syn();
        std::mem::swap(&mut peer.src, &mut peer.dst);
        peer.flags = SYN | ACK;
        peer.seq = 1000;
        peer.ack = c.seq;
        assert!(c.handshake(&peer).unwrap().is_some());
        assert_eq!(c.ack, 1001);
        assert!(c.receive(&peer).unwrap().1.is_some());
        let first = c.data(b"first datagram");
        let second = c.data(b"second datagram");
        assert_eq!(
            second.seq,
            first.seq.wrapping_add(first.payload.len() as u32)
        );
        peer.flags = ACK;
        peer.seq = 1200;
        peer.payload = wire::mangle(b"later", &c.config.padding, peer.seq, peer.ack);
        assert_eq!(c.receive(&peer).unwrap().0.unwrap(), b"later");
        peer.seq = 1100;
        peer.payload = wire::mangle(b"earlier", &c.config.padding, peer.seq, peer.ack);
        assert_eq!(c.receive(&peer).unwrap().0.unwrap(), b"earlier");
        peer.payload = vec![0];
        let (_, response) = c.receive(&peer).unwrap();
        assert!(response.is_some());
        peer.flags = RST;
        assert_eq!(
            c.receive(&peer).unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }

    #[test]
    fn control_packets_and_receive_window_refresh() {
        let mut c = connection();
        let mut peer = c.syn();
        std::mem::swap(&mut peer.src, &mut peer.dst);
        peer.flags = SYN | ACK;
        peer.seq = 1000;
        peer.ack = c.seq;
        c.handshake(&peer).unwrap();

        peer.flags = ACK;
        peer.seq = c.ack.wrapping_sub(1);
        let (data, reply) = c.receive(&peer).unwrap();
        assert!(data.is_none());
        assert!(reply.is_some());

        c.received = WINDOW - 1;
        peer.seq = c.ack;
        peer.payload = vec![0];
        let (data, reply) = c.receive(&peer).unwrap();
        assert!(data.is_none());
        assert_eq!(reply.unwrap().window as u32, WINDOW >> WINDOW_SCALE);
        assert_eq!(c.received, 0);

        c.received = WINDOW / 4 - 3;
        peer.seq = c.ack;
        peer.payload = b"ping".to_vec();
        let (data, reply) = c.receive(&peer).unwrap();
        assert_eq!(data.unwrap(), b"ping");
        assert_eq!(reply.unwrap().ack, c.ack);
        assert_eq!(c.received, 0);
    }

    #[tokio::test]
    async fn rejects_ipv6_before_opening_a_tun() {
        let error =
            MimicSocket::connect(MimicConfig::default(), "[::1]:443".parse().unwrap(), None)
                .await
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn syn_ack_validation_and_sequence_wraparound() {
        let mut c = connection();
        c.seq = u32::MAX;
        let mut s = c.syn();
        std::mem::swap(&mut s.src, &mut s.dst);
        s.flags = SYN | ACK;
        s.seq = u32::MAX;
        s.ack = 10;
        assert!(c.handshake(&s).unwrap().is_none());
        s.ack = c.seq;
        assert!(c.handshake(&s).unwrap().is_some());
        assert_eq!(c.ack, 0);
        c.data(&[1, 2]);
        assert_eq!(c.seq, 1);
    }
}
