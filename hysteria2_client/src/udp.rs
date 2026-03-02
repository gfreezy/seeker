use crate::client::Hy2Client;
use crate::protocol::{decode_udp_message, encode_udp_message, UdpMessage};
use bytes::BytesMut;
use std::io::{self, Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use tracing::{debug, error};

/// Maximum payload size per UDP datagram fragment.
/// QUIC datagrams have limited size; fragments allow larger UDP payloads.
const MAX_UDP_PAYLOAD: usize = 1200;

/// A UDP socket proxied through Hysteria 2 (QUIC datagrams)
pub struct Hy2UdpSocket {
    client: Arc<Hy2Client>,
    session_id: u32,
    next_packet_id: AtomicU16,
}

static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);

impl Hy2UdpSocket {
    /// Create a new UDP socket over the Hysteria 2 connection
    pub async fn new(client: Arc<Hy2Client>) -> io::Result<Self> {
        // Ensure connection is established
        let _ = client.get_connection().await?;

        if !client.udp_enabled() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "server does not support UDP",
            ));
        }

        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);

        debug!(session_id, "created Hysteria 2 UDP socket");

        Ok(Self {
            client,
            session_id,
            next_packet_id: AtomicU16::new(0),
        })
    }

    /// Send a UDP payload to the given address through the proxy
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let conn = self.client.get_connection().await?;
        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let target = config::Address::SocketAddress(addr);

        // Fragment if necessary
        let fragments: Vec<&[u8]> = if buf.len() <= MAX_UDP_PAYLOAD {
            vec![buf]
        } else {
            buf.chunks(MAX_UDP_PAYLOAD).collect()
        };

        let fragment_count = fragments.len() as u8;

        for (i, fragment) in fragments.iter().enumerate() {
            let msg = UdpMessage {
                session_id: self.session_id,
                packet_id,
                fragment_id: i as u8,
                fragment_count,
                addr: target.clone(),
                payload: fragment.to_vec(),
            };
            let mut frame = BytesMut::new();
            encode_udp_message(&msg, &mut frame);

            conn.send_datagram(frame.freeze()).map_err(|e| {
                error!("failed to send UDP datagram: {e}");
                Error::new(ErrorKind::ConnectionAborted, e.to_string())
            })?;
        }

        Ok(buf.len())
    }

    /// Receive a UDP payload from the proxy
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let conn = self.client.get_connection().await?;

        // Simple case: receive a single datagram (no fragment reassembly for now)
        // Full reassembly would require buffering fragments by packet_id
        loop {
            let datagram = conn.read_datagram().await.map_err(|e| {
                error!("failed to receive UDP datagram: {e}");
                Error::new(ErrorKind::ConnectionAborted, e.to_string())
            })?;

            let mut data = datagram.as_ref();
            let msg = decode_udp_message(&mut data)?;

            // Only accept messages for our session
            if msg.session_id != self.session_id {
                continue;
            }

            // For unfragmented messages (count=1), return directly
            if msg.fragment_count == 1 {
                let addr = match &msg.addr {
                    config::Address::SocketAddress(a) => *a,
                    config::Address::DomainNameAddress(host, port) => {
                        // For domain addresses, we can't easily return a SocketAddr
                        // Use 0.0.0.0 as placeholder — callers usually don't need the source
                        debug!(%host, %port, "received UDP from domain address");
                        SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            *port,
                        )
                    }
                };
                let copy_len = msg.payload.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&msg.payload[..copy_len]);
                return Ok((copy_len, addr));
            }

            // TODO: implement fragment reassembly for multi-fragment packets
            // For now, skip fragmented messages
            debug!(
                packet_id = msg.packet_id,
                fragment_id = msg.fragment_id,
                fragment_count = msg.fragment_count,
                "skipping fragmented UDP message"
            );
        }
    }
}
