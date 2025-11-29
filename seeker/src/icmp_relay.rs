//! ICMP relay module for transparent proxy.
//!
//! This module handles ICMP Echo Request forwarding:
//! 1. Receives ICMP Echo Requests from tun_nat via channel
//! 2. Resolves fake IP -> domain -> real IP
//! 3. Sends actual ICMP ping to real IP via raw socket
//! 4. The reply is delivered directly by the kernel to the original ping process
//!
//! Note: Replies come from the real IP, not the fake IP.

use crate::dns_client::DnsClient;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddrV4;
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tun_nat::IcmpEchoRequest;

/// ICMP Relay handles the actual ping forwarding.
pub struct IcmpRelay {
    handle: JoinHandle<()>,
}

impl IcmpRelay {
    /// Start the ICMP relay.
    ///
    /// # Arguments
    /// * `request_rx` - Channel to receive ICMP Echo Requests from tun_nat
    /// * `dns_client` - DNS client for resolving domains
    pub fn start(
        request_rx: crossbeam_channel::Receiver<IcmpEchoRequest>,
        dns_client: DnsClient,
    ) -> std::io::Result<Self> {
        // Create raw ICMP socket for sending
        let send_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        send_socket.set_nonblocking(false)?;
        let send_socket = Arc::new(send_socket);

        // Convert crossbeam receiver to tokio mpsc
        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn a thread to bridge crossbeam -> tokio
        std::thread::Builder::new()
            .name("icmp-bridge".to_string())
            .spawn(move || {
                while let Ok(request) = request_rx.recv() {
                    if tx.send(request).is_err() {
                        break;
                    }
                }
            })?;

        let handle = tokio::spawn(Self::relay_loop(rx, dns_client, send_socket));

        tracing::info!("ICMP relay started (async, direct reply mode)");

        Ok(Self { handle })
    }

    async fn relay_loop(
        mut request_rx: mpsc::UnboundedReceiver<IcmpEchoRequest>,
        dns_client: DnsClient,
        send_socket: Arc<Socket>,
    ) {
        while let Some(request) = request_rx.recv().await {
            let dns_client = dns_client.clone();
            let send_socket = send_socket.clone();

            // Handle each request concurrently
            tokio::spawn(async move {
                Self::handle_request(request, dns_client, send_socket).await;
            });
        }
    }

    async fn handle_request(
        request: IcmpEchoRequest,
        dns_client: DnsClient,
        send_socket: Arc<Socket>,
    ) {
        tracing::debug!(
            "ICMP relay: received request from {} to {} (ident={}, seq={})",
            request.src_ip,
            request.dst_ip,
            request.ident,
            request.seq_no
        );

        // Look up domain from fake IP
        let domain = match Store::global().get_host_by_ipv4(request.dst_ip) {
            Ok(Some(domain)) if !domain.is_empty() => domain,
            Ok(Some(_)) => {
                tracing::debug!("ICMP relay: empty domain for fake IP {}", request.dst_ip);
                return;
            }
            Ok(None) => {
                tracing::debug!("ICMP relay: no domain found for fake IP {}", request.dst_ip);
                return;
            }
            Err(e) => {
                tracing::debug!(
                    "ICMP relay: error looking up domain for fake IP {}: {:?}",
                    request.dst_ip,
                    e
                );
                return;
            }
        };

        // Resolve domain to real IP using async DNS lookup
        let real_ip = match dns_client.lookup(&domain).await {
            Ok(ip) => match ip {
                std::net::IpAddr::V4(v4) => v4,
                std::net::IpAddr::V6(_) => {
                    tracing::debug!("ICMP relay: domain {} resolved to IPv6, skipping", domain);
                    return;
                }
            },
            Err(e) => {
                tracing::warn!("ICMP relay: failed to resolve domain '{}': {:?}", domain, e);
                return;
            }
        };

        tracing::info!(
            "ICMP relay: {} -> {} (fake) -> {} -> {} (real)",
            request.src_ip,
            request.dst_ip,
            domain,
            real_ip
        );

        // Build ICMP packet with original ident and seq
        let icmp_packet = build_icmp_echo_request(request.ident, request.seq_no, &request.payload);
        let dest_addr = SocketAddrV4::new(real_ip, 0);

        // Send via blocking task since socket2 is sync
        let result = tokio::task::spawn_blocking(move || {
            send_socket.send_to(&icmp_packet, &dest_addr.into())
        })
        .await;

        match result {
            Ok(Ok(sent)) => {
                tracing::debug!(
                    "ICMP relay: sent {} bytes to {} (ident={}, seq={})",
                    sent,
                    real_ip,
                    request.ident,
                    request.seq_no
                );
            }
            Ok(Err(e)) => {
                tracing::error!("ICMP relay: failed to send to {}: {}", real_ip, e);
            }
            Err(e) => {
                tracing::error!("ICMP relay: spawn_blocking failed: {}", e);
            }
        }
    }
}

impl Drop for IcmpRelay {
    fn drop(&mut self) {
        self.handle.abort();
        tracing::info!("ICMP relay stopped");
    }
}

/// Build an ICMP Echo Request packet (without IP header - kernel adds it)
fn build_icmp_echo_request(ident: u16, seq_no: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut packet = vec![0u8; len];

    packet[0] = 8; // Type = Echo Request
    packet[1] = 0; // Code
    packet[4] = ((ident >> 8) & 0xff) as u8;
    packet[5] = (ident & 0xff) as u8;
    packet[6] = ((seq_no >> 8) & 0xff) as u8;
    packet[7] = (seq_no & 0xff) as u8;

    if !payload.is_empty() {
        packet[8..].copy_from_slice(payload);
    }

    // Calculate checksum
    let checksum = calc_checksum(&packet);
    packet[2] = ((checksum >> 8) & 0xff) as u8;
    packet[3] = (checksum & 0xff) as u8;

    packet
}

fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        i += 2;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}
