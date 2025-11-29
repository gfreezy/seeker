//! ICMP packet types for external handling.
//!
//! This module provides types for passing ICMP packets between tun_nat and external handlers.
//! The actual ICMP processing (DNS resolution, sending pings) is done outside tun_nat.

use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet};
use std::net::Ipv4Addr;

/// An ICMP Echo Request extracted from TUN for external processing.
#[derive(Debug, Clone)]
pub struct IcmpEchoRequest {
    /// Source IP (the client that sent the ping)
    pub src_ip: Ipv4Addr,
    /// Destination IP (the fake IP being pinged)
    pub dst_ip: Ipv4Addr,
    /// ICMP identifier
    pub ident: u16,
    /// ICMP sequence number
    pub seq_no: u16,
    /// ICMP payload data
    pub payload: Vec<u8>,
    /// Original TTL from IP header
    pub ttl: u8,
}

/// Try to parse an ICMP Echo Request from a raw IP packet.
pub fn parse_icmp_echo_request(packet_data: &[u8]) -> Option<IcmpEchoRequest> {
    let ipv4_packet = Ipv4Packet::new_checked(packet_data).ok()?;

    if ipv4_packet.next_header() != IpProtocol::Icmp {
        return None;
    }

    let icmp_packet = Icmpv4Packet::new_checked(ipv4_packet.payload()).ok()?;

    if icmp_packet.msg_type() != Icmpv4Message::EchoRequest {
        return None;
    }

    let payload = icmp_packet.data().to_vec();

    Some(IcmpEchoRequest {
        src_ip: ipv4_packet.src_addr(),
        dst_ip: ipv4_packet.dst_addr(),
        ident: icmp_packet.echo_ident(),
        seq_no: icmp_packet.echo_seq_no(),
        payload,
        ttl: ipv4_packet.hop_limit(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_icmp_echo_request() {
        // Build a minimal ICMP Echo Request packet
        let mut packet = vec![0u8; 28]; // 20 IP + 8 ICMP

        // IPv4 header
        packet[0] = 0x45;
        packet[2] = 0x00;
        packet[3] = 0x1c; // total length = 28
        packet[8] = 64; // TTL
        packet[9] = 0x01; // ICMP
                          // src: 192.168.1.100
        packet[12..16].copy_from_slice(&[192, 168, 1, 100]);
        // dst: 11.0.0.10
        packet[16..20].copy_from_slice(&[11, 0, 0, 10]);

        // ICMP Echo Request
        packet[20] = 0x08; // Type = Echo Request
        packet[21] = 0x00; // Code
        packet[24] = 0x04;
        packet[25] = 0xd2; // ident = 1234
        packet[26] = 0x00;
        packet[27] = 0x01; // seq = 1

        let request = parse_icmp_echo_request(&packet).unwrap();
        assert_eq!(request.src_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(request.dst_ip, Ipv4Addr::new(11, 0, 0, 10));
        assert_eq!(request.ident, 1234);
        assert_eq!(request.seq_no, 1);
        assert_eq!(request.ttl, 64);
    }
}
