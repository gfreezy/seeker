//! Mimic's on-wire format, independent of the host TCP stack.
use config::MimicPadding;
use rand::Rng;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket};
use std::net::{Ipv4Addr, SocketAddrV4};

pub const FIN: u8 = 1;
pub const SYN: u8 = 2;
pub const RST: u8 = 4;
pub const PSH: u8 = 8;
pub const ACK: u8 = 16;
pub const WINDOW_SCALE: u8 = 12;
pub const WINDOW: u32 = 0x0340_0000;

#[derive(Debug, Clone)]
pub struct Segment {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub scale: u8,
    pub payload: Vec<u8>,
}

impl Segment {
    pub fn encode(&self, mtu: u16) -> Vec<u8> {
        let syn = self.flags & SYN != 0;
        let header_len = if syn { 32 } else { 20 };
        let mut bytes = vec![0; 20 + header_len + self.payload.len()];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len((20 + header_len + self.payload.len()) as u16);
            ip.set_ident(rand::random());
            ip.set_dont_frag(true);
            ip.set_hop_limit(64);
            ip.set_next_header(IpProtocol::Tcp);
            ip.set_src_addr(*self.src.ip());
            ip.set_dst_addr(*self.dst.ip());
            ip.fill_checksum();
        }
        let tcp = &mut bytes[20..];
        tcp[0..2].copy_from_slice(&self.src.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&self.dst.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&self.seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&self.ack.to_be_bytes());
        tcp[12] = (header_len as u8 / 4) << 4;
        tcp[13] = self.flags;
        tcp[14..16].copy_from_slice(&self.window.to_be_bytes());
        if syn {
            let mss = mtu.saturating_sub(40);
            tcp[20..32].copy_from_slice(&[
                2,
                4,
                (mss >> 8) as u8,
                mss as u8,
                1,
                3,
                3,
                self.scale,
                1,
                1,
                4,
                2,
            ]);
        }
        tcp[header_len..].copy_from_slice(&self.payload);
        TcpPacket::new_unchecked(tcp).fill_checksum(
            &IpAddress::Ipv4(*self.src.ip()),
            &IpAddress::Ipv4(*self.dst.ip()),
        );
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let ip = Ipv4Packet::new_checked(bytes).ok()?;
        if ip.version() != 4
            || ip.next_header() != IpProtocol::Tcp
            || ip.more_frags()
            || ip.frag_offset() != 0
            || !ip.verify_checksum()
        {
            return None;
        }
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        let src = ip.src_addr();
        let dst = ip.dst_addr();
        if !tcp.verify_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst)) {
            return None;
        }
        let raw = ip.payload();
        let header_len = (raw[12] >> 4) as usize * 4;
        let mut scale = 0;
        let mut i = 20;
        while i < header_len {
            match raw[i] {
                0 => break,
                1 => i += 1,
                kind => {
                    let len = *raw.get(i + 1)? as usize;
                    if len < 2 || i + len > header_len {
                        return None;
                    }
                    if kind == 3 {
                        if len != 3 || raw[i + 2] > 14 {
                            return None;
                        }
                        scale = raw[i + 2];
                    }
                    i += len;
                }
            }
        }
        Some(Self {
            src: SocketAddrV4::new(src, tcp.src_port()),
            dst: SocketAddrV4::new(dst, tcp.dst_port()),
            seq: u32::from_be_bytes(raw[4..8].try_into().ok()?),
            ack: u32::from_be_bytes(raw[8..12].try_into().ok()?),
            flags: raw[13],
            window: tcp.window_len(),
            scale,
            payload: tcp.payload().to_vec(),
        })
    }
}

pub fn mangle(data: &[u8], padding: &MimicPadding, seq: u32, ack: u32) -> Vec<u8> {
    let n = padding.len(seq, ack);
    let moved = data.len().min(12 + n);
    let mut out = vec![0; n];
    rand::rng().fill(out.as_mut_slice());
    out.extend_from_slice(&data[moved..]);
    out.extend_from_slice(&data[..moved]);
    out
}

pub fn restore(data: &[u8], padding: &MimicPadding, seq: u32, ack: u32) -> Option<Vec<u8>> {
    let n = padding.len(seq, ack);
    let mut out = data.get(n..)?.to_vec();
    let moved = out.len().min(12 + n);
    out.rotate_right(moved);
    Some(out)
}

pub fn address(ip: Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mimic_wire_vectors_and_short_datagrams() {
        // Mimic moves the first 12 UDP payload bytes to the end, rather than
        // placing an ordinary TCP header in front of an unchanged payload.
        assert_eq!(
            mangle(b"0123456789abcdef", &MimicPadding::Fixed(0), 0, 0),
            b"cdef0123456789ab"
        );
        for padding in [
            MimicPadding::Fixed(0),
            MimicPadding::Fixed(16),
            MimicPadding::Mode(config::RandomPadding::Random),
        ] {
            for len in 0..1600 {
                let data: Vec<u8> = (0..len).map(|n| n as u8).collect();
                let encoded = mangle(&data, &padding, u32::MAX, 123);
                assert_eq!(restore(&encoded, &padding, u32::MAX, 123).unwrap(), data);
            }
        }
    }

    #[test]
    fn packet_checksums_options_and_malformed_input() {
        let segment = Segment {
            src: address(Ipv4Addr::new(198, 19, 0, 2), 45678),
            dst: address(Ipv4Addr::new(192, 0, 2, 1), 443),
            seq: u32::MAX,
            ack: 123,
            flags: SYN | ACK,
            window: 65535,
            scale: WINDOW_SCALE,
            payload: vec![],
        };
        let bytes = segment.encode(1500);
        let decoded = Segment::decode(&bytes).unwrap();
        assert_eq!(decoded.scale, WINDOW_SCALE);
        assert_eq!(decoded.seq, u32::MAX);
        for len in 0..bytes.len() {
            assert!(Segment::decode(&bytes[..len]).is_none());
        }
        let mut corrupt = bytes.clone();
        corrupt[24] ^= 1;
        assert!(Segment::decode(&corrupt).is_none());
        let mut fragment = bytes;
        fragment[6] |= 0x20;
        Ipv4Packet::new_unchecked(&mut fragment[..]).fill_checksum();
        assert!(Segment::decode(&fragment).is_none());
    }
}
