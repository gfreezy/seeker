use bytes::{Buf, BufMut, BytesMut};
use std::io::{self, ErrorKind};

/// QUIC varint encoding per RFC 9000 Section 16
pub fn encode_varint(mut value: u64, buf: &mut BytesMut) {
    if value <= 63 {
        buf.put_u8(value as u8);
    } else if value <= 16383 {
        value |= 0x4000;
        buf.put_u16(value as u16);
    } else if value <= 1_073_741_823 {
        value |= 0x8000_0000;
        buf.put_u32(value as u32);
    } else {
        value |= 0xC000_0000_0000_0000;
        buf.put_u64(value);
    }
}

/// QUIC varint decoding per RFC 9000 Section 16
pub fn decode_varint(buf: &mut impl Buf) -> io::Result<u64> {
    if !buf.has_remaining() {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "empty buffer"));
    }
    let first = buf.chunk()[0];
    let len = 1 << (first >> 6);
    if buf.remaining() < len {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "not enough bytes for varint",
        ));
    }
    let value = match len {
        1 => {
            buf.advance(1);
            (first & 0x3F) as u64
        }
        2 => {
            let v = buf.get_u16();
            (v & 0x3FFF) as u64
        }
        4 => {
            let v = buf.get_u32();
            (v & 0x3FFF_FFFF) as u64
        }
        8 => {
            let v = buf.get_u64();
            v & 0x3FFF_FFFF_FFFF_FFFF
        }
        _ => unreachable!(),
    };
    Ok(value)
}

/// Hysteria 2 address encoding: plain "host:port" string with varint length prefix.
/// This is used for both TCP requests and UDP messages.
pub fn encode_address(addr: &config::Address, buf: &mut BytesMut) {
    let addr_str = format!("{addr}"); // produces "host:port" or "ip:port"
    let addr_bytes = addr_str.as_bytes();
    encode_varint(addr_bytes.len() as u64, buf);
    buf.put_slice(addr_bytes);
}

/// Decode Hysteria 2 address from buffer: varint(len) + "host:port" string.
pub fn decode_address(buf: &mut impl Buf) -> io::Result<config::Address> {
    let addr_len = decode_varint(buf)? as usize;
    if buf.remaining() < addr_len {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "not enough bytes for address",
        ));
    }
    let mut addr_bytes = vec![0u8; addr_len];
    buf.copy_to_slice(&mut addr_bytes);
    let addr_str =
        String::from_utf8(addr_bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    // Parse "host:port" string
    use std::str::FromStr;
    config::Address::from_str(&addr_str)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("invalid address: {e:?}")))
}

/// TCP Request frame ID
pub const TCP_REQUEST_ID: u32 = 0x401;

/// Encode a TCP request: varint(0x401) + address + padding
pub fn encode_tcp_request(addr: &config::Address, buf: &mut BytesMut) {
    encode_varint(TCP_REQUEST_ID as u64, buf);
    encode_address(addr, buf);
    // Padding: varint(0) — no padding
    encode_varint(0, buf);
}

/// TCP Response status
#[derive(Debug)]
pub struct TcpResponse {
    pub status: u8,
    pub message: String,
}

/// Decode a TCP response: status(u8) + varint(msg_len) + msg + varint(padding_len) + padding
pub fn decode_tcp_response(buf: &mut impl Buf) -> io::Result<TcpResponse> {
    if !buf.has_remaining() {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "empty tcp response",
        ));
    }
    let status = buf.get_u8();
    let msg_len = decode_varint(buf)? as usize;
    if buf.remaining() < msg_len {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "not enough bytes for response message",
        ));
    }
    let mut msg_bytes = vec![0u8; msg_len];
    buf.copy_to_slice(&mut msg_bytes);
    let message =
        String::from_utf8(msg_bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

    // Read and skip padding
    let padding_len = decode_varint(buf)? as usize;
    if buf.remaining() < padding_len {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "not enough bytes for padding",
        ));
    }
    buf.advance(padding_len);

    Ok(TcpResponse { status, message })
}

/// UDP message frame for QUIC datagrams
#[derive(Debug)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub addr: config::Address,
    pub payload: Vec<u8>,
}

/// Encode a UDP message for QUIC datagram
pub fn encode_udp_message(msg: &UdpMessage, buf: &mut BytesMut) {
    encode_varint(msg.session_id as u64, buf);
    encode_varint(msg.packet_id as u64, buf);
    encode_varint(msg.fragment_id as u64, buf);
    encode_varint(msg.fragment_count as u64, buf);
    encode_address(&msg.addr, buf);
    buf.put_slice(&msg.payload);
}

/// Decode a UDP message from QUIC datagram bytes
pub fn decode_udp_message(buf: &mut impl Buf) -> io::Result<UdpMessage> {
    let session_id = decode_varint(buf)? as u32;
    let packet_id = decode_varint(buf)? as u16;
    let fragment_id = decode_varint(buf)? as u8;
    let fragment_count = decode_varint(buf)? as u8;
    let addr = decode_address(buf)?;
    let mut payload = vec![0u8; buf.remaining()];
    buf.copy_to_slice(&mut payload);
    Ok(UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        addr,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let mut buf = BytesMut::new();
            encode_varint(val, &mut buf);
            let decoded = decode_varint(&mut buf).unwrap();
            assert_eq!(val, decoded, "failed for value {val}");
        }
    }

    #[test]
    fn test_varint_encoding_lengths() {
        // 1-byte: 0..=63
        let mut buf = BytesMut::new();
        encode_varint(63, &mut buf);
        assert_eq!(buf.len(), 1);

        // 2-byte: 64..=16383
        buf.clear();
        encode_varint(64, &mut buf);
        assert_eq!(buf.len(), 2);

        // 4-byte: 16384..=1073741823
        buf.clear();
        encode_varint(16384, &mut buf);
        assert_eq!(buf.len(), 4);

        // 8-byte: 1073741824+
        buf.clear();
        encode_varint(1_073_741_824, &mut buf);
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn test_varint_decode_empty_buffer() {
        let mut buf = BytesMut::new();
        assert!(decode_varint(&mut buf).is_err());
    }

    #[test]
    fn test_address_roundtrip_domain() {
        let addr = config::Address::DomainNameAddress("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        encode_address(&addr, &mut buf);
        let decoded = decode_address(&mut buf).unwrap();
        assert_eq!(format!("{addr}"), format!("{decoded}"));
    }

    #[test]
    fn test_address_encoding_is_plain_string() {
        let addr = config::Address::DomainNameAddress("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        encode_address(&addr, &mut buf);
        // Should be varint(15) + "example.com:443"
        let len = decode_varint(&mut buf).unwrap();
        assert_eq!(len, 15); // "example.com:443".len()
        let mut addr_bytes = vec![0u8; len as usize];
        buf.copy_to_slice(&mut addr_bytes);
        assert_eq!(std::str::from_utf8(&addr_bytes).unwrap(), "example.com:443");
    }

    #[test]
    fn test_address_roundtrip_ipv4() {
        let addr = config::Address::from_str("1.2.3.4:8080").unwrap();
        let mut buf = BytesMut::new();
        encode_address(&addr, &mut buf);
        let decoded = decode_address(&mut buf).unwrap();
        assert_eq!(format!("{addr}"), format!("{decoded}"));
    }

    #[test]
    fn test_address_roundtrip_ipv6() {
        let addr = config::Address::SocketAddress("[::1]:8080".parse().unwrap());
        let mut buf = BytesMut::new();
        encode_address(&addr, &mut buf);
        let decoded = decode_address(&mut buf).unwrap();
        assert_eq!(format!("{addr}"), format!("{decoded}"));
    }

    #[test]
    fn test_tcp_request_encoding() {
        let addr = config::Address::DomainNameAddress("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        encode_tcp_request(&addr, &mut buf);
        // Should start with varint(0x401)
        assert!(!buf.is_empty());
        // Verify the request ID
        let id = decode_varint(&mut buf).unwrap();
        assert_eq!(id, TCP_REQUEST_ID as u64);
        // Should contain the address as a plain string
        let decoded_addr = decode_address(&mut buf).unwrap();
        assert_eq!(format!("{addr}"), format!("{decoded_addr}"));
        // Should have padding length (0)
        let padding = decode_varint(&mut buf).unwrap();
        assert_eq!(padding, 0);
        assert!(!buf.has_remaining());
    }

    #[test]
    fn test_tcp_response_decode_success() {
        let mut buf = BytesMut::new();
        // status = 0x00 (success)
        buf.put_u8(0x00);
        // message = "ok" (varint len + bytes)
        encode_varint(2, &mut buf);
        buf.put_slice(b"ok");
        // padding = 0
        encode_varint(0, &mut buf);

        let resp = decode_tcp_response(&mut buf).unwrap();
        assert_eq!(resp.status, 0x00);
        assert_eq!(resp.message, "ok");
    }

    #[test]
    fn test_tcp_response_decode_error_status() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x01); // error status
        encode_varint(11, &mut buf);
        buf.put_slice(b"access deny");
        encode_varint(0, &mut buf);

        let resp = decode_tcp_response(&mut buf).unwrap();
        assert_eq!(resp.status, 0x01);
        assert_eq!(resp.message, "access deny");
    }

    #[test]
    fn test_tcp_response_decode_with_padding() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00);
        encode_varint(0, &mut buf); // empty message
        encode_varint(5, &mut buf); // 5 bytes padding
        buf.put_slice(&[0u8; 5]);

        let resp = decode_tcp_response(&mut buf).unwrap();
        assert_eq!(resp.status, 0x00);
        assert_eq!(resp.message, "");
        assert!(!buf.has_remaining());
    }

    #[test]
    fn test_tcp_response_decode_empty() {
        let mut buf = BytesMut::new();
        assert!(decode_tcp_response(&mut buf).is_err());
    }

    #[test]
    fn test_udp_message_roundtrip() {
        let msg = UdpMessage {
            session_id: 42,
            packet_id: 7,
            fragment_id: 0,
            fragment_count: 1,
            addr: config::Address::from_str("1.2.3.4:53").unwrap(),
            payload: b"hello dns".to_vec(),
        };

        let mut buf = BytesMut::new();
        encode_udp_message(&msg, &mut buf);

        let decoded = decode_udp_message(&mut buf).unwrap();
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.packet_id, 7);
        assert_eq!(decoded.fragment_id, 0);
        assert_eq!(decoded.fragment_count, 1);
        assert_eq!(format!("{}", decoded.addr), "1.2.3.4:53");
        assert_eq!(decoded.payload, b"hello dns");
    }

    #[test]
    fn test_udp_message_roundtrip_domain() {
        let msg = UdpMessage {
            session_id: 100,
            packet_id: 1,
            fragment_id: 2,
            fragment_count: 3,
            addr: config::Address::DomainNameAddress("dns.google".to_string(), 443),
            payload: vec![0xAB, 0xCD],
        };

        let mut buf = BytesMut::new();
        encode_udp_message(&msg, &mut buf);

        let decoded = decode_udp_message(&mut buf).unwrap();
        assert_eq!(decoded.session_id, 100);
        assert_eq!(decoded.packet_id, 1);
        assert_eq!(decoded.fragment_id, 2);
        assert_eq!(decoded.fragment_count, 3);
        assert_eq!(format!("{}", decoded.addr), "dns.google:443");
        assert_eq!(decoded.payload, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_udp_message_empty_payload() {
        let msg = UdpMessage {
            session_id: 1,
            packet_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            addr: config::Address::from_str("127.0.0.1:53").unwrap(),
            payload: vec![],
        };

        let mut buf = BytesMut::new();
        encode_udp_message(&msg, &mut buf);

        let decoded = decode_udp_message(&mut buf).unwrap();
        assert_eq!(decoded.session_id, 1);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_address_decode_truncated() {
        // varint(100) but only 3 bytes of data — should fail with UnexpectedEof
        let mut buf = BytesMut::new();
        encode_varint(100, &mut buf);
        buf.put_slice(b"abc");
        assert!(decode_address(&mut buf).is_err());
    }
}
