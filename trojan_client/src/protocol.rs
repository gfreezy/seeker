use bytes::{BufMut, BytesMut};
use config::Address;
use sha2::{Digest, Sha224};
use std::fmt::Write;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const CRLF: &[u8] = b"\r\n";

/// Compute hex(SHA224(password)), producing a 56-character lowercase hex string.
pub fn hash_password(password: &str) -> String {
    let hash = Sha224::digest(password.as_bytes());
    let mut hex = String::with_capacity(56);
    for byte in hash {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

/// Encode a Trojan handshake request into `buf`.
///
/// Format: password_hash(56) + CRLF + CMD(1) + ATYP(1) + DST.ADDR(var) + DST.PORT(2) + CRLF
pub fn encode_trojan_request(password_hash: &str, cmd: u8, addr: &Address, buf: &mut BytesMut) {
    buf.put_slice(password_hash.as_bytes());
    buf.put_slice(CRLF);
    buf.put_u8(cmd);
    addr.write_to_buf(buf);
    buf.put_slice(CRLF);
}

/// Encode a Trojan UDP packet into `buf`.
///
/// Format: ATYP(1) + DST.ADDR(var) + DST.PORT(2) + Length(2) + CRLF + Payload
pub fn encode_udp_packet(addr: &Address, payload: &[u8], buf: &mut BytesMut) {
    addr.write_to_buf(buf);
    buf.put_u16(payload.len() as u16);
    buf.put_slice(CRLF);
    buf.put_slice(payload);
}

/// Decode a Trojan UDP packet from `data`.
///
/// Returns (address, payload_slice, total_consumed_bytes).
pub fn decode_udp_packet(data: &[u8]) -> io::Result<(Address, &[u8], usize)> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty packet"));
    }

    let atyp = data[0];
    let (addr, addr_len) = match atyp {
        ATYP_IPV4 => {
            // 1 (atyp) + 4 (ip) + 2 (port) = 7
            if data.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv4 address",
                ));
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            (
                Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(ip, port))),
                7,
            )
        }
        ATYP_IPV6 => {
            // 1 (atyp) + 16 (ip) + 2 (port) = 19
            if data.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv6 address",
                ));
            }
            let ip = Ipv6Addr::from([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
                data[10], data[11], data[12], data[13], data[14], data[15], data[16],
            ]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            (
                Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
                19,
            )
        }
        ATYP_DOMAIN => {
            if data.len() < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated domain address",
                ));
            }
            let domain_len = data[1] as usize;
            // 1 (atyp) + 1 (len) + domain_len + 2 (port)
            let total = 2 + domain_len + 2;
            if data.len() < total {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated domain address",
                ));
            }
            let domain = String::from_utf8(data[2..2 + domain_len].to_vec()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid domain encoding")
            })?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[2 + domain_len + 1]]);
            (Address::DomainNameAddress(domain, port), total)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported address type: {atyp:#x}"),
            ));
        }
    };

    // After address: Length(2) + CRLF(2) + Payload
    if data.len() < addr_len + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated UDP packet header",
        ));
    }
    let payload_len = u16::from_be_bytes([data[addr_len], data[addr_len + 1]]) as usize;
    // Skip CRLF (2 bytes after length)
    let payload_start = addr_len + 4;
    let total = payload_start + payload_len;
    if data.len() < total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated UDP payload",
        ));
    }

    Ok((addr, &data[payload_start..total], total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        // SHA-224("test") = 90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809
        let hash = hash_password("test");
        assert_eq!(hash.len(), 56);
        assert_eq!(
            hash,
            "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809"
        );
    }

    #[test]
    fn test_hash_password_empty() {
        // SHA-224("") = d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
        let hash = hash_password("");
        assert_eq!(hash.len(), 56);
        assert_eq!(
            hash,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn test_encode_trojan_request_domain() {
        let hash = hash_password("password");
        let addr = Address::DomainNameAddress("example.com".to_string(), 80);
        let mut buf = BytesMut::new();
        encode_trojan_request(&hash, CMD_CONNECT, &addr, &mut buf);

        // hash(56) + CRLF(2) + CMD(1) + ATYP(1) + len(1) + "example.com"(11) + port(2) + CRLF(2) = 76
        assert_eq!(buf.len(), 76);
        // Starts with hash
        assert_eq!(&buf[..56], hash.as_bytes());
        // CRLF after hash
        assert_eq!(&buf[56..58], b"\r\n");
        // CMD
        assert_eq!(buf[58], CMD_CONNECT);
        // ATYP
        assert_eq!(buf[59], ATYP_DOMAIN);
        // Ends with CRLF
        assert_eq!(&buf[buf.len() - 2..], b"\r\n");
    }

    #[test]
    fn test_encode_decode_udp_packet_ipv4() {
        let addr = Address::SocketAddress("1.2.3.4:53".parse().unwrap());
        let payload = b"hello";
        let mut buf = BytesMut::new();
        encode_udp_packet(&addr, payload, &mut buf);

        let (decoded_addr, decoded_payload, consumed) = decode_udp_packet(&buf).unwrap();
        assert_eq!(decoded_addr, addr);
        assert_eq!(decoded_payload, payload);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_encode_decode_udp_packet_domain() {
        let addr = Address::DomainNameAddress("example.com".to_string(), 443);
        let payload = b"world";
        let mut buf = BytesMut::new();
        encode_udp_packet(&addr, payload, &mut buf);

        let (decoded_addr, decoded_payload, consumed) = decode_udp_packet(&buf).unwrap();
        assert_eq!(decoded_addr, addr);
        assert_eq!(decoded_payload, payload);
        assert_eq!(consumed, buf.len());
    }
}
