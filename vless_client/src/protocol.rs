use bytes::{BufMut, BytesMut};
use config::Address;
use std::net::SocketAddr;
use uuid::Uuid;

pub const VLESS_VERSION: u8 = 0;
pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

/// Encode VLESS addons as protobuf.
///
/// If flow is provided, encodes: field1(tag=0x0a) + varint_len + flow_bytes
/// Returns the encoded addons bytes (empty if no flow).
fn encode_addons(flow: Option<&str>) -> Vec<u8> {
    let flow = match flow {
        Some(f) if !f.is_empty() => f,
        _ => return Vec::new(),
    };
    let flow_bytes = flow.as_bytes();
    let mut addons = Vec::with_capacity(2 + flow_bytes.len());
    // Protobuf: field 1, wire type 2 (length-delimited)
    addons.push(0x0a);
    // Varint-encode the length (flow strings are short, single byte is fine)
    addons.push(flow_bytes.len() as u8);
    addons.extend_from_slice(flow_bytes);
    addons
}

/// Encode a VLESS request header into `buf`.
///
/// Format: Version(1) + UUID(16) + AddonsLen(1) + Addons(var) + CMD(1) + Port(2) + AddrType(1) + Addr(var)
pub fn encode_vless_request(
    uuid: &Uuid,
    cmd: u8,
    addr: &Address,
    flow: Option<&str>,
    buf: &mut BytesMut,
) -> std::io::Result<()> {
    // Version
    buf.put_u8(VLESS_VERSION);
    // UUID (16 bytes)
    buf.put_slice(uuid.as_bytes());
    // Addons
    let addons = encode_addons(flow);
    buf.put_u8(addons.len() as u8);
    if !addons.is_empty() {
        buf.put_slice(&addons);
    }
    // Command
    buf.put_u8(cmd);
    // Port (big-endian) + Address type + Address
    write_vless_address(addr, buf)
}

/// Write VLESS address format: Port(2) + AddrType(1) + Addr(var)
fn write_vless_address(addr: &Address, buf: &mut BytesMut) -> std::io::Result<()> {
    match addr {
        Address::SocketAddress(SocketAddr::V4(v4)) => {
            buf.put_u16(v4.port());
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&v4.ip().octets());
        }
        Address::SocketAddress(SocketAddr::V6(v6)) => {
            buf.put_u16(v6.port());
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&v6.ip().octets());
        }
        Address::DomainNameAddress(domain, port) => {
            if domain.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "VLESS domain name too long: {} bytes (max 255)",
                        domain.len()
                    ),
                ));
            }
            buf.put_u16(*port);
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_vless_request_domain_no_flow() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let addr = Address::DomainNameAddress("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        encode_vless_request(&uuid, CMD_TCP, &addr, None, &mut buf).unwrap();

        // version(1) + uuid(16) + addons_len(1) + cmd(1) + port(2) + atyp(1) + domain_len(1) + "example.com"(11) = 34
        assert_eq!(buf.len(), 34);
        assert_eq!(buf[0], VLESS_VERSION);
        assert_eq!(&buf[1..17], uuid.as_bytes());
        assert_eq!(buf[17], 0); // addons_len = 0
        assert_eq!(buf[18], CMD_TCP);
        assert_eq!(u16::from_be_bytes([buf[19], buf[20]]), 443);
        assert_eq!(buf[21], ATYP_DOMAIN);
        assert_eq!(buf[22], 11);
        assert_eq!(&buf[23..34], b"example.com");
    }

    #[test]
    fn test_encode_vless_request_with_flow() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let addr = Address::DomainNameAddress("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        encode_vless_request(&uuid, CMD_TCP, &addr, Some("xtls-rprx-vision"), &mut buf).unwrap();

        assert_eq!(buf[0], VLESS_VERSION);
        assert_eq!(&buf[1..17], uuid.as_bytes());
        // addons_len = 1 (tag) + 1 (len) + 16 (flow string) = 18
        assert_eq!(buf[17], 18);
        // protobuf: tag=0x0a, len=16
        assert_eq!(buf[18], 0x0a);
        assert_eq!(buf[19], 16);
        assert_eq!(&buf[20..36], b"xtls-rprx-vision");
        // cmd follows addons
        assert_eq!(buf[36], CMD_TCP);
    }

    #[test]
    fn test_encode_vless_request_ipv4() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let addr = Address::SocketAddress("1.2.3.4:80".parse().unwrap());
        let mut buf = BytesMut::new();
        encode_vless_request(&uuid, CMD_TCP, &addr, None, &mut buf).unwrap();

        // version(1) + uuid(16) + addons_len(1) + cmd(1) + port(2) + atyp(1) + ipv4(4) = 26
        assert_eq!(buf.len(), 26);
        assert_eq!(buf[18], CMD_TCP);
        assert_eq!(u16::from_be_bytes([buf[19], buf[20]]), 80);
        assert_eq!(buf[21], ATYP_IPV4);
        assert_eq!(&buf[22..26], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_encode_vless_request_ipv6() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let addr = Address::SocketAddress("[::1]:8080".parse().unwrap());
        let mut buf = BytesMut::new();
        encode_vless_request(&uuid, CMD_TCP, &addr, None, &mut buf).unwrap();

        // version(1) + uuid(16) + addons_len(1) + cmd(1) + port(2) + atyp(1) + ipv6(16) = 38
        assert_eq!(buf.len(), 38);
        assert_eq!(buf[21], ATYP_IPV6);
    }

    #[test]
    fn test_encode_addons_none() {
        assert!(encode_addons(None).is_empty());
        assert!(encode_addons(Some("")).is_empty());
    }

    #[test]
    fn test_encode_addons_flow() {
        let addons = encode_addons(Some("xtls-rprx-vision"));
        // tag(1) + len(1) + "xtls-rprx-vision"(16) = 18
        assert_eq!(addons.len(), 18);
        assert_eq!(addons[0], 0x0a);
        assert_eq!(addons[1], 16);
        assert_eq!(&addons[2..], b"xtls-rprx-vision");
    }
}
