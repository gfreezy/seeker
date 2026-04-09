use bytes::BufMut;
use bytes::BytesMut;
use config::Address;
use digest::Digest;
use hmac::{Hmac, Mac};
use md5::Md5;
use openssl::symm;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::crypto::VMessEncryptMethod;

pub const CMD_TCP: u8 = 0x01;
#[allow(dead_code)]
pub const CMD_UDP: u8 = 0x02;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x02;
pub const ATYP_IPV6: u8 = 0x03;

pub const VMESS_VERSION: u8 = 1;
pub const OPTION_S: u8 = 0x01; // Standard data stream (chunk stream)
#[allow(dead_code)]
pub const OPTION_M: u8 = 0x04; // Chunk masking (metadata obfuscation)
#[allow(dead_code)]
pub const OPTION_P: u8 = 0x08; // Global padding

const VMESS_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

type HmacMd5 = Hmac<Md5>;

/// Parse a UUID string into 16-byte array.
pub fn parse_uuid(uuid_str: &str) -> Result<[u8; 16]> {
    let uuid = Uuid::parse_str(uuid_str)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("invalid UUID: {e}")))?;
    Ok(*uuid.as_bytes())
}

/// Generate 16-byte authentication credential.
/// auth = HMAC-MD5(key=user_id, msg=timestamp_big_endian)
pub fn generate_auth(user_id: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(user_id).expect("HMAC accepts any key size");
    mac.update(&timestamp.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// Derive the key for encrypting the command header.
/// key = MD5(user_id ++ "c48619fe-8f02-49e0-b9e9-edf763e17e21")
pub fn derive_command_key(user_id: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(user_id);
    hasher.update(VMESS_MAGIC);
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// Derive the IV for encrypting the command header.
/// iv = MD5(timestamp_bytes * 4)
pub fn derive_command_iv(timestamp: u64) -> [u8; 16] {
    let ts_bytes = timestamp.to_be_bytes();
    let mut hasher = Md5::new();
    for _ in 0..4 {
        hasher.update(ts_bytes);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// FNV-1a 32-bit hash.
pub fn fnv1a(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Write VMess-format address to buffer.
/// NOTE: VMess address types differ from SOCKS5:
///   0x01 = IPv4, 0x02 = Domain, 0x03 = IPv6
#[allow(dead_code)]
fn vmess_write_address(addr: &Address, buf: &mut BytesMut) {
    match addr {
        Address::SocketAddress(SocketAddr::V4(v4)) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        Address::SocketAddress(SocketAddr::V6(v6)) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
        Address::DomainNameAddress(domain, port) => {
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_bytes());
            buf.put_u16(*port);
        }
    }
}

/// Build the command header plaintext (before encryption).
///
/// Layout:
///   Version(1) + DataIV(16) + DataKey(16) + RespAuthV(1)
///   + Options(1) + (P<<4|Method)(1) + Reserved(1) + Cmd(1)
///   + Port(2 BE) + ATYP(1) + Addr(var) + Padding(P) + FNV1a(4)
pub fn build_command(
    data_iv: &[u8; 16],
    data_key: &[u8; 16],
    resp_auth_v: u8,
    method: VMessEncryptMethod,
    cmd: u8,
    addr: &Address,
) -> Vec<u8> {
    let padding_len: u8 = rand::random::<u8>() % 16;
    let mut buf = BytesMut::with_capacity(128);

    buf.put_u8(VMESS_VERSION);
    buf.put_slice(data_iv);
    buf.put_slice(data_key);
    buf.put_u8(resp_auth_v);
    buf.put_u8(OPTION_S);
    buf.put_u8((padding_len << 4) | (method as u8 & 0x0f));
    buf.put_u8(0x00); // Reserved

    // Command + address (port is part of the address in VMess)
    buf.put_u8(cmd);

    // Write port and address
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
            buf.put_u16(*port);
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_bytes());
        }
    }

    // Random padding
    if padding_len > 0 {
        let padding: Vec<u8> = (0..padding_len).map(|_| rand::random()).collect();
        buf.put_slice(&padding);
    }

    // FNV1a checksum of everything so far
    let checksum = fnv1a(&buf);
    buf.put_u32(checksum);

    buf.to_vec()
}

/// Encrypt command header with AES-128-CFB.
pub fn encrypt_command(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    symm::encrypt(symm::Cipher::aes_128_cfb128(), key, Some(iv), plaintext)
        .map_err(|e| Error::other(format!("AES-128-CFB encrypt failed: {e}")))
}

/// Decrypt data with AES-128-CFB.
pub fn decrypt_cfb(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    symm::decrypt(symm::Cipher::aes_128_cfb128(), key, Some(iv), ciphertext)
        .map_err(|e| Error::other(format!("AES-128-CFB decrypt failed: {e}")))
}

/// Derive response key = MD5(request_data_key).
pub fn derive_response_key(data_key: &[u8; 16]) -> [u8; 16] {
    let result = Md5::digest(data_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// Derive response IV = MD5(request_data_iv).
pub fn derive_response_iv(data_iv: &[u8; 16]) -> [u8; 16] {
    let result = Md5::digest(data_iv);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// Parsed response header.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ResponseHeader {
    pub auth_v: u8,
    pub options: u8,
    pub cmd_instruction: u8,
    pub cmd_length: u8,
}

/// Decrypt and parse the response header (4 bytes minimum).
pub fn decrypt_response_header(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<ResponseHeader> {
    if ciphertext.len() < 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "response header too short",
        ));
    }

    let plaintext = decrypt_cfb(key, iv, ciphertext)?;

    Ok(ResponseHeader {
        auth_v: plaintext[0],
        options: plaintext[1],
        cmd_instruction: plaintext[2],
        cmd_length: plaintext[3],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid() {
        let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let bytes = parse_uuid(uuid_str).unwrap();
        assert_eq!(bytes.len(), 16);
        // Verify round-trip
        let uuid = Uuid::from_bytes(bytes);
        assert_eq!(uuid.to_string(), uuid_str);
    }

    #[test]
    fn test_parse_uuid_invalid() {
        assert!(parse_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn test_fnv1a() {
        // Known FNV-1a test vectors
        assert_eq!(fnv1a(b""), 0x811c9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c292c);
        assert_eq!(fnv1a(b"foobar"), 0xbf9cf968);
    }

    #[test]
    fn test_generate_auth() {
        let user_id = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let timestamp: u64 = 1234567890;
        let auth = generate_auth(&user_id, timestamp);
        assert_eq!(auth.len(), 16);
        // Same inputs should produce same output
        let auth2 = generate_auth(&user_id, timestamp);
        assert_eq!(auth, auth2);
        // Different timestamp should produce different output
        let auth3 = generate_auth(&user_id, timestamp + 1);
        assert_ne!(auth, auth3);
    }

    #[test]
    fn test_derive_command_key_iv() {
        let user_id = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let key = derive_command_key(&user_id);
        assert_eq!(key.len(), 16);

        let timestamp: u64 = 1234567890;
        let iv = derive_command_iv(timestamp);
        assert_eq!(iv.len(), 16);

        // Different timestamps produce different IVs
        let iv2 = derive_command_iv(timestamp + 1);
        assert_ne!(iv, iv2);
    }

    #[test]
    fn test_encrypt_decrypt_command_roundtrip() {
        let user_id = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let key = derive_command_key(&user_id);
        let iv = derive_command_iv(1234567890);

        let data_key = [1u8; 16];
        let data_iv = [2u8; 16];
        let addr = Address::DomainNameAddress("example.com".to_string(), 80);

        let cmd = build_command(
            &data_iv,
            &data_key,
            0x42,
            VMessEncryptMethod::Aes128Gcm,
            CMD_TCP,
            &addr,
        );

        // Verify command starts with version
        assert_eq!(cmd[0], VMESS_VERSION);

        // Encrypt and decrypt
        let encrypted = encrypt_command(&key, &iv, &cmd).unwrap();
        let decrypted = decrypt_cfb(&key, &iv, &encrypted).unwrap();
        assert_eq!(cmd, decrypted);
    }

    #[test]
    fn test_build_command_structure() {
        let data_key = [0xAA; 16];
        let data_iv = [0xBB; 16];
        let addr = Address::DomainNameAddress("test.com".to_string(), 443);

        let cmd = build_command(
            &data_iv,
            &data_key,
            0x55,
            VMessEncryptMethod::Aes128Gcm,
            CMD_TCP,
            &addr,
        );

        // Check version
        assert_eq!(cmd[0], 1);
        // Check data IV
        assert_eq!(&cmd[1..17], &[0xBB; 16]);
        // Check data key
        assert_eq!(&cmd[17..33], &[0xAA; 16]);
        // Check response auth V
        assert_eq!(cmd[33], 0x55);
        // Check options (S=1)
        assert_eq!(cmd[34], OPTION_S);
        // Check encrypt method in lower 4 bits (GCM = 0x03)
        assert_eq!(cmd[35] & 0x0f, 0x03);
        // Check reserved
        assert_eq!(cmd[36], 0x00);
        // Check command
        assert_eq!(cmd[37], CMD_TCP);

        // Last 4 bytes should be FNV1a checksum
        let checksum_bytes = &cmd[cmd.len() - 4..];
        let expected_checksum = fnv1a(&cmd[..cmd.len() - 4]);
        let actual_checksum = u32::from_be_bytes([
            checksum_bytes[0],
            checksum_bytes[1],
            checksum_bytes[2],
            checksum_bytes[3],
        ]);
        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_response_key_iv_derivation() {
        let data_key = [0xAA; 16];
        let data_iv = [0xBB; 16];

        let resp_key = derive_response_key(&data_key);
        let resp_iv = derive_response_iv(&data_iv);

        // Should be deterministic
        assert_eq!(resp_key, derive_response_key(&data_key));
        assert_eq!(resp_iv, derive_response_iv(&data_iv));

        // Should differ from input
        assert_ne!(resp_key, data_key);
        assert_ne!(resp_iv, data_iv);
    }

    #[test]
    fn test_decrypt_response_header() {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        let header = [0x42, 0x00, 0x00, 0x00]; // auth_v=0x42, options=0, cmd=0, len=0
        let encrypted = encrypt_command(&key, &iv, &header).unwrap();
        let parsed = decrypt_response_header(&key, &iv, &encrypted).unwrap();
        assert_eq!(parsed.auth_v, 0x42);
        assert_eq!(parsed.cmd_length, 0);
    }

    #[test]
    fn test_vmess_write_address_domain() {
        let addr = Address::DomainNameAddress("example.com".to_string(), 80);
        let mut buf = BytesMut::new();
        vmess_write_address(&addr, &mut buf);
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 11); // "example.com".len()
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([buf[13], buf[14]]), 80);
    }

    #[test]
    fn test_vmess_write_address_ipv4() {
        let addr = Address::SocketAddress("1.2.3.4:443".parse().unwrap());
        let mut buf = BytesMut::new();
        vmess_write_address(&addr, &mut buf);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([buf[5], buf[6]]), 443);
    }
}
