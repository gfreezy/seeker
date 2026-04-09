use bytes::BufMut;
use bytes::BytesMut;
use config::Address;
use digest::Digest;
use hmac::{Hmac, Mac};
use md5::Md5;
use openssl::symm;
use sha2::Sha256;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::crypto::VMessEncryptMethod;
use crate::kdf;

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

    // For AEAD modes, enable chunk masking (M) which uses ShakeSizeParser
    let options = if method.is_aead() {
        OPTION_S | OPTION_M
    } else {
        OPTION_S
    };

    buf.put_u8(VMESS_VERSION);
    buf.put_slice(data_iv);
    buf.put_slice(data_key);
    buf.put_u8(resp_auth_v);
    buf.put_u8(options);
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

// ─── AEAD Header Format ─────────────────────────────────────

/// CRC32 IEEE checksum.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Create AEAD Auth ID (16 bytes): AES-128-ECB encrypt [timestamp(8) + random(4) + CRC32(4)].
pub fn create_auth_id(cmd_key: &[u8; 16], timestamp: u64) -> Result<[u8; 16]> {
    let aes_key =
        &kdf::vmess_kdf_1_one_shot(cmd_key, kdf::KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY)[..16];

    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&timestamp.to_be_bytes());
    rand::fill(&mut buf[8..12]);
    let crc = crc32_ieee(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());

    // AES-128-ECB encrypt (single block, no padding)
    let cipher = openssl::symm::Cipher::aes_128_ecb();
    let mut crypter =
        openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Encrypt, aes_key, None)
            .map_err(|e| Error::other(format!("AES ECB init: {e}")))?;
    crypter.pad(false);
    let mut out = [0u8; 32]; // extra space for openssl
    let n = crypter
        .update(&buf, &mut out)
        .map_err(|e| Error::other(format!("AES ECB encrypt: {e}")))?;
    let n2 = crypter
        .finalize(&mut out[n..])
        .map_err(|e| Error::other(format!("AES ECB finalize: {e}")))?;
    assert_eq!(n + n2, 16);

    let mut auth_id = [0u8; 16];
    auth_id.copy_from_slice(&out[..16]);
    Ok(auth_id)
}

/// Seal the VMess AEAD header.
///
/// Returns: auth_id(16) + sealed_length(18) + connection_nonce(8) + sealed_command(N+16)
pub fn seal_vmess_aead_header(cmd_key: &[u8; 16], command: &[u8]) -> Result<Vec<u8>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::other(format!("system time: {e}")))?
        .as_secs();

    let auth_id = create_auth_id(cmd_key, timestamp)?;

    let mut connection_nonce = [0u8; 8];
    rand::fill(&mut connection_nonce[..]);

    // Seal command length: AEAD(u16(command.len()))
    let len_key = &kdf::vmess_kdf_3_one_shot(
        cmd_key,
        kdf::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        &auth_id,
        &connection_nonce,
    )[..16];
    let len_iv = &kdf::vmess_kdf_3_one_shot(
        cmd_key,
        kdf::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        &auth_id,
        &connection_nonce,
    )[..12];

    let len_bytes = (command.len() as u16).to_be_bytes();
    let mut len_tag = [0u8; 16];
    let sealed_len = symm::encrypt_aead(
        symm::Cipher::aes_128_gcm(),
        len_key,
        Some(len_iv),
        &auth_id,
        &len_bytes,
        &mut len_tag,
    )
    .map_err(|e| Error::other(format!("AEAD seal length: {e}")))?;

    // Seal command payload: AEAD(command)
    let payload_key = &kdf::vmess_kdf_3_one_shot(
        cmd_key,
        kdf::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        &auth_id,
        &connection_nonce,
    )[..16];
    let payload_iv = &kdf::vmess_kdf_3_one_shot(
        cmd_key,
        kdf::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
        &auth_id,
        &connection_nonce,
    )[..12];

    let mut payload_tag = [0u8; 16];
    let sealed_payload = symm::encrypt_aead(
        symm::Cipher::aes_128_gcm(),
        payload_key,
        Some(payload_iv),
        &auth_id,
        command,
        &mut payload_tag,
    )
    .map_err(|e| Error::other(format!("AEAD seal payload: {e}")))?;

    // Assemble: auth_id(16) + sealed_len(2) + len_tag(16) + nonce(8) + sealed_payload + payload_tag(16)
    let mut out = Vec::with_capacity(16 + 2 + 16 + 8 + sealed_payload.len() + 16);
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&sealed_len);
    out.extend_from_slice(&len_tag);
    out.extend_from_slice(&connection_nonce);
    out.extend_from_slice(&sealed_payload);
    out.extend_from_slice(&payload_tag);

    Ok(out)
}

/// Derive response key for AEAD mode = SHA256(request_data_key)[0:16].
pub fn derive_response_key_aead(data_key: &[u8; 16]) -> [u8; 16] {
    let result = Sha256::digest(data_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

/// Derive response IV for AEAD mode = SHA256(request_data_iv)[0:16].
pub fn derive_response_iv_aead(data_iv: &[u8; 16]) -> [u8; 16] {
    let result = Sha256::digest(data_iv);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

/// Decrypt AEAD response header.
/// Reads: sealed_length(18) then sealed_payload(len+16).
/// Returns the raw header bytes (typically 4 bytes: auth_v + options + cmd + cmd_len).
pub fn decrypt_aead_response_header(
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>> {
    // Decrypt length: first 18 bytes
    if data.len() < 18 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "AEAD response header too short",
        ));
    }

    let len_key = kdf::vmess_kdf16(resp_key, kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY);
    let len_iv =
        &kdf::vmess_kdf_1_one_shot(resp_iv, kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV)[..12];

    let (len_ct, len_tag) = data[..18].split_at(2);
    let len_plain = symm::decrypt_aead(
        symm::Cipher::aes_128_gcm(),
        &len_key,
        Some(len_iv),
        &[],
        len_ct,
        len_tag,
    )
    .map_err(|e| Error::other(format!("AEAD resp header len decrypt: {e}")))?;

    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    // Decrypt payload
    let payload_start = 18;
    let payload_end = payload_start + header_len + 16;
    if data.len() < payload_end {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "AEAD response header payload too short",
        ));
    }

    let payload_key = kdf::vmess_kdf16(resp_key, kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY);
    let payload_iv =
        &kdf::vmess_kdf_1_one_shot(resp_iv, kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV)[..12];

    let (payload_ct, payload_tag) = data[payload_start..payload_end].split_at(header_len);
    let payload = symm::decrypt_aead(
        symm::Cipher::aes_128_gcm(),
        &payload_key,
        Some(payload_iv),
        &[],
        payload_ct,
        payload_tag,
    )
    .map_err(|e| Error::other(format!("AEAD resp header payload decrypt: {e}")))?;

    Ok(payload)
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
        // Check options (S=1 | M=4 for GCM)
        assert_eq!(cmd[34], OPTION_S | OPTION_M);
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
