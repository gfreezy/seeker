use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
pub const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] =
    b"VMess Header AEAD Key_Length";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] =
    b"VMess Header AEAD Nonce_Length";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

const BLOCK_LEN: usize = 64;
const TAG_LEN: usize = 32;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// VMess AEAD KDF — nested HMAC construction.
///
/// V2Ray's KDF builds nested HMACs where each level uses the previous level as its hash function:
///   L0 = HMAC-SHA256(key="VMess AEAD KDF")
///   L1(msg) = HMAC(key=salt1, hash=L0)(msg) = L0(okey1 || L0(ikey1 || msg))
///   L2(msg) = HMAC(key=salt2, hash=L1)(msg) = L1(okey2 || L1(ikey2 || msg))
///   ...
///
/// Each level is a function that takes arbitrary data and returns 32 bytes.
///
/// Level 0: plain HMAC-SHA256 with key = KDF_SALT_CONST_VMESS_AEAD_KDF
fn l0(data: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(KDF_SALT_CONST_VMESS_AEAD_KDF).expect("HMAC key size");
    mac.update(data);
    let r = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&r);
    out
}

/// Compute HMAC key pads (ikey, okey) from a key, using a given hash function to shorten long keys.
fn compute_pads(
    key: &[u8],
    hash_fn: &dyn Fn(&[u8]) -> [u8; TAG_LEN],
) -> ([u8; BLOCK_LEN], [u8; BLOCK_LEN]) {
    let mut ikey = [0u8; BLOCK_LEN];
    let mut okey = [0u8; BLOCK_LEN];

    if key.len() > BLOCK_LEN {
        let hk = hash_fn(key);
        ikey[..TAG_LEN].copy_from_slice(&hk);
        okey[..TAG_LEN].copy_from_slice(&hk);
    } else {
        ikey[..key.len()].copy_from_slice(key);
        okey[..key.len()].copy_from_slice(key);
    }

    for i in 0..BLOCK_LEN {
        ikey[i] ^= IPAD;
        okey[i] ^= OPAD;
    }
    (ikey, okey)
}

/// Level 1: HMAC(key=salt, hash=L0)
/// L1(msg) = L0(okey || L0(ikey || msg))
fn l1(salt: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
    let (ikey, okey) = compute_pads(salt, &l0);
    let mut inner_input = Vec::with_capacity(BLOCK_LEN + data.len());
    inner_input.extend_from_slice(&ikey);
    inner_input.extend_from_slice(data);
    let inner = l0(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_LEN + TAG_LEN);
    outer_input.extend_from_slice(&okey);
    outer_input.extend_from_slice(&inner);
    l0(&outer_input)
}

/// Level 2: HMAC(key=salt2, hash=L1(salt1))
/// L2(msg) = L1(okey2 || L1(ikey2 || msg))
fn l2(salt1: &[u8], salt2: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
    let l1_fn = |d: &[u8]| l1(salt1, d);
    let (ikey, okey) = compute_pads(salt2, &l1_fn);

    let mut inner_input = Vec::with_capacity(BLOCK_LEN + data.len());
    inner_input.extend_from_slice(&ikey);
    inner_input.extend_from_slice(data);
    let inner = l1_fn(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_LEN + TAG_LEN);
    outer_input.extend_from_slice(&okey);
    outer_input.extend_from_slice(&inner);
    l1_fn(&outer_input)
}

/// Level 3: HMAC(key=salt3, hash=L2(salt1, salt2))
fn l3(salt1: &[u8], salt2: &[u8], salt3: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
    let l2_fn = |d: &[u8]| l2(salt1, salt2, d);
    let (ikey, okey) = compute_pads(salt3, &l2_fn);

    let mut inner_input = Vec::with_capacity(BLOCK_LEN + data.len());
    inner_input.extend_from_slice(&ikey);
    inner_input.extend_from_slice(data);
    let inner = l2_fn(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_LEN + TAG_LEN);
    outer_input.extend_from_slice(&okey);
    outer_input.extend_from_slice(&inner);
    l2_fn(&outer_input)
}

/// KDF with 1 salt level. Used for auth_id encryption key, response header keys.
pub fn vmess_kdf_1_one_shot(data: &[u8], salt1: &[u8]) -> [u8; 32] {
    l1(salt1, data)
}

/// KDF with 3 salt levels. Used for header payload encryption keys.
pub fn vmess_kdf_3_one_shot(data: &[u8], salt1: &[u8], salt2: &[u8], salt3: &[u8]) -> [u8; 32] {
    l3(salt1, salt2, salt3, data)
}

/// Shortcut: KDF16 returns first 16 bytes.
pub fn vmess_kdf16(data: &[u8], salt: &[u8]) -> [u8; 16] {
    let full = vmess_kdf_1_one_shot(data, salt);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_deterministic() {
        let key = b"test-key-data";
        let r1 = vmess_kdf_1_one_shot(key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
        let r2 = vmess_kdf_1_one_shot(key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_kdf_different_salts() {
        let key = b"test-key-data";
        let r1 = vmess_kdf_1_one_shot(key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
        let r2 = vmess_kdf_1_one_shot(key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_kdf3_deterministic() {
        let key = b"test-key";
        let r1 = vmess_kdf_3_one_shot(key, b"s1", b"s2", b"s3");
        let r2 = vmess_kdf_3_one_shot(key, b"s1", b"s2", b"s3");
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_kdf16_length() {
        let result = vmess_kdf16(b"test", KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
        assert_eq!(result.len(), 16);
    }
}
