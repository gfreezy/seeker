//! Crypto protocol for ShadowSocks UDP
//!
//! Payload with stream cipher
//! ```plain
//! +-------+----------+
//! |  IV   | Payload  |
//! +-------+----------+
//! | Fixed | Variable |
//! +-------+----------+
//! ```
//!
//! Payload with AEAD cipher
//!
//! ```plain
//! UDP (after encryption, *ciphertext*)
//! +--------+-----------+-----------+
//! | NONCE  |  *Data*   |  Data_TAG |
//! +--------+-----------+-----------+
//! | Fixed  | Variable  |   Fixed   |
//! +--------+-----------+-----------+
//! ```

use std::io::{Error, ErrorKind, Result};

use bytes::{BufMut, BytesMut};
use crypto::{CipherCategory, CipherType, CryptoMode};

/// Encrypt payload into ShadowSocks UDP encrypted packet
pub fn encrypt_payload(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut BytesMut,
) -> Result<usize> {
    match t.category() {
        CipherCategory::Stream => encrypt_payload_stream(t, key, payload, output),
        CipherCategory::Aead => encrypt_payload_aead(t, key, payload, output),
    }
}

/// Decrypt payload from ShadowSocks UDP encrypted packet
pub fn decrypt_payload(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut BytesMut,
) -> Result<usize> {
    match t.category() {
        CipherCategory::Stream => decrypt_payload_stream(t, key, payload, output),
        CipherCategory::Aead => decrypt_payload_aead(t, key, payload, output),
    }
}

fn encrypt_payload_aead(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut BytesMut,
) -> Result<usize> {
    let salt = t.gen_salt();
    let tag_size = t.tag_size();
    let mut cipher = crypto::new_aead_encryptor(t, key, &salt);

    let salt_len = salt.len();
    output.put_slice(&salt);
    output.resize(salt_len + payload.len() + tag_size, 0);

    cipher.encrypt(
        payload,
        &mut output[salt_len..salt_len + payload.len() + tag_size],
    );

    Ok(salt_len + payload.len() + tag_size)
}

fn decrypt_payload_aead(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut BytesMut,
) -> Result<usize> {
    let tag_size = t.tag_size();
    let salt_size = t.salt_size();

    if payload.len() < tag_size + salt_size {
        let err = Error::new(ErrorKind::UnexpectedEof, "udp packet too short");
        return Err(err);
    }

    let salt = &payload[..salt_size];
    let data = &payload[salt_size..];
    let data_length = payload.len() - tag_size - salt_size;

    let mut cipher = crypto::new_aead_decryptor(t, key, salt);

    output.resize(data_length, 0);
    cipher.decrypt(data, &mut output[..data_length])?;

    Ok(data_length)
}

fn encrypt_payload_stream(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut BytesMut,
) -> Result<usize> {
    let iv = t.gen_init_vec();
    let mut cipher = crypto::new_stream(t, key, &iv, CryptoMode::Encrypt);

    output.put_slice(&iv);
    cipher.update(payload, output)?;
    cipher.finalize(output)?;
    Ok(payload.len() + iv.len())
}

fn decrypt_payload_stream(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut BytesMut,
) -> Result<usize> {
    let iv_size = t.iv_size();

    let iv = &payload[..iv_size];
    let data = &payload[iv_size..];

    let mut cipher = crypto::new_stream(t, key, iv, CryptoMode::Decrypt);

    cipher.update(data, output)?;
    cipher.finalize(output)?;

    Ok(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_PACKET_SIZE;

    #[test]
    fn test_encrypt_and_decrypt_payload_aead() {
        let cipher_type = CipherType::XChaCha20IetfPoly1305;
        let key = cipher_type.bytes_to_key(b"key");
        let payload = b"payload";
        let mut output = BytesMut::with_capacity(MAX_PACKET_SIZE);
        let mut output2 = BytesMut::with_capacity(MAX_PACKET_SIZE);
        let size = encrypt_payload_aead(cipher_type, &key, payload, &mut output).unwrap();
        let size2 = decrypt_payload_aead(cipher_type, &key, &output[..size], &mut output2).unwrap();
        assert_eq!(&output2[..size2], payload);
    }

    #[test]
    fn test_encrypt_and_decrypt_payload_stream() {
        let cipher_type = CipherType::ChaCha20Ietf;
        let key = cipher_type.bytes_to_key(b"key");
        let payload = b"payload";
        let mut output = BytesMut::with_capacity(MAX_PACKET_SIZE);
        let mut output2 = BytesMut::with_capacity(MAX_PACKET_SIZE);
        let size = encrypt_payload_stream(cipher_type, &key, payload, &mut output).unwrap();
        let size2 =
            decrypt_payload_stream(cipher_type, &key, &output[..size], &mut output2).unwrap();
        assert_eq!(
            std::str::from_utf8(&output2[..size2]),
            std::str::from_utf8(payload)
        );
    }
}
