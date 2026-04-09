use openssl::symm;
use std::io::{Error, ErrorKind, Result};

/// VMess data encryption methods.
/// Values match V2Ray's SecurityType protobuf enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VMessEncryptMethod {
    Aes128Cfb = 0x01,        // LEGACY
    Aes128Gcm = 0x03,        // AES128_GCM
    ChaCha20Poly1305 = 0x04, // CHACHA20_POLY1305
    None = 0x05,             // NONE
}

impl VMessEncryptMethod {
    pub fn from_str_name(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" | "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            "aes-128-cfb" | "legacy" => Ok(Self::Aes128Cfb),
            "none" | "zero" => Ok(Self::None),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown vmess encrypt method: {s}"),
            )),
        }
    }

    pub fn is_aead(&self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::ChaCha20Poly1305)
    }

    pub fn tag_size(&self) -> usize {
        if self.is_aead() {
            16
        } else {
            0
        }
    }
}

/// Streaming AES-128-CFB cipher (maintains state across calls).
pub struct CfbCipher {
    crypter: symm::Crypter,
}

impl CfbCipher {
    pub fn new_encrypt(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        let crypter = symm::Crypter::new(
            symm::Cipher::aes_128_cfb128(),
            symm::Mode::Encrypt,
            key,
            Some(iv),
        )
        .map_err(|e| Error::other(format!("CFB encrypt init: {e}")))?;
        Ok(Self { crypter })
    }

    pub fn new_decrypt(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        let crypter = symm::Crypter::new(
            symm::Cipher::aes_128_cfb128(),
            symm::Mode::Decrypt,
            key,
            Some(iv),
        )
        .map_err(|e| Error::other(format!("CFB decrypt init: {e}")))?;
        Ok(Self { crypter })
    }

    /// Encrypt/decrypt data in-place (streaming, state preserved across calls).
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.crypter
            .update(input, output)
            .map_err(|e| Error::other(format!("CFB update: {e}")))
    }
}

/// AEAD cipher (AES-128-GCM or ChaCha20-Poly1305) for per-chunk encryption.
pub struct AeadCipher {
    cipher: symm::Cipher,
    key: [u8; 16],
    base_nonce: [u8; 12],
    count: u16,
}

impl AeadCipher {
    pub fn new_gcm(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&iv[..12]);
        Self {
            cipher: symm::Cipher::aes_128_gcm(),
            key: *key,
            base_nonce,
            count: 0,
        }
    }

    pub fn new_chacha20(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        // ChaCha20-Poly1305 needs 32-byte key, but VMess uses 16-byte key.
        // V2Ray extends the 16-byte key by repeating it: key16 ++ key16 -> key32.
        // However, openssl's chacha20_poly1305 expects 32-byte key.
        // We'll handle this in seal/open by using the proper key size.
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&iv[..12]);
        Self {
            cipher: symm::Cipher::chacha20_poly1305(),
            key: *key,
            base_nonce,
            count: 0,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.base_nonce;
        let count_bytes = self.count.to_be_bytes();
        nonce[0] = count_bytes[0];
        nonce[1] = count_bytes[1];
        self.count = self.count.wrapping_add(1);
        nonce
    }

    fn effective_key(&self) -> Vec<u8> {
        if self.cipher == symm::Cipher::chacha20_poly1305() {
            // ChaCha20-Poly1305 needs 32-byte key; VMess doubles the 16-byte key
            let mut key32 = vec![0u8; 32];
            key32[..16].copy_from_slice(&self.key);
            key32[16..].copy_from_slice(&self.key);
            key32
        } else {
            self.key.to_vec()
        }
    }

    /// Seal plaintext with AEAD, returning ciphertext + 16-byte tag appended.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let key = self.effective_key();
        let mut tag = [0u8; 16];

        let ciphertext =
            symm::encrypt_aead(self.cipher, &key, Some(&nonce), &[], plaintext, &mut tag)
                .map_err(|e| Error::other(format!("AEAD seal: {e}")))?;

        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        Ok(result)
    }

    /// Open ciphertext (with 16-byte tag appended), returning plaintext.
    pub fn open(&mut self, ciphertext_with_tag: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return Err(Error::new(ErrorKind::InvalidData, "AEAD data too short"));
        }

        let nonce = self.next_nonce();
        let key = self.effective_key();
        let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

        symm::decrypt_aead(self.cipher, &key, Some(&nonce), &[], ciphertext, tag)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("AEAD open: {e}")))
    }
}

/// Unified data cipher for VMess data stream.
pub enum VMessDataCipher {
    Cfb(CfbCipher),
    Aead(AeadCipher),
    None,
}

impl VMessDataCipher {
    pub fn new_encrypt(method: VMessEncryptMethod, key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        match method {
            VMessEncryptMethod::Aes128Cfb => Ok(Self::Cfb(CfbCipher::new_encrypt(key, iv)?)),
            VMessEncryptMethod::Aes128Gcm => Ok(Self::Aead(AeadCipher::new_gcm(key, iv))),
            VMessEncryptMethod::ChaCha20Poly1305 => {
                Ok(Self::Aead(AeadCipher::new_chacha20(key, iv)))
            }
            VMessEncryptMethod::None => Ok(Self::None),
        }
    }

    pub fn new_decrypt(method: VMessEncryptMethod, key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        match method {
            VMessEncryptMethod::Aes128Cfb => Ok(Self::Cfb(CfbCipher::new_decrypt(key, iv)?)),
            VMessEncryptMethod::Aes128Gcm => Ok(Self::Aead(AeadCipher::new_gcm(key, iv))),
            VMessEncryptMethod::ChaCha20Poly1305 => {
                Ok(Self::Aead(AeadCipher::new_chacha20(key, iv)))
            }
            VMessEncryptMethod::None => Ok(Self::None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_method_from_str() {
        assert_eq!(
            VMessEncryptMethod::from_str_name("auto").unwrap(),
            VMessEncryptMethod::Aes128Gcm
        );
        assert_eq!(
            VMessEncryptMethod::from_str_name("aes-128-gcm").unwrap(),
            VMessEncryptMethod::Aes128Gcm
        );
        assert_eq!(
            VMessEncryptMethod::from_str_name("chacha20-poly1305").unwrap(),
            VMessEncryptMethod::ChaCha20Poly1305
        );
        assert_eq!(
            VMessEncryptMethod::from_str_name("none").unwrap(),
            VMessEncryptMethod::None
        );
        assert!(VMessEncryptMethod::from_str_name("invalid").is_err());
    }

    #[test]
    fn test_encrypt_method_wire_values() {
        // Verify wire format values match V2Ray's SecurityType protobuf enum
        assert_eq!(VMessEncryptMethod::Aes128Cfb as u8, 0x01);
        assert_eq!(VMessEncryptMethod::Aes128Gcm as u8, 0x03);
        assert_eq!(VMessEncryptMethod::ChaCha20Poly1305 as u8, 0x04);
        assert_eq!(VMessEncryptMethod::None as u8, 0x05);
    }

    #[test]
    fn test_cfb_cipher_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x55u8; 16];
        let plaintext = b"hello world vmess cfb test data";

        let mut enc = CfbCipher::new_encrypt(&key, &iv).unwrap();
        let mut ciphertext = vec![0u8; plaintext.len()];
        enc.update(plaintext, &mut ciphertext).unwrap();

        let mut dec = CfbCipher::new_decrypt(&key, &iv).unwrap();
        let mut decrypted = vec![0u8; ciphertext.len()];
        dec.update(&ciphertext, &mut decrypted).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_cfb_cipher_streaming() {
        let key = [0x42u8; 16];
        let iv = [0x55u8; 16];

        // Encrypt in two parts
        let mut enc = CfbCipher::new_encrypt(&key, &iv).unwrap();
        let mut ct1 = vec![0u8; 5];
        enc.update(b"hello", &mut ct1).unwrap();
        let mut ct2 = vec![0u8; 6];
        enc.update(b" world", &mut ct2).unwrap();

        // Decrypt all at once
        let mut dec = CfbCipher::new_decrypt(&key, &iv).unwrap();
        let mut combined = vec![0u8; 11];
        let mut all_ct = ct1;
        all_ct.extend_from_slice(&ct2);
        dec.update(&all_ct, &mut combined).unwrap();

        assert_eq!(&combined, b"hello world");
    }

    #[test]
    fn test_aead_gcm_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x55u8; 16];

        let mut enc = AeadCipher::new_gcm(&key, &iv);
        let mut dec = AeadCipher::new_gcm(&key, &iv);

        let plaintext = b"hello aead gcm";
        let sealed = enc.seal(plaintext).unwrap();
        assert_eq!(sealed.len(), plaintext.len() + 16); // 16 byte tag

        let opened = dec.open(&sealed).unwrap();
        assert_eq!(&opened, plaintext);
    }

    #[test]
    fn test_aead_nonce_increments() {
        let key = [0x42u8; 16];
        let iv = [0x55u8; 16];

        let mut enc = AeadCipher::new_gcm(&key, &iv);
        let mut dec = AeadCipher::new_gcm(&key, &iv);

        // Encrypt two chunks
        let sealed1 = enc.seal(b"chunk1").unwrap();
        let sealed2 = enc.seal(b"chunk2").unwrap();

        // Decrypt in order
        let opened1 = dec.open(&sealed1).unwrap();
        let opened2 = dec.open(&sealed2).unwrap();
        assert_eq!(&opened1, b"chunk1");
        assert_eq!(&opened2, b"chunk2");
    }
}
