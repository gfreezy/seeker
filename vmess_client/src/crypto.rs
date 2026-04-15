use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;
use cipher::KeyIvInit;
use std::io::{Error, ErrorKind, Result};

type Aes128CfbEnc = cfb_mode::BufEncryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::BufDecryptor<aes::Aes128>;

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
pub enum CfbCipher {
    Encrypt(Aes128CfbEnc),
    Decrypt(Aes128CfbDec),
}

impl CfbCipher {
    pub fn new_encrypt(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        let c = Aes128CfbEnc::new_from_slices(key, iv)
            .map_err(|e| Error::other(format!("CFB encrypt init: {e}")))?;
        Ok(Self::Encrypt(c))
    }

    pub fn new_decrypt(key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        let c = Aes128CfbDec::new_from_slices(key, iv)
            .map_err(|e| Error::other(format!("CFB decrypt init: {e}")))?;
        Ok(Self::Decrypt(c))
    }

    /// Encrypt/decrypt data (streaming, state preserved across calls).
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        if output.len() < input.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "output buffer too small",
            ));
        }
        output[..input.len()].copy_from_slice(input);
        match self {
            CfbCipher::Encrypt(c) => c.encrypt(&mut output[..input.len()]),
            CfbCipher::Decrypt(c) => c.decrypt(&mut output[..input.len()]),
        }
        Ok(input.len())
    }
}

/// AEAD cipher (AES-128-GCM or ChaCha20-Poly1305) for per-chunk encryption.
///
/// The GCM variant is boxed because `Aes128Gcm` carries ~750 bytes of precomputed
/// tables — roughly 15× the size of the ChaCha state. Without the box, this enum
/// would trip `clippy::large_enum_variant` and every `VMessDataCipher` would pay
/// that footprint even when the connection uses ChaCha.
pub enum AeadCipher {
    Gcm {
        cipher: Box<Aes128Gcm>,
        base_nonce: [u8; 12],
        count: u16,
    },
    ChaCha {
        cipher: ChaCha20Poly1305,
        base_nonce: [u8; 12],
        count: u16,
    },
}

impl AeadCipher {
    pub fn new_gcm(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&iv[..12]);
        let cipher = Box::new(Aes128Gcm::new(key.into()));
        Self::Gcm {
            cipher,
            base_nonce,
            count: 0,
        }
    }

    pub fn new_chacha20(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        // ChaCha20-Poly1305 needs 32-byte key, but VMess uses 16-byte key.
        // V2Ray extends the 16-byte key by repeating it: key16 ++ key16 -> key32.
        let mut key32 = [0u8; 32];
        key32[..16].copy_from_slice(key);
        key32[16..].copy_from_slice(key);
        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&iv[..12]);
        let cipher = ChaCha20Poly1305::new((&key32).into());
        Self::ChaCha {
            cipher,
            base_nonce,
            count: 0,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let (base_nonce, count) = match self {
            AeadCipher::Gcm {
                base_nonce, count, ..
            } => (base_nonce, count),
            AeadCipher::ChaCha {
                base_nonce, count, ..
            } => (base_nonce, count),
        };
        let mut nonce = *base_nonce;
        let count_bytes = count.to_be_bytes();
        nonce[0] = count_bytes[0];
        nonce[1] = count_bytes[1];
        *count = count.wrapping_add(1);
        nonce
    }

    /// Seal plaintext with AEAD, returning ciphertext + 16-byte tag appended.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let mut buf = plaintext.to_vec();
        let tag = match self {
            AeadCipher::Gcm { cipher, .. } => cipher
                .encrypt_in_place_detached((&nonce).into(), &[], &mut buf)
                .map_err(|e| Error::other(format!("AEAD seal: {e}")))?,
            AeadCipher::ChaCha { cipher, .. } => cipher
                .encrypt_in_place_detached((&nonce).into(), &[], &mut buf)
                .map_err(|e| Error::other(format!("AEAD seal: {e}")))?,
        };
        buf.extend_from_slice(&tag);
        Ok(buf)
    }

    /// Open ciphertext (with 16-byte tag appended), returning plaintext.
    pub fn open(&mut self, ciphertext_with_tag: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return Err(Error::new(ErrorKind::InvalidData, "AEAD data too short"));
        }

        let nonce = self.next_nonce();
        let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
        let mut buf = ciphertext.to_vec();
        match self {
            AeadCipher::Gcm { cipher, .. } => cipher
                .decrypt_in_place_detached((&nonce).into(), &[], &mut buf, tag.into())
                .map_err(|e| Error::new(ErrorKind::InvalidData, format!("AEAD open: {e}")))?,
            AeadCipher::ChaCha { cipher, .. } => cipher
                .decrypt_in_place_detached((&nonce).into(), &[], &mut buf, tag.into())
                .map_err(|e| Error::new(ErrorKind::InvalidData, format!("AEAD open: {e}")))?,
        }
        Ok(buf)
    }
}

/// Unified data cipher for VMess data stream.
///
/// Inner variants are boxed: `CfbCipher` holds ~700 bytes of AES round keys
/// and `AeadCipher::Gcm` holds ~750 bytes of GCM tables. Without indirection
/// every `VMessDataCipher` would be ~736 bytes regardless of which cipher is
/// actually selected.
pub enum VMessDataCipher {
    Cfb(Box<CfbCipher>),
    Aead(Box<AeadCipher>),
    None,
}

impl VMessDataCipher {
    pub fn new_encrypt(method: VMessEncryptMethod, key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        match method {
            VMessEncryptMethod::Aes128Cfb => {
                Ok(Self::Cfb(Box::new(CfbCipher::new_encrypt(key, iv)?)))
            }
            VMessEncryptMethod::Aes128Gcm => {
                Ok(Self::Aead(Box::new(AeadCipher::new_gcm(key, iv))))
            }
            VMessEncryptMethod::ChaCha20Poly1305 => {
                Ok(Self::Aead(Box::new(AeadCipher::new_chacha20(key, iv))))
            }
            VMessEncryptMethod::None => Ok(Self::None),
        }
    }

    pub fn new_decrypt(method: VMessEncryptMethod, key: &[u8; 16], iv: &[u8; 16]) -> Result<Self> {
        match method {
            VMessEncryptMethod::Aes128Cfb => {
                Ok(Self::Cfb(Box::new(CfbCipher::new_decrypt(key, iv)?)))
            }
            VMessEncryptMethod::Aes128Gcm => {
                Ok(Self::Aead(Box::new(AeadCipher::new_gcm(key, iv))))
            }
            VMessEncryptMethod::ChaCha20Poly1305 => {
                Ok(Self::Aead(Box::new(AeadCipher::new_chacha20(key, iv))))
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
