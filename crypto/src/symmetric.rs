//! Symmetric stream ciphers backed by RustCrypto crates.
//!
//! Replaces the legacy OpenSSL implementation. Supports AES-{128,192,256}
//! in CFB-128 / CFB-8 / CTR modes and Camellia-{128,192,256} in CFB-128 / CFB-8.
//! CFB-1 (bit-level feedback) is not provided — RustCrypto has no such impl —
//! and these modes are deprecated legacy Shadowsocks stream ciphers.

// `generic-array` 0.14 is deprecated (RustCrypto is migrating to generic-array 1.x),
// but our pinned cipher 0.4 / aes 0.8 / cfb-mode 0.8 still depend on it. Upgrading
// the full stack is a separate effort (aes-gcm 0.11 is still RC), so we silence
// the chain of deprecation warnings here.
#![allow(deprecated)]

use super::{cipher, CipherResult, CipherType, CryptoMode, StreamCipher};
use ::cipher::generic_array::GenericArray;
use ::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher as CipherStreamCipher};
use bytes::{BufMut, BytesMut};

// --- AES CFB-128 (streaming via BufEncryptor/BufDecryptor) ---
#[cfg(feature = "aes-cfb")]
type Aes128Cfb128Enc = cfb_mode::BufEncryptor<aes::Aes128>;
#[cfg(feature = "aes-cfb")]
type Aes128Cfb128Dec = cfb_mode::BufDecryptor<aes::Aes128>;
#[cfg(feature = "aes-cfb")]
type Aes192Cfb128Enc = cfb_mode::BufEncryptor<aes::Aes192>;
#[cfg(feature = "aes-cfb")]
type Aes192Cfb128Dec = cfb_mode::BufDecryptor<aes::Aes192>;
#[cfg(feature = "aes-cfb")]
type Aes256Cfb128Enc = cfb_mode::BufEncryptor<aes::Aes256>;
#[cfg(feature = "aes-cfb")]
type Aes256Cfb128Dec = cfb_mode::BufDecryptor<aes::Aes256>;

// --- AES CFB-8 (block size = 1 byte; streaming via encrypt_block_mut) ---
#[cfg(feature = "aes-cfb")]
type Aes128Cfb8Enc = cfb8::Encryptor<aes::Aes128>;
#[cfg(feature = "aes-cfb")]
type Aes128Cfb8Dec = cfb8::Decryptor<aes::Aes128>;
#[cfg(feature = "aes-cfb")]
type Aes192Cfb8Enc = cfb8::Encryptor<aes::Aes192>;
#[cfg(feature = "aes-cfb")]
type Aes192Cfb8Dec = cfb8::Decryptor<aes::Aes192>;
#[cfg(feature = "aes-cfb")]
type Aes256Cfb8Enc = cfb8::Encryptor<aes::Aes256>;
#[cfg(feature = "aes-cfb")]
type Aes256Cfb8Dec = cfb8::Decryptor<aes::Aes256>;

// --- AES CTR ---
#[cfg(feature = "aes-ctr")]
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
#[cfg(feature = "aes-ctr")]
type Aes192Ctr = ctr::Ctr128BE<aes::Aes192>;
#[cfg(feature = "aes-ctr")]
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

// --- Camellia CFB-128 ---
#[cfg(feature = "camellia-cfb")]
type Camellia128Cfb128Enc = cfb_mode::BufEncryptor<camellia::Camellia128>;
#[cfg(feature = "camellia-cfb")]
type Camellia128Cfb128Dec = cfb_mode::BufDecryptor<camellia::Camellia128>;
#[cfg(feature = "camellia-cfb")]
type Camellia192Cfb128Enc = cfb_mode::BufEncryptor<camellia::Camellia192>;
#[cfg(feature = "camellia-cfb")]
type Camellia192Cfb128Dec = cfb_mode::BufDecryptor<camellia::Camellia192>;
#[cfg(feature = "camellia-cfb")]
type Camellia256Cfb128Enc = cfb_mode::BufEncryptor<camellia::Camellia256>;
#[cfg(feature = "camellia-cfb")]
type Camellia256Cfb128Dec = cfb_mode::BufDecryptor<camellia::Camellia256>;

// --- Camellia CFB-8 ---
#[cfg(feature = "camellia-cfb")]
type Camellia128Cfb8Enc = cfb8::Encryptor<camellia::Camellia128>;
#[cfg(feature = "camellia-cfb")]
type Camellia128Cfb8Dec = cfb8::Decryptor<camellia::Camellia128>;
#[cfg(feature = "camellia-cfb")]
type Camellia192Cfb8Enc = cfb8::Encryptor<camellia::Camellia192>;
#[cfg(feature = "camellia-cfb")]
type Camellia192Cfb8Dec = cfb8::Decryptor<camellia::Camellia192>;
#[cfg(feature = "camellia-cfb")]
type Camellia256Cfb8Enc = cfb8::Encryptor<camellia::Camellia256>;
#[cfg(feature = "camellia-cfb")]
type Camellia256Cfb8Dec = cfb8::Decryptor<camellia::Camellia256>;

enum Inner {
    #[cfg(feature = "aes-cfb")]
    Aes128Cfb128Enc(Aes128Cfb128Enc),
    #[cfg(feature = "aes-cfb")]
    Aes128Cfb128Dec(Aes128Cfb128Dec),
    #[cfg(feature = "aes-cfb")]
    Aes192Cfb128Enc(Aes192Cfb128Enc),
    #[cfg(feature = "aes-cfb")]
    Aes192Cfb128Dec(Aes192Cfb128Dec),
    #[cfg(feature = "aes-cfb")]
    Aes256Cfb128Enc(Aes256Cfb128Enc),
    #[cfg(feature = "aes-cfb")]
    Aes256Cfb128Dec(Aes256Cfb128Dec),

    #[cfg(feature = "aes-cfb")]
    Aes128Cfb8Enc(Aes128Cfb8Enc),
    #[cfg(feature = "aes-cfb")]
    Aes128Cfb8Dec(Aes128Cfb8Dec),
    #[cfg(feature = "aes-cfb")]
    Aes192Cfb8Enc(Aes192Cfb8Enc),
    #[cfg(feature = "aes-cfb")]
    Aes192Cfb8Dec(Aes192Cfb8Dec),
    #[cfg(feature = "aes-cfb")]
    Aes256Cfb8Enc(Aes256Cfb8Enc),
    #[cfg(feature = "aes-cfb")]
    Aes256Cfb8Dec(Aes256Cfb8Dec),

    #[cfg(feature = "aes-ctr")]
    Aes128Ctr(Aes128Ctr),
    #[cfg(feature = "aes-ctr")]
    Aes192Ctr(Aes192Ctr),
    #[cfg(feature = "aes-ctr")]
    Aes256Ctr(Aes256Ctr),

    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb128Enc(Camellia128Cfb128Enc),
    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb128Dec(Camellia128Cfb128Dec),
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb128Enc(Camellia192Cfb128Enc),
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb128Dec(Camellia192Cfb128Dec),
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb128Enc(Camellia256Cfb128Enc),
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb128Dec(Camellia256Cfb128Dec),

    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb8Enc(Camellia128Cfb8Enc),
    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb8Dec(Camellia128Cfb8Dec),
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb8Enc(Camellia192Cfb8Enc),
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb8Dec(Camellia192Cfb8Dec),
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb8Enc(Camellia256Cfb8Enc),
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb8Dec(Camellia256Cfb8Dec),
}

/// Symmetric stream cipher (formerly `OpenSSLCipher`), now backed by RustCrypto.
pub struct SymmetricCipher {
    inner: Inner,
}

impl SymmetricCipher {
    pub fn new(
        cipher_type: cipher::CipherType,
        key: &[u8],
        iv: &[u8],
        mode: CryptoMode,
    ) -> SymmetricCipher {
        SymmetricCipher {
            inner: build_inner(cipher_type, key, iv, mode),
        }
    }
}

fn build_inner(t: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> Inner {
    match t {
        #[cfg(feature = "aes-cfb")]
        CipherType::Aes128Cfb | CipherType::Aes128Cfb128 => match mode {
            CryptoMode::Encrypt => Inner::Aes128Cfb128Enc(
                Aes128Cfb128Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Aes128Cfb128Dec(
                Aes128Cfb128Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "aes-cfb")]
        CipherType::Aes192Cfb | CipherType::Aes192Cfb128 => match mode {
            CryptoMode::Encrypt => Inner::Aes192Cfb128Enc(
                Aes192Cfb128Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Aes192Cfb128Dec(
                Aes192Cfb128Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "aes-cfb")]
        CipherType::Aes256Cfb | CipherType::Aes256Cfb128 => match mode {
            CryptoMode::Encrypt => Inner::Aes256Cfb128Enc(
                Aes256Cfb128Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Aes256Cfb128Dec(
                Aes256Cfb128Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },

        #[cfg(feature = "aes-cfb")]
        CipherType::Aes128Cfb8 => match mode {
            CryptoMode::Encrypt => {
                Inner::Aes128Cfb8Enc(Aes128Cfb8Enc::new_from_slices(key, iv).expect("valid key/iv"))
            }
            CryptoMode::Decrypt => {
                Inner::Aes128Cfb8Dec(Aes128Cfb8Dec::new_from_slices(key, iv).expect("valid key/iv"))
            }
        },
        #[cfg(feature = "aes-cfb")]
        CipherType::Aes192Cfb8 => match mode {
            CryptoMode::Encrypt => {
                Inner::Aes192Cfb8Enc(Aes192Cfb8Enc::new_from_slices(key, iv).expect("valid key/iv"))
            }
            CryptoMode::Decrypt => {
                Inner::Aes192Cfb8Dec(Aes192Cfb8Dec::new_from_slices(key, iv).expect("valid key/iv"))
            }
        },
        #[cfg(feature = "aes-cfb")]
        CipherType::Aes256Cfb8 => match mode {
            CryptoMode::Encrypt => {
                Inner::Aes256Cfb8Enc(Aes256Cfb8Enc::new_from_slices(key, iv).expect("valid key/iv"))
            }
            CryptoMode::Decrypt => {
                Inner::Aes256Cfb8Dec(Aes256Cfb8Dec::new_from_slices(key, iv).expect("valid key/iv"))
            }
        },

        #[cfg(feature = "aes-cfb")]
        CipherType::Aes128Cfb1 | CipherType::Aes192Cfb1 | CipherType::Aes256Cfb1 => {
            panic!("CFB-1 ciphers are not supported (no pure-Rust implementation)")
        }

        #[cfg(feature = "aes-ctr")]
        CipherType::Aes128Ctr => {
            Inner::Aes128Ctr(Aes128Ctr::new_from_slices(key, iv).expect("valid key/iv"))
        }
        #[cfg(feature = "aes-ctr")]
        CipherType::Aes192Ctr => {
            Inner::Aes192Ctr(Aes192Ctr::new_from_slices(key, iv).expect("valid key/iv"))
        }
        #[cfg(feature = "aes-ctr")]
        CipherType::Aes256Ctr => {
            Inner::Aes256Ctr(Aes256Ctr::new_from_slices(key, iv).expect("valid key/iv"))
        }

        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia128Cfb | CipherType::Camellia128Cfb128 => match mode {
            CryptoMode::Encrypt => Inner::Camellia128Cfb128Enc(
                Camellia128Cfb128Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Camellia128Cfb128Dec(
                Camellia128Cfb128Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia192Cfb | CipherType::Camellia192Cfb128 => match mode {
            CryptoMode::Encrypt => Inner::Camellia192Cfb128Enc(
                Camellia192Cfb128Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Camellia192Cfb128Dec(
                Camellia192Cfb128Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia256Cfb | CipherType::Camellia256Cfb128 => match mode {
            CryptoMode::Encrypt => Inner::Camellia256Cfb128Enc(
                Camellia256Cfb128Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Camellia256Cfb128Dec(
                Camellia256Cfb128Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia128Cfb8 => match mode {
            CryptoMode::Encrypt => Inner::Camellia128Cfb8Enc(
                Camellia128Cfb8Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Camellia128Cfb8Dec(
                Camellia128Cfb8Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia192Cfb8 => match mode {
            CryptoMode::Encrypt => Inner::Camellia192Cfb8Enc(
                Camellia192Cfb8Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Camellia192Cfb8Dec(
                Camellia192Cfb8Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia256Cfb8 => match mode {
            CryptoMode::Encrypt => Inner::Camellia256Cfb8Enc(
                Camellia256Cfb8Enc::new_from_slices(key, iv).expect("valid key/iv"),
            ),
            CryptoMode::Decrypt => Inner::Camellia256Cfb8Dec(
                Camellia256Cfb8Dec::new_from_slices(key, iv).expect("valid key/iv"),
            ),
        },
        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia128Cfb1 | CipherType::Camellia192Cfb1 | CipherType::Camellia256Cfb1 => {
            panic!("Camellia CFB-1 ciphers are not supported (no pure-Rust implementation)")
        }

        other => panic!("cipher type {other:?} is not supported by SymmetricCipher"),
    }
}

/// Encrypt `buf` in-place byte-by-byte through a CFB-8 encryptor, advancing its state.
#[cfg(any(feature = "aes-cfb", feature = "camellia-cfb"))]
fn cfb8_encrypt<C>(c: &mut C, buf: &mut [u8])
where
    C: BlockEncryptMut<BlockSize = ::cipher::consts::U1>,
{
    for b in buf.iter_mut() {
        let mut block = GenericArray::<u8, ::cipher::consts::U1>::default();
        block[0] = *b;
        c.encrypt_block_mut(&mut block);
        *b = block[0];
    }
}

/// Decrypt `buf` in-place byte-by-byte through a CFB-8 decryptor, advancing its state.
#[cfg(any(feature = "aes-cfb", feature = "camellia-cfb"))]
fn cfb8_decrypt<C>(c: &mut C, buf: &mut [u8])
where
    C: BlockDecryptMut<BlockSize = ::cipher::consts::U1>,
{
    for b in buf.iter_mut() {
        let mut block = GenericArray::<u8, ::cipher::consts::U1>::default();
        block[0] = *b;
        c.decrypt_block_mut(&mut block);
        *b = block[0];
    }
}

fn process_in_place(inner: &mut Inner, buf: &mut [u8]) {
    match inner {
        #[cfg(feature = "aes-cfb")]
        Inner::Aes128Cfb128Enc(c) => c.encrypt(buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes128Cfb128Dec(c) => c.decrypt(buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes192Cfb128Enc(c) => c.encrypt(buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes192Cfb128Dec(c) => c.decrypt(buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes256Cfb128Enc(c) => c.encrypt(buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes256Cfb128Dec(c) => c.decrypt(buf),

        #[cfg(feature = "aes-cfb")]
        Inner::Aes128Cfb8Enc(c) => cfb8_encrypt(c, buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes128Cfb8Dec(c) => cfb8_decrypt(c, buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes192Cfb8Enc(c) => cfb8_encrypt(c, buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes192Cfb8Dec(c) => cfb8_decrypt(c, buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes256Cfb8Enc(c) => cfb8_encrypt(c, buf),
        #[cfg(feature = "aes-cfb")]
        Inner::Aes256Cfb8Dec(c) => cfb8_decrypt(c, buf),

        #[cfg(feature = "aes-ctr")]
        Inner::Aes128Ctr(c) => c.apply_keystream(buf),
        #[cfg(feature = "aes-ctr")]
        Inner::Aes192Ctr(c) => c.apply_keystream(buf),
        #[cfg(feature = "aes-ctr")]
        Inner::Aes256Ctr(c) => c.apply_keystream(buf),

        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia128Cfb128Enc(c) => c.encrypt(buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia128Cfb128Dec(c) => c.decrypt(buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia192Cfb128Enc(c) => c.encrypt(buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia192Cfb128Dec(c) => c.decrypt(buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia256Cfb128Enc(c) => c.encrypt(buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia256Cfb128Dec(c) => c.decrypt(buf),

        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia128Cfb8Enc(c) => cfb8_encrypt(c, buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia128Cfb8Dec(c) => cfb8_decrypt(c, buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia192Cfb8Enc(c) => cfb8_encrypt(c, buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia192Cfb8Dec(c) => cfb8_decrypt(c, buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia256Cfb8Enc(c) => cfb8_encrypt(c, buf),
        #[cfg(feature = "camellia-cfb")]
        Inner::Camellia256Cfb8Dec(c) => cfb8_decrypt(c, buf),
    }
}

unsafe impl Send for SymmetricCipher {}

impl StreamCipher for SymmetricCipher {
    fn update(&mut self, data: &[u8], out: &mut dyn BufMut) -> CipherResult<()> {
        let mut buf = BytesMut::from(data);
        process_in_place(&mut self.inner, &mut buf);
        out.put_slice(&buf);
        Ok(())
    }

    fn finalize(&mut self, _out: &mut dyn BufMut) -> CipherResult<()> {
        // These stream ciphers (CFB, CTR, CFB8) produce output 1-to-1 with input
        // and have no final block to flush.
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}
