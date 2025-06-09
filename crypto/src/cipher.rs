//! Ciphers

use std::{
    fmt::{self, Debug, Display},
    io, mem,
    str::{self, FromStr},
};

use crate::digest::{self, Digest, DigestType};
use bytes::{BufMut, Bytes, BytesMut};
#[cfg(feature = "camellia-cfb")]
use openssl::nid::Nid;
#[cfg(feature = "openssl")]
use openssl::symm;
use rand::RngCore;
#[cfg(feature = "use-ring")]
use ring::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

/// Cipher result
pub type CipherResult<T> = Result<T, Error>;

/// Cipher error
pub enum Error {
    UnknownCipherType,
    #[cfg(feature = "openssl")]
    OpenSSLError(::openssl::error::ErrorStack),
    IoError(io::Error),
    AeadDecryptFailed,
    SodiumError,
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            #[cfg(feature = "openssl")]
            Error::OpenSSLError(ref err) => write!(f, "{err:?}"),
            Error::IoError(ref err) => write!(f, "{err:?}"),
            Error::AeadDecryptFailed => write!(f, "AEAD decrypt failed"),
            Error::SodiumError => write!(f, "Sodium error"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            #[cfg(feature = "openssl")]
            Error::OpenSSLError(ref err) => write!(f, "{err}"),
            Error::IoError(ref err) => write!(f, "{err}"),
            Error::AeadDecryptFailed => write!(f, "AeadDecryptFailed"),
            Error::SodiumError => write!(f, "sodium error"),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::UnknownCipherType => io::Error::other("unknown cipher type"),
            #[cfg(feature = "openssl")]
            Error::OpenSSLError(err) => From::from(err),
            Error::IoError(err) => err,
            Error::AeadDecryptFailed => io::Error::other("AEAD decrypt error"),
            Error::SodiumError => io::Error::other("sodium error"),
        }
    }
}

#[cfg(feature = "openssl")]
impl From<::openssl::error::ErrorStack> for Error {
    fn from(e: ::openssl::error::ErrorStack) -> Error {
        Error::OpenSSLError(e)
    }
}

#[cfg(feature = "aes-cfb")]
const CIPHER_AES_128_CFB: &str = "aes-128-cfb";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_128_CFB_1: &str = "aes-128-cfb1";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_128_CFB_8: &str = "aes-128-cfb8";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_128_CFB_128: &str = "aes-128-cfb128";

#[cfg(feature = "aes-cfb")]
const CIPHER_AES_192_CFB: &str = "aes-192-cfb";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_192_CFB_1: &str = "aes-192-cfb1";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_192_CFB_8: &str = "aes-192-cfb8";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_192_CFB_128: &str = "aes-192-cfb128";

#[cfg(feature = "aes-cfb")]
const CIPHER_AES_256_CFB: &str = "aes-256-cfb";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_256_CFB_1: &str = "aes-256-cfb1";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_256_CFB_8: &str = "aes-256-cfb8";
#[cfg(feature = "aes-cfb")]
const CIPHER_AES_256_CFB_128: &str = "aes-256-cfb128";

#[cfg(feature = "aes-ctr")]
const CIPHER_AES_128_CTR: &str = "aes-128-ctr";
#[cfg(feature = "aes-ctr")]
const CIPHER_AES_192_CTR: &str = "aes-192-ctr";
#[cfg(feature = "aes-ctr")]
const CIPHER_AES_256_CTR: &str = "aes-256-ctr";

#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_128_CFB: &str = "camellia-128-cfb";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_192_CFB: &str = "camellia-192-cfb";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_256_CFB: &str = "camellia-256-cfb";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_128_CFB_1: &str = "camellia-128-cfb1";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_192_CFB_1: &str = "camellia-192-cfb1";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_256_CFB_1: &str = "camellia-256-cfb1";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_128_CFB_8: &str = "camellia-128-cfb8";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_192_CFB_8: &str = "camellia-192-cfb8";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_256_CFB_8: &str = "camellia-256-cfb8";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_128_CFB_128: &str = "camellia-128-cfb128";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_192_CFB_128: &str = "camellia-192-cfb128";
#[cfg(feature = "camellia-cfb")]
const CIPHER_CAMELLIA_256_CFB_128: &str = "camellia-256-cfb128";

#[cfg(feature = "rc4")]
const CIPHER_RC4: &str = "rc4";
#[cfg(feature = "rc4")]
const CIPHER_RC4_MD5: &str = "rc4-md5";

const CIPHER_TABLE: &str = "table";

#[cfg(feature = "sodium")]
const CIPHER_CHACHA20: &str = "chacha20";
#[cfg(feature = "sodium")]
const CIPHER_SALSA20: &str = "salsa20";
#[cfg(feature = "sodium")]
const CIPHER_XSALSA20: &str = "xsalsa20";
#[cfg(feature = "sodium")]
const CIPHER_CHACHA20_IETF: &str = "chacha20-ietf";

#[cfg(feature = "miscreant")]
const CIPHER_AES_128_PMAC_SIV: &str = "aes-128-pmac-siv";
#[cfg(feature = "miscreant")]
const CIPHER_AES_256_PMAC_SIV: &str = "aes-256-pmac-siv";

const CIPHER_PLAIN: &str = "plain";

#[cfg(feature = "use-ring")]
const CIPHER_AES_128_GCM: &str = "aes-128-gcm";
#[cfg(feature = "use-ring")]
const CIPHER_AES_256_GCM: &str = "aes-256-gcm";
#[cfg(feature = "use-ring")]
const CIPHER_CHACHA20_IETF_POLY1305: &str = "chacha20-ietf-poly1305";
#[cfg(feature = "sodium")]
const CIPHER_XCHACHA20_IETF_POLY1305: &str = "xchacha20-ietf-poly1305";

/// ShadowSocks cipher type
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum CipherType {
    Table,
    Plain,

    #[cfg(feature = "aes-cfb")]
    Aes128Cfb,
    #[cfg(feature = "aes-cfb")]
    Aes128Cfb1,
    #[cfg(feature = "aes-cfb")]
    Aes128Cfb8,
    #[cfg(feature = "aes-cfb")]
    Aes128Cfb128,

    #[cfg(feature = "aes-cfb")]
    Aes192Cfb,
    #[cfg(feature = "aes-cfb")]
    Aes192Cfb1,
    #[cfg(feature = "aes-cfb")]
    Aes192Cfb8,
    #[cfg(feature = "aes-cfb")]
    Aes192Cfb128,

    #[cfg(feature = "aes-cfb")]
    Aes256Cfb,
    #[cfg(feature = "aes-cfb")]
    Aes256Cfb1,
    #[cfg(feature = "aes-cfb")]
    Aes256Cfb8,
    #[cfg(feature = "aes-cfb")]
    Aes256Cfb128,

    #[cfg(feature = "aes-ctr")]
    Aes128Ctr,
    #[cfg(feature = "aes-ctr")]
    Aes192Ctr,
    #[cfg(feature = "aes-ctr")]
    Aes256Ctr,

    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb,
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb,
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb,
    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb1,
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb1,
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb1,
    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb8,
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb8,
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb8,
    #[cfg(feature = "camellia-cfb")]
    Camellia128Cfb128,
    #[cfg(feature = "camellia-cfb")]
    Camellia192Cfb128,
    #[cfg(feature = "camellia-cfb")]
    Camellia256Cfb128,

    #[cfg(feature = "rc4")]
    Rc4,
    #[cfg(feature = "rc4")]
    Rc4Md5,

    #[cfg(feature = "sodium")]
    ChaCha20,
    #[cfg(feature = "sodium")]
    Salsa20,
    #[cfg(feature = "sodium")]
    XSalsa20,
    #[cfg(feature = "sodium")]
    ChaCha20Ietf,

    #[cfg(feature = "use-ring")]
    Aes128Gcm,
    #[cfg(feature = "use-ring")]
    Aes256Gcm,

    #[cfg(feature = "use-ring")]
    ChaCha20IetfPoly1305,
    #[cfg(feature = "sodium")]
    XChaCha20IetfPoly1305,

    #[cfg(feature = "miscreant")]
    Aes128PmacSiv,
    #[cfg(feature = "miscreant")]
    Aes256PmacSiv,
}

/// Category of ciphers
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CipherCategory {
    /// Stream ciphers is used for OLD ShadowSocks protocol, which uses stream ciphers to encrypt data payloads
    Stream,
    /// AEAD ciphers is used in modern ShadowSocks protocol, which sends data in separate packets
    Aead,
}

impl CipherType {
    /// Symmetric crypto key size
    pub fn key_size(self) -> usize {
        match self {
            CipherType::Table | CipherType::Plain => 0,

            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1().key_len(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb8 => symm::Cipher::aes_128_cfb8().key_len(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb | CipherType::Aes128Cfb128 => {
                symm::Cipher::aes_128_cfb128().key_len()
            }
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb1 => symm::Cipher::aes_192_cfb1().key_len(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb8 => symm::Cipher::aes_192_cfb8().key_len(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb | CipherType::Aes192Cfb128 => {
                symm::Cipher::aes_192_cfb128().key_len()
            }
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1().key_len(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb8 => symm::Cipher::aes_256_cfb8().key_len(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb | CipherType::Aes256Cfb128 => {
                symm::Cipher::aes_256_cfb128().key_len()
            }

            #[cfg(feature = "aes-ctr")]
            CipherType::Aes128Ctr => symm::Cipher::aes_128_ctr().key_len(),
            #[cfg(feature = "aes-ctr")]
            CipherType::Aes192Ctr => symm::Cipher::aes_192_ctr().key_len(),
            #[cfg(feature = "aes-ctr")]
            CipherType::Aes256Ctr => symm::Cipher::aes_256_ctr().key_len(),

            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB128)
                .expect("openssl doesn't support camellia-128-cfb")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb1 => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB1)
                .expect("openssl doesn't support camellia-128-cfb1")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb8 => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB8)
                .expect("openssl doesn't support camellia-128-cfb8")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB128)
                .expect("openssl doesn't support camellia-128-cfb128")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB128)
                .expect("openssl doesn't support camellia-192-cfb")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb1 => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB1)
                .expect("openssl doesn't support camellia-192-cfb1")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb8 => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB8)
                .expect("openssl doesn't support camellia-192-cfb8")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB128)
                .expect("openssl doesn't support camellia-192-cfb128")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB128)
                .expect("openssl doesn't support camellia-256-cfb")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb1 => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB1)
                .expect("openssl doesn't support camellia-256-cfb1")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb8 => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB8)
                .expect("openssl doesn't support camellia-256-cfb8")
                .key_len(),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB128)
                .expect("openssl doesn't support camellia-256-cfb128")
                .key_len(),

            #[cfg(feature = "rc4")]
            CipherType::Rc4 | CipherType::Rc4Md5 => symm::Cipher::rc4().key_len(),

            #[cfg(feature = "sodium")]
            CipherType::ChaCha20
            | CipherType::Salsa20
            | CipherType::XSalsa20
            | CipherType::ChaCha20Ietf => 32,

            #[cfg(feature = "use-ring")]
            CipherType::Aes128Gcm => AES_128_GCM.key_len(),
            #[cfg(feature = "use-ring")]
            CipherType::Aes256Gcm => AES_256_GCM.key_len(),

            #[cfg(feature = "use-ring")]
            CipherType::ChaCha20IetfPoly1305 => CHACHA20_POLY1305.key_len(),

            #[cfg(feature = "sodium")]
            CipherType::XChaCha20IetfPoly1305 => 32,

            #[cfg(feature = "miscreant")]
            CipherType::Aes128PmacSiv => 32,
            #[cfg(feature = "miscreant")]
            CipherType::Aes256PmacSiv => 64,
        }
    }

    fn classic_bytes_to_key(self, key: &[u8]) -> Bytes {
        let iv_len = self.iv_size();
        let key_len = self.key_size();

        if iv_len + key_len == 0 {
            return Bytes::new();
        }

        let mut digest = digest::with_type(DigestType::Md5);

        let total_loop = (key_len + iv_len).div_ceil(digest.digest_len());
        let m_length = digest.digest_len() + key.len();

        let mut result = BytesMut::with_capacity(total_loop * digest.digest_len());
        let mut m = BytesMut::with_capacity(key.len());

        for _ in 0..total_loop {
            let mut vkey = mem::replace(&mut m, BytesMut::with_capacity(m_length));
            vkey.put(key);

            digest.update(&vkey);
            digest.digest_reset(&mut m);

            result.put_slice(&m);
        }

        result.truncate(key_len);
        result.freeze()
    }

    /// Extends key to match the required key length
    pub fn bytes_to_key(self, key: &[u8]) -> Bytes {
        self.classic_bytes_to_key(key)
    }

    /// Symmetric crypto initialize vector size
    pub fn iv_size(self) -> usize {
        match self {
            CipherType::Table | CipherType::Plain => 0,

            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb8 => symm::Cipher::aes_128_cfb8()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb | CipherType::Aes128Cfb128 => symm::Cipher::aes_128_cfb128()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb1 => symm::Cipher::aes_192_cfb1()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb8 => symm::Cipher::aes_192_cfb8()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb | CipherType::Aes192Cfb128 => symm::Cipher::aes_192_cfb128()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb8 => symm::Cipher::aes_256_cfb8()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb | CipherType::Aes256Cfb128 => symm::Cipher::aes_256_cfb128()
                .iv_len()
                .expect("iv_len should not be None"),

            #[cfg(feature = "aes-ctr")]
            CipherType::Aes128Ctr => symm::Cipher::aes_128_ctr()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-ctr")]
            CipherType::Aes192Ctr => symm::Cipher::aes_192_ctr()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "aes-ctr")]
            CipherType::Aes256Ctr => symm::Cipher::aes_256_ctr()
                .iv_len()
                .expect("iv_len should not be None"),

            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB128)
                .expect("openssl doesn't support camellia-128-cfb")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb1 => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB1)
                .expect("openssl doesn't support camellia-128-cfb1")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb8 => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB8)
                .expect("openssl doesn't support camellia-128-cfb8")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB128)
                .expect("openssl doesn't support camellia-128-cfb128")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB128)
                .expect("openssl doesn't support camellia-192-cfb")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb1 => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB1)
                .expect("openssl doesn't support camellia-192-cfb1")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb8 => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB8)
                .expect("openssl doesn't support camellia-192-cfb8")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB128)
                .expect("openssl doesn't support camellia-192-cfb128")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB128)
                .expect("openssl doesn't support camellia-256-cfb")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb1 => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB1)
                .expect("openssl doesn't support camellia-256-cfb1")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb8 => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB8)
                .expect("openssl doesn't support camellia-256-cfb8")
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB128)
                .expect("openssl doesn't support camellia-256-cfb128")
                .iv_len()
                .expect("iv_len should not be None"),

            #[cfg(feature = "rc4")]
            CipherType::Rc4 => symm::Cipher::rc4()
                .iv_len()
                .expect("iv_len should not be None"),
            #[cfg(feature = "rc4")]
            CipherType::Rc4Md5 => 16,

            #[cfg(feature = "sodium")]
            CipherType::ChaCha20 | CipherType::Salsa20 => 8,
            #[cfg(feature = "sodium")]
            CipherType::XSalsa20 => 24,
            #[cfg(feature = "sodium")]
            CipherType::ChaCha20Ietf => 12,

            #[cfg(feature = "use-ring")]
            CipherType::Aes128Gcm => AES_128_GCM.nonce_len(),
            #[cfg(feature = "use-ring")]
            CipherType::Aes256Gcm => AES_256_GCM.nonce_len(),
            #[cfg(feature = "use-ring")]
            CipherType::ChaCha20IetfPoly1305 => CHACHA20_POLY1305.nonce_len(),
            #[cfg(feature = "sodium")]
            CipherType::XChaCha20IetfPoly1305 => 24,

            #[cfg(feature = "miscreant")]
            CipherType::Aes128PmacSiv => 8,
            #[cfg(feature = "miscreant")]
            CipherType::Aes256PmacSiv => 8,
        }
    }

    fn gen_random_bytes(len: usize) -> Bytes {
        let mut iv = BytesMut::with_capacity(len);
        unsafe {
            iv.set_len(len);
        }

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut iv);
        iv.freeze()
    }

    /// Generate a random initialize vector for this cipher
    pub fn gen_init_vec(self) -> Bytes {
        let iv_len = self.iv_size();
        CipherType::gen_random_bytes(iv_len)
    }

    /// Get category of cipher
    pub fn category(self) -> CipherCategory {
        match self {
            #[cfg(feature = "use-ring")]
            CipherType::Aes128Gcm | CipherType::Aes256Gcm | CipherType::ChaCha20IetfPoly1305 => {
                CipherCategory::Aead
            }

            #[cfg(feature = "sodium")]
            CipherType::XChaCha20IetfPoly1305 => CipherCategory::Aead,

            #[cfg(feature = "miscreant")]
            CipherType::Aes128PmacSiv | CipherType::Aes256PmacSiv => CipherCategory::Aead,

            _ => CipherCategory::Stream,
        }
    }

    /// Get tag size for AEAD Ciphers
    pub fn tag_size(self) -> usize {
        assert!(self.category() == CipherCategory::Aead);

        match self {
            #[cfg(feature = "use-ring")]
            CipherType::Aes128Gcm => AES_128_GCM.tag_len(),
            #[cfg(feature = "use-ring")]
            CipherType::Aes256Gcm => AES_256_GCM.tag_len(),
            #[cfg(feature = "use-ring")]
            CipherType::ChaCha20IetfPoly1305 => CHACHA20_POLY1305.tag_len(),
            #[cfg(feature = "sodium")]
            CipherType::XChaCha20IetfPoly1305 => 16,

            #[cfg(feature = "miscreant")]
            CipherType::Aes128PmacSiv | CipherType::Aes256PmacSiv => 16,

            _ => panic!("only support AEAD ciphers, found {self:?}"),
        }
    }

    /// Get nonce size for AEAD ciphers
    pub fn salt_size(self) -> usize {
        assert!(self.category() == CipherCategory::Aead);
        self.key_size()
    }

    /// Get salt for AEAD ciphers
    pub fn gen_salt(self) -> Bytes {
        CipherType::gen_random_bytes(self.salt_size())
    }
}

impl FromStr for CipherType {
    type Err = Error;

    fn from_str(s: &str) -> Result<CipherType, Error> {
        match s {
            CIPHER_TABLE | "" => Ok(CipherType::Table),
            CIPHER_PLAIN => Ok(CipherType::Plain),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_128_CFB => Ok(CipherType::Aes128Cfb),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_128_CFB_1 => Ok(CipherType::Aes128Cfb1),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_128_CFB_8 => Ok(CipherType::Aes128Cfb8),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_128_CFB_128 => Ok(CipherType::Aes128Cfb128),

            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_192_CFB => Ok(CipherType::Aes192Cfb),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_192_CFB_1 => Ok(CipherType::Aes192Cfb1),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_192_CFB_8 => Ok(CipherType::Aes192Cfb8),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_192_CFB_128 => Ok(CipherType::Aes192Cfb128),

            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_256_CFB => Ok(CipherType::Aes256Cfb),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_256_CFB_1 => Ok(CipherType::Aes256Cfb1),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_256_CFB_8 => Ok(CipherType::Aes256Cfb8),
            #[cfg(feature = "aes-cfb")]
            CIPHER_AES_256_CFB_128 => Ok(CipherType::Aes256Cfb128),

            #[cfg(feature = "aes-ctr")]
            CIPHER_AES_128_CTR => Ok(CipherType::Aes128Ctr),
            #[cfg(feature = "aes-ctr")]
            CIPHER_AES_192_CTR => Ok(CipherType::Aes192Ctr),
            #[cfg(feature = "aes-ctr")]
            CIPHER_AES_256_CTR => Ok(CipherType::Aes256Ctr),

            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_128_CFB => Ok(CipherType::Camellia128Cfb),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_128_CFB_1 => Ok(CipherType::Camellia128Cfb1),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_128_CFB_8 => Ok(CipherType::Camellia128Cfb8),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_128_CFB_128 => Ok(CipherType::Camellia128Cfb128),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_192_CFB => Ok(CipherType::Camellia192Cfb),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_192_CFB_1 => Ok(CipherType::Camellia192Cfb1),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_192_CFB_8 => Ok(CipherType::Camellia192Cfb8),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_192_CFB_128 => Ok(CipherType::Camellia192Cfb128),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_256_CFB => Ok(CipherType::Camellia256Cfb),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_256_CFB_1 => Ok(CipherType::Camellia256Cfb1),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_256_CFB_8 => Ok(CipherType::Camellia256Cfb8),
            #[cfg(feature = "camellia-cfb")]
            CIPHER_CAMELLIA_256_CFB_128 => Ok(CipherType::Camellia256Cfb128),

            #[cfg(feature = "rc4")]
            CIPHER_RC4 => Ok(CipherType::Rc4),
            #[cfg(feature = "rc4")]
            CIPHER_RC4_MD5 => Ok(CipherType::Rc4Md5),

            #[cfg(feature = "sodium")]
            CIPHER_CHACHA20 => Ok(CipherType::ChaCha20),
            #[cfg(feature = "sodium")]
            CIPHER_SALSA20 => Ok(CipherType::Salsa20),
            #[cfg(feature = "sodium")]
            CIPHER_XSALSA20 => Ok(CipherType::XSalsa20),
            #[cfg(feature = "sodium")]
            CIPHER_CHACHA20_IETF => Ok(CipherType::ChaCha20Ietf),

            #[cfg(feature = "use-ring")]
            CIPHER_AES_128_GCM => Ok(CipherType::Aes128Gcm),
            #[cfg(feature = "use-ring")]
            CIPHER_AES_256_GCM => Ok(CipherType::Aes256Gcm),

            #[cfg(feature = "use-ring")]
            CIPHER_CHACHA20_IETF_POLY1305 => Ok(CipherType::ChaCha20IetfPoly1305),
            #[cfg(feature = "sodium")]
            CIPHER_XCHACHA20_IETF_POLY1305 => Ok(CipherType::XChaCha20IetfPoly1305),

            #[cfg(feature = "miscreant")]
            CIPHER_AES_128_PMAC_SIV => Ok(CipherType::Aes128PmacSiv),
            #[cfg(feature = "miscreant")]
            CIPHER_AES_256_PMAC_SIV => Ok(CipherType::Aes256PmacSiv),

            _ => Err(Error::UnknownCipherType),
        }
    }
}

impl Display for CipherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherType::Table => write!(f, "{CIPHER_TABLE}"),
            CipherType::Plain => write!(f, "{CIPHER_PLAIN}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb => write!(f, "{CIPHER_AES_128_CFB}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb1 => write!(f, "{CIPHER_AES_128_CFB_1}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb8 => write!(f, "{CIPHER_AES_128_CFB_8}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb128 => write!(f, "{CIPHER_AES_128_CFB_128}"),

            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb => write!(f, "{CIPHER_AES_192_CFB}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb1 => write!(f, "{CIPHER_AES_192_CFB_1}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb8 => write!(f, "{CIPHER_AES_192_CFB_8}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes192Cfb128 => write!(f, "{CIPHER_AES_192_CFB_128}"),

            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb => write!(f, "{CIPHER_AES_256_CFB}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb1 => write!(f, "{CIPHER_AES_256_CFB_1}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb8 => write!(f, "{CIPHER_AES_256_CFB_8}"),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb128 => write!(f, "{CIPHER_AES_256_CFB_128}"),

            #[cfg(feature = "aes-ctr")]
            CipherType::Aes128Ctr => write!(f, "{CIPHER_AES_128_CTR}"),
            #[cfg(feature = "aes-ctr")]
            CipherType::Aes192Ctr => write!(f, "{CIPHER_AES_192_CTR}"),
            #[cfg(feature = "aes-ctr")]
            CipherType::Aes256Ctr => write!(f, "{CIPHER_AES_256_CTR}"),

            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb => write!(f, "{CIPHER_CAMELLIA_128_CFB}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb1 => write!(f, "{CIPHER_CAMELLIA_128_CFB_1}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb8 => write!(f, "{CIPHER_CAMELLIA_128_CFB_8}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia128Cfb128 => write!(f, "{CIPHER_CAMELLIA_128_CFB_128}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb => write!(f, "{CIPHER_CAMELLIA_192_CFB}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb1 => write!(f, "{CIPHER_CAMELLIA_192_CFB_1}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb8 => write!(f, "{CIPHER_CAMELLIA_192_CFB_8}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia192Cfb128 => write!(f, "{CIPHER_CAMELLIA_192_CFB_128}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb => write!(f, "{CIPHER_CAMELLIA_256_CFB}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb1 => write!(f, "{CIPHER_CAMELLIA_256_CFB_1}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb8 => write!(f, "{CIPHER_CAMELLIA_256_CFB_8}"),
            #[cfg(feature = "camellia-cfb")]
            CipherType::Camellia256Cfb128 => write!(f, "{CIPHER_CAMELLIA_256_CFB_128}"),

            #[cfg(feature = "rc4")]
            CipherType::Rc4 => write!(f, "{CIPHER_RC4}"),
            #[cfg(feature = "rc4")]
            CipherType::Rc4Md5 => write!(f, "{CIPHER_RC4_MD5}"),

            #[cfg(feature = "sodium")]
            CipherType::ChaCha20 => write!(f, "{CIPHER_CHACHA20}"),
            #[cfg(feature = "sodium")]
            CipherType::Salsa20 => write!(f, "{CIPHER_SALSA20}"),
            #[cfg(feature = "sodium")]
            CipherType::XSalsa20 => write!(f, "{CIPHER_XSALSA20}"),
            #[cfg(feature = "sodium")]
            CipherType::ChaCha20Ietf => write!(f, "{CIPHER_CHACHA20_IETF}"),

            #[cfg(feature = "use-ring")]
            CipherType::Aes128Gcm => write!(f, "{CIPHER_AES_128_GCM}"),
            #[cfg(feature = "use-ring")]
            CipherType::Aes256Gcm => write!(f, "{CIPHER_AES_256_GCM}"),
            #[cfg(feature = "use-ring")]
            CipherType::ChaCha20IetfPoly1305 => write!(f, "{CIPHER_CHACHA20_IETF_POLY1305}"),
            #[cfg(feature = "sodium")]
            CipherType::XChaCha20IetfPoly1305 => write!(f, "{CIPHER_XCHACHA20_IETF_POLY1305}"),

            #[cfg(feature = "miscreant")]
            CipherType::Aes128PmacSiv => write!(f, "{}", CIPHER_AES_128_PMAC_SIV),
            #[cfg(feature = "miscreant")]
            CipherType::Aes256PmacSiv => write!(f, "{}", CIPHER_AES_256_PMAC_SIV),
        }
    }
}

#[cfg(test)]
mod test_cipher {
    use crate::{new_stream, CipherType, CryptoMode};

    #[test]
    fn test_get_cipher() {
        let key = CipherType::ChaCha20.bytes_to_key(b"PassWORD");
        let iv = CipherType::ChaCha20.gen_init_vec();
        let mut encryptor = new_stream(
            CipherType::ChaCha20,
            &key[0..],
            &iv[0..],
            CryptoMode::Encrypt,
        );
        let mut decryptor = new_stream(
            CipherType::ChaCha20,
            &key[0..],
            &iv[0..],
            CryptoMode::Decrypt,
        );
        let message = "HELLO WORLD";

        let mut encrypted_msg = Vec::new();
        encryptor
            .update(message.as_bytes(), &mut encrypted_msg)
            .unwrap();
        let mut decrypted_msg = Vec::new();
        decryptor
            .update(&encrypted_msg[..], &mut decrypted_msg)
            .unwrap();

        assert!(message.as_bytes() == &decrypted_msg[..]);
    }

    #[cfg(feature = "rc4")]
    #[test]
    fn test_rc4_md5_key_iv() {
        let ty = CipherType::Rc4Md5;
        assert_eq!(ty.key_size(), 16);
        assert_eq!(ty.iv_size(), 16);
    }
}
