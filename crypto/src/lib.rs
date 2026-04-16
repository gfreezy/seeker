//! Crypto methods for shadowsocks

pub use self::{
    aead::{
        new_aead_decryptor, new_aead_encryptor, AeadDecryptor, AeadEncryptor, BoxAeadDecryptor,
        BoxAeadEncryptor,
    },
    cipher::{CipherCategory, CipherResult, CipherType},
    stream::{new_stream, BoxStreamCipher, StreamCipher},
};

pub mod aead;
pub mod cipher;
pub mod digest;
pub mod dummy;
#[cfg(feature = "use-ring")]
pub mod ring;
#[cfg(feature = "miscreant")]
pub mod siv;
#[cfg(feature = "sodium")]
pub mod sodium;
pub mod stream;
#[cfg(any(feature = "aes-cfb", feature = "aes-ctr", feature = "camellia-cfb"))]
pub mod symmetric;
pub mod table;

/// Crypto mode, encrypt or decrypt
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CryptoMode {
    Encrypt,
    Decrypt,
}
