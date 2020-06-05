use anyhow::Context;
use bytes::BytesMut;
use crypto::CipherType;
use ssclient::{decrypt_payload, encrypt_payload};
use std::io::Read;

pub fn decrypt_config<R: Read>(
    mut reader: R,
    cipher_type: CipherType,
    decrypt_key: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut content = String::new();
    let _size = reader
        .read_to_string(&mut content)
        .context("Read http response error")?;
    let b64decoded = base64::decode(content.trim().as_bytes()).context("base64 decode error")?;
    let mut output = BytesMut::new();
    let size = decrypt_payload(
        cipher_type,
        &cipher_type.bytes_to_key(decrypt_key.as_bytes()),
        &b64decoded,
        &mut output,
    )
    .context("decrypt payload error")?;
    Ok(output[..size].to_vec())
}

pub fn encrypt_config<R: Read>(
    mut reader: R,
    cipher_type: CipherType,
    encrypt_key: &str,
) -> anyhow::Result<String> {
    let mut buf = vec![];
    let size = reader.read_to_end(&mut buf)?;

    let mut output = BytesMut::new();
    let size = encrypt_payload(
        cipher_type,
        &cipher_type.bytes_to_key(encrypt_key.as_bytes()),
        &buf[..size],
        &mut output,
    )?;

    let content = base64::encode(&output[..size]);

    Ok(content)
}

#[cfg(test)]
mod tests {
    use crate::config_encryptor::{decrypt_config, encrypt_config};
    use crypto::CipherType;

    #[test]
    fn test_base64() {
        let content = "halsdjflwefjklasdjflkasdjf";
        let e = encrypt_config(content.as_bytes(), CipherType::ChaCha20Ietf, "test").unwrap();
        let d = decrypt_config(e.as_bytes(), CipherType::ChaCha20Ietf, "test").unwrap();
        assert_eq!(content, String::from_utf8(d).unwrap());
    }
}
