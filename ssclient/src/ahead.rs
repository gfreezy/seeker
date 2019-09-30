use crate::MAX_PACKET_SIZE;
use byteorder::BigEndian;
use bytes::ByteOrder;
use crypto::{BoxAeadDecryptor, BoxAeadEncryptor, CipherType};
use futures::{AsyncRead, AsyncReadExt};
use std::io::{Error, ErrorKind, Result};

fn buffer_size(tag_size: usize, data: &[u8]) -> usize {
    2 + tag_size // len and len_tag
        + data.len() + tag_size // data and data_tag
}

pub(crate) async fn ahead_encrypted_write(
    cipher: &mut BoxAeadEncryptor,
    buf: &[u8],
    dst: &mut [u8],
    t: CipherType,
) -> Result<usize> {
    let tag_size = t.tag_size();

    assert!(
        buf.len() <= MAX_PACKET_SIZE,
        "Buffer size too large, AEAD encryption protocol requires buffer to be smaller than 0x3FFF"
    );

    let output_length = buffer_size(tag_size, buf);
    let data_length = buf.len() as u16;
    let mut data_len_buf = [0u8; 2];
    BigEndian::write_u16(&mut data_len_buf, data_length);

    let output_length_size = 2 + tag_size;
    cipher.encrypt(&data_len_buf, &mut dst[..output_length_size]);
    cipher.encrypt(buf, &mut dst[output_length_size..output_length]);

    Ok(output_length)
}

pub(crate) async fn ahead_decrypted_read<T: AsyncRead + Unpin>(
    cipher: &mut BoxAeadDecryptor,
    mut src: T,
    tmp_buf: &mut [u8],
    output: &mut [u8],
    t: CipherType,
) -> Result<usize> {
    let tag_size = t.tag_size();
    src.read_exact(&mut tmp_buf[..2 + tag_size]).await?;
    let mut len_buf = [0u8; 2];
    cipher.decrypt(&tmp_buf[..2 + tag_size], &mut len_buf)?;
    let len = BigEndian::read_u16(&len_buf) as usize;
    if len > MAX_PACKET_SIZE {
        return Err(ErrorKind::InvalidData.into());
    }

    src.read_exact(&mut tmp_buf[..len + tag_size]).await?;
    cipher.decrypt(&tmp_buf[..len + tag_size], &mut output[..len])?;
    Ok(len)
}

#[allow(dead_code)]
pub fn encrypt_payload_aead(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let salt = t.gen_salt();
    let tag_size = t.tag_size();
    let mut cipher = crypto::new_aead_encryptor(t, key, &salt);

    let salt_len = salt.len();
    output[..salt_len].copy_from_slice(&salt);

    cipher.encrypt(
        payload,
        &mut output[salt_len..salt_len + payload.len() + tag_size],
    );

    Ok(salt_len + payload.len() + tag_size)
}

#[allow(dead_code)]
fn decrypt_payload_aead(
    t: CipherType,
    key: &[u8],
    payload: &[u8],
    output: &mut [u8],
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

    cipher.decrypt(data, &mut output[..data_length])?;

    Ok(data_length)
}
