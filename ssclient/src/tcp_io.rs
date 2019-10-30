use crate::MAX_PACKET_SIZE;
use byteorder::BigEndian;
use bytes::ByteOrder;
use crypto::{BoxAeadDecryptor, BoxAeadEncryptor, CipherType};
use futures::{AsyncRead, AsyncReadExt};
use std::io::{ErrorKind, Result};

fn buffer_size(tag_size: usize, data: &[u8]) -> usize {
    2 + tag_size // len and len_tag
        + data.len() + tag_size // data and data_tag
}

pub(crate) fn aead_encrypted_write(
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

pub(crate) async fn aead_decrypted_read<T: AsyncRead + Unpin>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task;

    #[test]
    fn test_encrypt_and_decrypt_stream() {
        let cipher_type = CipherType::Aes256Gcm;
        let key = cipher_type.bytes_to_key("keasdfsdfy".as_bytes());
        let iv = cipher_type.gen_salt();
        let mut encrypter_cipher = crypto::new_aead_encryptor(cipher_type, &key, &iv);
        let mut decrypter_cipher = crypto::new_aead_decryptor(cipher_type, &key, &iv);

        let buf = "hello".as_bytes();
        let mut dst = [0; MAX_PACKET_SIZE];
        let mut tmp_buf = [0; MAX_PACKET_SIZE];
        let mut output = [0; MAX_PACKET_SIZE];

        let size =
            aead_encrypted_write(&mut encrypter_cipher, &buf, &mut dst, cipher_type).unwrap();

        task::block_on(async {
            let s = aead_decrypted_read(
                &mut decrypter_cipher,
                &dst[..size],
                &mut tmp_buf,
                &mut output,
                cipher_type,
            )
            .await
            .unwrap();
            assert_eq!(&output[..s], buf);
        })
    }
}
