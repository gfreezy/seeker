//! AEAD packet I/O facilities
//!
//! AEAD protocol is defined in https://shadowsocks.org/en/spec/AEAD.html.
//!
//! ```plain
//! TCP request (before encryption)
//! +------+---------------------+------------------+
//! | ATYP | Destination Address | Destination Port |
//! +------+---------------------+------------------+
//! |  1   |       Variable      |         2        |
//! +------+---------------------+------------------+
//!
//! TCP request (after encryption, *ciphertext*)
//! +--------+--------------+------------------+--------------+---------------+
//! | NONCE  |  *HeaderLen* |   HeaderLen_TAG  |   *Header*   |  Header_TAG   |
//! +--------+--------------+------------------+--------------+---------------+
//! | Fixed  |       2      |       Fixed      |   Variable   |     Fixed     |
//! +--------+--------------+------------------+--------------+---------------+
//!
//! TCP Chunk (before encryption)
//! +----------+
//! |  DATA    |
//! +----------+
//! | Variable |
//! +----------+
//!
//! TCP Chunk (after encryption, *ciphertext*)
//! +--------------+---------------+--------------+------------+
//! |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
//! +--------------+---------------+--------------+------------+
//! |      2       |     Fixed     |   Variable   |   Fixed    |
//! +--------------+---------------+--------------+------------+
//! ```

use std::io::Result;
use std::{
    cmp, io,
    pin::Pin,
    slice,
    task::{Context, Poll},
    u16,
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::ready;

use crate::BUFFER_SIZE;
use async_std::io::{Read, Write};
use crypto::{self, BoxAeadDecryptor, BoxAeadEncryptor, CipherType};

/// AEAD packet payload must be smaller than 0x3FFF
const MAX_PACKET_SIZE: usize = 0x3FFF;

#[derive(Debug)]
enum DecryptReadStep {
    Length,
    Data(usize),
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<T> {
    conn: T,
    buffer: BytesMut,
    data: BytesMut,
    cipher: BoxAeadDecryptor,
    pos: usize,
    tag_size: usize,
    steps: DecryptReadStep,
    got_final: bool,
}

impl<T: Read + Write + Unpin> DecryptedReader<T> {
    pub fn new(conn: T, t: CipherType, key: &[u8], nonce: &[u8]) -> DecryptedReader<T> {
        DecryptedReader {
            conn,
            buffer: BytesMut::with_capacity(BUFFER_SIZE),
            data: BytesMut::with_capacity(BUFFER_SIZE),
            cipher: crypto::new_aead_decryptor(t, key, nonce),
            pos: 0,
            tag_size: t.tag_size(),
            steps: DecryptReadStep::Length,
            got_final: false,
        }
    }

    fn poll_read_decrypted(
        &mut self,
        ctx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        while self.pos >= self.data.len() {
            // Already received EOF
            if self.got_final {
                return Poll::Ready(Ok(0));
            }

            // Refill buffer
            match self.steps {
                DecryptReadStep::Length => ready!(self.poll_read_decrypted_length(ctx))?,
                DecryptReadStep::Data(len) => ready!(self.poll_read_decrypted_data(ctx, len))?,
            }
        }

        let remaining_len = self.data.len() - self.pos;
        let n = cmp::min(dst.len(), remaining_len);
        (&mut dst[..n]).copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(n))
    }

    fn poll_read_decrypted_length(&mut self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let buf_len = 2 + self.tag_size;
        ready!(self.poll_read_exact(ctx, buf_len, true))?;
        if self.got_final {
            return Poll::Ready(Ok(()));
        }

        // Done reading, decrypt it
        let len = {
            let mut len_buf = [0u8; 2];
            self.cipher.decrypt(&self.buffer[..], &mut len_buf)?;
            BigEndian::read_u16(&len_buf) as usize
        };

        // Clear buffer before overwriting it
        self.buffer.clear();
        self.data.clear();
        self.pos = 0;

        // Next step, read data
        self.steps = DecryptReadStep::Data(len);
        self.buffer.reserve(len + self.tag_size);
        self.data.reserve(len);

        Poll::Ready(Ok(()))
    }

    fn poll_read_decrypted_data(
        &mut self,
        ctx: &mut Context<'_>,
        size: usize,
    ) -> Poll<io::Result<()>> {
        let buf_len = size + self.tag_size;
        ready!(self.poll_read_exact(ctx, buf_len, false))?;

        // Done reading data, decrypt it
        unsafe {
            // It has enough space, I am sure about that
            let buffer =
                slice::from_raw_parts_mut(self.data.bytes_mut().as_mut_ptr() as *mut u8, size);
            self.cipher.decrypt(&self.buffer[..], buffer)?;

            // Move forward the pointer
            self.data.advance_mut(size);
        }

        // Clear buffer before overwriting it
        self.buffer.clear();

        // Reset read position
        self.pos = 0;

        // Next step, read length
        self.steps = DecryptReadStep::Length;
        self.buffer.reserve(2 + self.tag_size);

        Poll::Ready(Ok(()))
    }

    fn poll_read_exact(
        &mut self,
        ctx: &mut Context<'_>,
        size: usize,
        allow_eof: bool,
    ) -> Poll<io::Result<()>> {
        while self.buffer.len() < size {
            let remaining = size - self.buffer.len();
            unsafe {
                // It has enough space, I am sure about that
                let buffer = slice::from_raw_parts_mut(
                    self.buffer.bytes_mut().as_mut_ptr() as *mut u8,
                    remaining,
                );
                let n = ready!(Pin::new(&mut self.conn).poll_read(ctx, buffer))?;
                if n == 0 {
                    if self.buffer.is_empty() && allow_eof && !self.got_final {
                        // Read nothing
                        self.got_final = true;
                        return Poll::Ready(Ok(()));
                    } else {
                        use std::io::ErrorKind;
                        return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                    }
                }
                self.buffer.advance_mut(n);
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<T: Read + Write + Unpin> Read for DecryptedReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        (&mut *self).poll_read_decrypted(cx, buf)
    }
}

enum EncryptWriteStep {
    Nothing,
    Writing(BytesMut, usize),
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<T> {
    conn: T,
    cipher: BoxAeadEncryptor,
    tag_size: usize,
    steps: EncryptWriteStep,
    nonce: Option<Bytes>,
}

impl<T: Read + Write + Unpin> EncryptedWriter<T> {
    /// Creates a new EncryptedWriter
    pub fn new(conn: T, t: CipherType, key: &[u8], nonce: Bytes) -> EncryptedWriter<T> {
        EncryptedWriter {
            conn,
            cipher: crypto::new_aead_encryptor(t, key, &nonce),
            tag_size: t.tag_size(),
            steps: EncryptWriteStep::Nothing,
            nonce: Some(nonce),
        }
    }

    fn poll_write_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        mut data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Data.Len is a 16-bit big-endian integer indicating the length of Data. It must be smaller than 0x3FFF.
        if data.len() > MAX_PACKET_SIZE {
            data = &data[..MAX_PACKET_SIZE];
        }

        ready!(self.poll_write_all_encrypted(ctx, data))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_all_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<()>> {
        assert!(
            data.len() <= MAX_PACKET_SIZE,
            "buffer size too large, AEAD encryption protocol requires buffer to be smaller than 0x3FFF"
        );

        loop {
            match self.steps {
                EncryptWriteStep::Nothing => {
                    let output_length = self.buffer_size(data);
                    let data_length = data.len() as u16;

                    // Send the first packet with nonce
                    let nonce_length = match self.nonce {
                        Some(ref n) => n.len(),
                        None => 0,
                    };

                    let mut buf = BytesMut::with_capacity(nonce_length + output_length);

                    // Put nonce first
                    if let Some(n) = self.nonce.take() {
                        buf.extend(n);
                    }

                    let mut data_len_buf = [0u8; 2];
                    BigEndian::write_u16(&mut data_len_buf, data_length);

                    unsafe {
                        let b = slice::from_raw_parts_mut(
                            buf.bytes_mut().as_mut_ptr() as *mut u8,
                            output_length,
                        );

                        let output_length_size = 2 + self.tag_size;
                        self.cipher
                            .encrypt(&data_len_buf, &mut b[..output_length_size]);
                        self.cipher
                            .encrypt(data, &mut b[output_length_size..output_length]);

                        buf.advance_mut(output_length);
                    }

                    self.steps = EncryptWriteStep::Writing(buf, 0);
                }
                EncryptWriteStep::Writing(ref mut buf, ref mut pos) => {
                    while *pos < buf.len() {
                        let n = ready!(Pin::new(&mut self.conn).poll_write(ctx, &buf[*pos..]))?;
                        if n == 0 {
                            use std::io::ErrorKind;
                            return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                        }
                        *pos += n;
                    }

                    self.steps = EncryptWriteStep::Nothing;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        2 + self.tag_size // len and len_tag
            + data.len() + self.tag_size // data and data_tag
    }
}

impl<T: Read + Write + Unpin> Write for EncryptedWriter<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        (&mut *self).poll_write_encrypted(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut (*self).conn).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut (*self).conn).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{DecryptedReader, EncryptedWriter};
    use async_std::io::Cursor;
    use async_std::prelude::*;
    use async_std::task::block_on;
    use bytes::Bytes;
    use crypto::CipherType;

    #[test]
    fn test_write() {
        block_on(async move {
            let method = CipherType::ChaCha20IetfPoly1305;
            let password = "GwEU01uXWm0Pp6t08";
            let key = method.bytes_to_key(password.as_bytes());
            let nonce = method.gen_salt();
            let mut buf = Cursor::new(Vec::new());
            let mut writer = EncryptedWriter::new(&mut buf, method, &key, nonce.clone());
            let data = b"hello";
            writer.write_all(data).await.unwrap();
            buf.set_position(0);
            let encrypted = encrypt(method, key, nonce.clone(), data);
            assert_eq!(&buf.get_ref()[nonce.len()..], encrypted.as_slice());
        });
    }

    #[test]
    fn test_read() {
        block_on(async move {
            let method = CipherType::ChaCha20IetfPoly1305;
            let password = "GwEU01uXWm0Pp6t08";
            let key = method.bytes_to_key(password.as_bytes());
            let nonce = method.gen_salt();
            let data = b"hello";
            let output = encrypt(method, key.clone(), nonce.clone(), data);
            let mut reader = DecryptedReader::new(Cursor::new(output), method, &key, &nonce);
            let mut buf = vec![];
            reader.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.as_slice(), data)
        });
    }

    #[test]
    fn test_encrypt_decrypt() {
        let method = CipherType::ChaCha20IetfPoly1305;
        let password = "GwEU01uXWm0Pp6t08";
        let key = method.bytes_to_key(password.as_bytes());
        let nonce = method.gen_salt();
        let data = b"hello";
        let output = encrypt(method, key.clone(), nonce.clone(), data);
        assert_eq!(decrypt(method, key, nonce, &output).as_slice(), data);
    }

    fn encrypt(method: CipherType, key: Bytes, nonce: Bytes, data: &[u8]) -> Vec<u8> {
        let data_len = data.len();
        let tag_size = method.tag_size();
        let buf_size = 2 + tag_size // len and len_tag
                + data_len + tag_size; // data and data_tag
        let length_buf = (data_len as u16).to_be_bytes();
        let length_buf_len = length_buf.len();

        let mut size = 0;
        let mut right_buf = vec![0; buf_size];
        let mut encryptor = crypto::new_aead_encryptor(method, &key, &nonce);
        encryptor.encrypt(
            &length_buf,
            &mut right_buf[size..size + tag_size + length_buf_len],
        );
        size += tag_size + length_buf_len;
        encryptor.encrypt(data, &mut right_buf[size..size + tag_size + data_len]);
        size += tag_size + data_len;
        assert_eq!(size, buf_size);
        right_buf
    }

    fn decrypt(method: CipherType, key: Bytes, nonce: Bytes, data: &[u8]) -> Vec<u8> {
        let tag_size = method.tag_size();

        let mut right_buf = vec![0; 1024];
        let mut encryptor = crypto::new_aead_decryptor(method, &key, &nonce);
        let mut length = [0; 2];
        encryptor
            .decrypt(&data[..2 + tag_size], &mut length)
            .unwrap();
        let len = u16::from_be_bytes(length) as usize;
        encryptor
            .decrypt(&data[2 + tag_size..], &mut right_buf[..len])
            .unwrap();
        right_buf.truncate(len);
        right_buf
    }
}
