//! Stream protocol implementation

use std::{
    cmp, io,
    pin::Pin,
    task::{Context, Poll},
};

use async_std::io::{Read, Write};
use async_std::task::ready;
use bytes::{BufMut, Bytes, BytesMut};
use crypto::{new_stream, BoxStreamCipher, CipherType, CryptoMode};
use std::io::Result;

use crate::BUFFER_SIZE;

const DUMMY_BUFFER: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<T> {
    conn: T,
    buffer: BytesMut,
    cipher: BoxStreamCipher,
    pos: usize,
    got_final: bool,
    incoming_buffer: Vec<u8>,
}

impl<T: Read + Write + Unpin> DecryptedReader<T> {
    pub fn new(conn: T, t: CipherType, key: &[u8], iv: &[u8]) -> DecryptedReader<T> {
        let cipher = new_stream(t, key, iv, CryptoMode::Decrypt);
        let buffer_size = cipher.buffer_size(&DUMMY_BUFFER);
        DecryptedReader {
            conn,
            buffer: BytesMut::with_capacity(buffer_size),
            cipher,
            pos: 0,
            got_final: false,
            incoming_buffer: vec![0u8; BUFFER_SIZE],
        }
    }

    fn poll_read_decrypted(
        &mut self,
        ctx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        while self.pos >= self.buffer.len() {
            if self.got_final {
                return Poll::Ready(Ok(0));
            }

            let n = ready!(Pin::new(&mut self.conn).poll_read(ctx, &mut self.incoming_buffer))?;

            // Reset pointers
            self.buffer.clear();
            self.pos = 0;

            if n == 0 {
                // Finialize block
                self.buffer.reserve(self.buffer_size(&[]));
                self.cipher.finalize(&mut self.buffer)?;
                self.got_final = true;
            } else {
                let data = &self.incoming_buffer[..n];
                // Ensure we have enough space
                let buffer_len = self.buffer_size(data);
                self.buffer.reserve(buffer_len);
                self.cipher.update(data, &mut self.buffer)?;
            }
        }

        let remaining_len = self.buffer.len() - self.pos;
        let n = cmp::min(dst.len(), remaining_len);
        (&mut dst[..n]).copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(n))
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.buffer_size(data)
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
    cipher: BoxStreamCipher,
    steps: EncryptWriteStep,
    iv: Option<Bytes>,
}

impl<T: Read + Write + Unpin> EncryptedWriter<T> {
    /// Creates a new EncryptedWriter
    pub fn new(conn: T, t: CipherType, key: &[u8], iv: Bytes) -> EncryptedWriter<T> {
        EncryptedWriter {
            conn,
            cipher: new_stream(t, key, &iv, CryptoMode::Encrypt),
            steps: EncryptWriteStep::Nothing,
            iv: Some(iv),
        }
    }

    fn poll_write_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_write_all_encrypted(ctx, data))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_all_encrypted(
        &mut self,
        ctx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<()>> {
        // FIXME: How about finalize?

        loop {
            match self.steps {
                EncryptWriteStep::Nothing => {
                    // Send the first packet with iv
                    let iv_length = match self.iv {
                        Some(ref i) => i.len(),
                        None => 0,
                    };

                    let mut buf = BytesMut::with_capacity(iv_length + self.buffer_size(data));

                    // Put iv first
                    if let Some(i) = self.iv.take() {
                        buf.extend(i);
                    }

                    self.cipher_update(data, &mut buf)?;

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

    fn cipher_update<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        self.cipher.update(data, buf).map_err(From::from)
    }

    #[allow(dead_code)]
    fn cipher_finalize<B: BufMut>(&mut self, buf: &mut B) -> io::Result<()> {
        self.cipher.finalize(buf).map_err(From::from)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.buffer_size(data)
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
    use crypto::{CipherType, CryptoMode};

    #[test]
    fn test_write() {
        block_on(async move {
            let method = CipherType::ChaCha20Ietf;
            let password = "GwEU01uXWm0Pp6t08";
            let key = method.bytes_to_key(password.as_bytes());
            let nonce = method.gen_init_vec();
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
            let method = CipherType::ChaCha20Ietf;
            let password = "GwEU01uXWm0Pp6t08";
            let key = method.bytes_to_key(password.as_bytes());
            let nonce = method.gen_init_vec();
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
        let method = CipherType::ChaCha20Ietf;
        let password = "GwEU01uXWm0Pp6t08";
        let key = method.bytes_to_key(password.as_bytes());
        let nonce = method.gen_init_vec();
        let data = b"hello";
        let output = encrypt(method, key.clone(), nonce.clone(), data);
        assert_eq!(decrypt(method, key, nonce, &output).as_slice(), data);
    }

    fn encrypt(method: CipherType, key: Bytes, nonce: Bytes, data: &[u8]) -> Vec<u8> {
        let mut encryptor = crypto::new_stream(method, &key, &nonce, CryptoMode::Encrypt);
        let mut right_buf = Vec::new();
        encryptor.update(data, &mut right_buf).unwrap();
        right_buf
    }

    fn decrypt(method: CipherType, key: Bytes, nonce: Bytes, data: &[u8]) -> Vec<u8> {
        let mut decryptor = crypto::new_stream(method, &key, &nonce, CryptoMode::Decrypt);
        let buf_size = decryptor.buffer_size(data);
        let mut buf = Vec::with_capacity(buf_size);
        decryptor.update(data, &mut buf).unwrap();
        buf
    }
}
