use crate::crypto::{VMessDataCipher, VMessEncryptMethod};
use crate::protocol::fnv1a;
use bytes::{BufMut, BytesMut};
use std::cmp;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum payload per chunk (before encryption overhead).
const MAX_CHUNK_PAYLOAD: usize = 16384;

// ─── ChunkReader ─────────────────────────────────────────────

#[derive(Debug)]
enum ReadStep {
    Length,
    Data(usize),
}

/// Reads and decrypts VMess standard data stream chunks.
pub struct ChunkReader {
    method: VMessEncryptMethod,
    cipher: VMessDataCipher,
    /// Accumulation buffer for reading from the underlying stream.
    raw_buf: BytesMut,
    /// Decrypted data ready for the caller.
    data: BytesMut,
    data_pos: usize,
    step: ReadStep,
    got_eof: bool,
}

impl ChunkReader {
    pub fn new(method: VMessEncryptMethod, cipher: VMessDataCipher) -> Self {
        Self {
            method,
            cipher,
            raw_buf: BytesMut::with_capacity(4096),
            data: BytesMut::with_capacity(4096),
            data_pos: 0,
            step: ReadStep::Length,
            got_eof: false,
        }
    }

    /// Poll-based read that decrypts data and returns plaintext.
    pub fn poll_read_decrypted<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        // Return buffered data first
        while self.data_pos >= self.data.len() {
            if self.got_eof {
                return Poll::Ready(Ok(()));
            }

            match self.step {
                ReadStep::Length => ready!(self.poll_read_length(cx, reader))?,
                ReadStep::Data(len) => ready!(self.poll_read_data(cx, reader, len))?,
            }
        }

        let remaining = self.data.len() - self.data_pos;
        let n = cmp::min(dst.remaining(), remaining);
        dst.put_slice(&self.data[self.data_pos..self.data_pos + n]);
        self.data_pos += n;
        Poll::Ready(Ok(()))
    }

    fn poll_read_length<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
    ) -> Poll<Result<()>> {
        let needed = if self.method.is_aead() {
            2 + 16 // 2-byte length sealed with 16-byte AEAD tag
        } else {
            2 // raw 2 bytes (encrypted with CFB stream or plaintext)
        };

        ready!(self.poll_read_exact(cx, reader, needed, true))?;
        if self.got_eof {
            return Poll::Ready(Ok(()));
        }

        let length = if self.method.is_aead() {
            // AEAD: open the sealed 2-byte length
            if let VMessDataCipher::Aead(ref mut aead) = self.cipher {
                let plaintext = aead.open(&self.raw_buf[..needed])?;
                u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize
            } else {
                unreachable!()
            }
        } else if let VMessDataCipher::Cfb(ref mut cfb) = self.cipher {
            // CFB: decrypt 2 bytes through the streaming cipher
            let mut len_buf = [0u8; 2];
            cfb.update(&self.raw_buf[..2], &mut len_buf)?;
            u16::from_be_bytes(len_buf) as usize
        } else {
            // None: read raw 2 bytes
            u16::from_be_bytes([self.raw_buf[0], self.raw_buf[1]]) as usize
        };

        self.raw_buf.clear();

        if length == 0 {
            self.got_eof = true;
            return Poll::Ready(Ok(()));
        }

        self.data.clear();
        self.data_pos = 0;
        self.step = ReadStep::Data(length);

        Poll::Ready(Ok(()))
    }

    fn poll_read_data<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        size: usize,
    ) -> Poll<Result<()>> {
        let needed = if self.method.is_aead() {
            size + 16 // payload + AEAD tag
        } else {
            size // already includes FNV1a overhead for CFB
        };

        ready!(self.poll_read_exact(cx, reader, needed, false))?;

        match &mut self.cipher {
            VMessDataCipher::Aead(aead) => {
                let plaintext = aead.open(&self.raw_buf[..needed])?;
                self.data.extend_from_slice(&plaintext);
            }
            VMessDataCipher::Cfb(cfb) => {
                let mut decrypted = vec![0u8; size];
                cfb.update(&self.raw_buf[..size], &mut decrypted)?;

                // First 4 bytes are FNV1a checksum, rest is payload
                if size < 4 {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidData,
                        "CFB chunk too short for FNV1a",
                    )));
                }
                let checksum =
                    u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
                let payload = &decrypted[4..];
                let expected = fnv1a(payload);
                if checksum != expected {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidData,
                        "FNV1a checksum mismatch",
                    )));
                }
                self.data.extend_from_slice(payload);
            }
            VMessDataCipher::None => {
                self.data.extend_from_slice(&self.raw_buf[..size]);
            }
        }

        self.raw_buf.clear();
        self.data_pos = 0;
        self.step = ReadStep::Length;

        Poll::Ready(Ok(()))
    }

    /// Read exactly `size` bytes from the underlying reader into `raw_buf`.
    fn poll_read_exact<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        size: usize,
        allow_eof: bool,
    ) -> Poll<Result<()>> {
        self.raw_buf
            .reserve(size.saturating_sub(self.raw_buf.len()));

        while self.raw_buf.len() < size {
            let remaining = size - self.raw_buf.len();
            let mut buf = vec![0u8; remaining];
            let mut read_buf = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut *reader).poll_read(cx, &mut read_buf))?;
            let n = read_buf.filled().len();
            if n == 0 {
                if self.raw_buf.is_empty() && allow_eof && !self.got_eof {
                    self.got_eof = true;
                    return Poll::Ready(Ok(()));
                } else {
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
            }
            self.raw_buf.put_slice(&buf[..n]);
        }

        Poll::Ready(Ok(()))
    }
}

// ─── ChunkWriter ─────────────────────────────────────────────

enum WriteStep {
    Idle,
    Writing { buf: BytesMut, pos: usize },
}

/// Encrypts and writes VMess standard data stream chunks.
pub struct ChunkWriter {
    method: VMessEncryptMethod,
    cipher: VMessDataCipher,
    step: WriteStep,
}

impl ChunkWriter {
    pub fn new(method: VMessEncryptMethod, cipher: VMessDataCipher) -> Self {
        Self {
            method,
            cipher,
            step: WriteStep::Idle,
        }
    }

    /// Encrypt data into a chunk and write it.
    pub fn poll_write_encrypted<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
        data: &[u8],
    ) -> Poll<Result<usize>> {
        loop {
            match &mut self.step {
                WriteStep::Idle => {
                    if data.is_empty() {
                        return Poll::Ready(Ok(0));
                    }

                    let payload_len = cmp::min(data.len(), MAX_CHUNK_PAYLOAD);
                    let payload = &data[..payload_len];
                    let chunk = self.encrypt_chunk(payload)?;

                    self.step = WriteStep::Writing {
                        buf: BytesMut::from(chunk.as_slice()),
                        pos: 0,
                    };

                    // Fall through to write
                    // We'll return payload_len (original data consumed) once the chunk is fully written
                }
                WriteStep::Writing { buf, pos } => {
                    let remaining = &buf[*pos..];
                    let n = ready!(Pin::new(&mut *writer).poll_write(cx, remaining))?;
                    if n == 0 {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::WriteZero,
                            "write returned 0",
                        )));
                    }
                    *pos += n;
                    if *pos >= buf.len() {
                        // Chunk fully written, figure out how much original data was consumed
                        let buf_len = buf.len();
                        let consumed = compute_payload_len(self.method, buf_len);
                        self.step = WriteStep::Idle;
                        return Poll::Ready(Ok(consumed));
                    }
                    // Keep writing the rest of the chunk
                }
            }
        }
    }

    pub fn poll_flush_encrypted<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<Result<()>> {
        // Flush any pending writes first
        if let WriteStep::Writing { buf, pos } = &mut self.step {
            while *pos < buf.len() {
                let remaining = &buf[*pos..];
                let n = ready!(Pin::new(&mut *writer).poll_write(cx, remaining))?;
                if n == 0 {
                    return Poll::Ready(Err(Error::new(ErrorKind::WriteZero, "write returned 0")));
                }
                *pos += n;
            }
            self.step = WriteStep::Idle;
        }
        Pin::new(writer).poll_flush(cx)
    }

    pub fn poll_shutdown_encrypted<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<Result<()>> {
        Pin::new(writer).poll_shutdown(cx)
    }

    fn encrypt_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        match &mut self.cipher {
            VMessDataCipher::Aead(aead) => {
                let len_bytes = (payload.len() as u16).to_be_bytes();
                let sealed_len = aead.seal(&len_bytes)?;
                let sealed_data = aead.seal(payload)?;
                let mut chunk = Vec::with_capacity(sealed_len.len() + sealed_data.len());
                chunk.extend_from_slice(&sealed_len);
                chunk.extend_from_slice(&sealed_data);
                Ok(chunk)
            }
            VMessDataCipher::Cfb(cfb) => {
                // Length includes 4 bytes of FNV1a
                let total_len = (payload.len() + 4) as u16;
                let len_bytes = total_len.to_be_bytes();
                let checksum = fnv1a(payload).to_be_bytes();

                // Build plaintext: length + FNV1a + payload
                let mut plaintext = Vec::with_capacity(2 + 4 + payload.len());
                plaintext.extend_from_slice(&len_bytes);
                plaintext.extend_from_slice(&checksum);
                plaintext.extend_from_slice(payload);

                // Encrypt everything through the streaming CFB
                let mut encrypted = vec![0u8; plaintext.len()];
                cfb.update(&plaintext, &mut encrypted)?;
                Ok(encrypted)
            }
            VMessDataCipher::None => {
                let len_bytes = (payload.len() as u16).to_be_bytes();
                let mut chunk = Vec::with_capacity(2 + payload.len());
                chunk.extend_from_slice(&len_bytes);
                chunk.extend_from_slice(payload);
                Ok(chunk)
            }
        }
    }
}

/// Determine original payload size from the encrypted chunk size.
fn compute_payload_len(method: VMessEncryptMethod, buf_len: usize) -> usize {
    match method {
        VMessEncryptMethod::Aes128Gcm | VMessEncryptMethod::ChaCha20Poly1305 => {
            // sealed_len(18) + sealed_data(payload + 16) = 34 + payload
            buf_len.saturating_sub(34)
        }
        VMessEncryptMethod::Aes128Cfb => {
            // encrypted(2 + 4 + payload) = 6 + payload
            buf_len.saturating_sub(6)
        }
        VMessEncryptMethod::None => {
            // 2 + payload
            buf_len.saturating_sub(2)
        }
    }
}
