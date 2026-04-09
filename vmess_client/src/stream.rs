use crate::crypto::{VMessDataCipher, VMessEncryptMethod};
use crate::protocol::fnv1a;
use bytes::{BufMut, BytesMut};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::cmp;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum payload per chunk (before encryption overhead).
const MAX_CHUNK_PAYLOAD: usize = 0x4000;

// ─── ShakeSizeParser ────────────────────────────────────────

/// Shake128-based size encoder/decoder for VMess AEAD chunk masking.
/// The size field is: `Shake128-masked u16` + 16 zero bytes = 18 bytes total.
struct ShakeSizeParser {
    reader: sha3::Shake128Reader,
}

impl ShakeSizeParser {
    fn new(iv: &[u8]) -> Self {
        let mut hasher = sha3::Shake128::default();
        hasher.update(iv);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    fn encode(&mut self, size: u16, buf: &mut [u8]) {
        let size_bytes = size.to_be_bytes();
        let mut mask = [0u8; 2];
        XofReader::read(&mut self.reader, &mut mask);
        buf[0] = size_bytes[0] ^ mask[0];
        buf[1] = size_bytes[1] ^ mask[1];
    }

    fn decode(&mut self, buf: &[u8]) -> u16 {
        let mut mask = [0u8; 2];
        XofReader::read(&mut self.reader, &mut mask);
        u16::from_be_bytes([buf[0] ^ mask[0], buf[1] ^ mask[1]])
    }
}

// ─── ChunkReader ─────────────────────────────────────────────

#[derive(Debug)]
enum ReadStep {
    Length,
    Data(usize, usize), // (size_after_unpadding, padding_size)
}

/// Reads and decrypts VMess standard data stream chunks.
pub struct ChunkReader {
    method: VMessEncryptMethod,
    cipher: VMessDataCipher,
    size_parser: Option<ShakeSizeParser>, // Some for AEAD, None for others
    raw_buf: BytesMut,
    data: BytesMut,
    data_pos: usize,
    step: ReadStep,
    got_eof: bool,
}

impl ChunkReader {
    pub fn new(method: VMessEncryptMethod, cipher: VMessDataCipher, resp_iv: &[u8]) -> Self {
        let size_parser = if method.is_aead() {
            Some(ShakeSizeParser::new(resp_iv))
        } else {
            None
        };
        Self {
            method,
            cipher,
            size_parser,
            raw_buf: BytesMut::with_capacity(4096),
            data: BytesMut::with_capacity(4096),
            data_pos: 0,
            step: ReadStep::Length,
            got_eof: false,
        }
    }

    pub fn poll_read_decrypted<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        while self.data_pos >= self.data.len() {
            if self.got_eof {
                return Poll::Ready(Ok(()));
            }
            match self.step {
                ReadStep::Length => ready!(self.poll_read_length(cx, reader))?,
                ReadStep::Data(size, padding) => {
                    ready!(self.poll_read_data(cx, reader, size, padding))?
                }
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
        let needed = 2; // All chunk size fields are 2 bytes (plain, CFB-encrypted, or Shake-masked)

        ready!(self.poll_read_exact(cx, reader, needed, true))?;
        if self.got_eof {
            return Poll::Ready(Ok(()));
        }

        let (length, padding) = if let Some(ref mut sp) = self.size_parser {
            let size = sp.decode(&self.raw_buf[..needed]) as usize;
            let padding = 0; // No OPTION_P, no padding
            (size, padding)
        } else if let VMessDataCipher::Cfb(ref mut cfb) = self.cipher {
            let mut len_buf = [0u8; 2];
            cfb.update(&self.raw_buf[..2], &mut len_buf)?;
            (u16::from_be_bytes(len_buf) as usize, 0)
        } else {
            // None encryption
            (
                u16::from_be_bytes([self.raw_buf[0], self.raw_buf[1]]) as usize,
                0,
            )
        };

        self.raw_buf.clear();

        // EOF: for AEAD, size == tag_len means empty payload
        let tag_size = self.method.tag_size();
        let eof = if self.method.is_aead() {
            length <= tag_size + padding
        } else {
            length == 0
        };
        if eof {
            self.got_eof = true;
            return Poll::Ready(Ok(()));
        }

        self.data.clear();
        self.data_pos = 0;
        // For AEAD: length = data_len + tag_len + padding_len
        // We read `length` bytes, then strip padding and AEAD-open
        self.step = ReadStep::Data(length, padding);

        Poll::Ready(Ok(()))
    }

    fn poll_read_data<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        size: usize,
        padding: usize,
    ) -> Poll<Result<()>> {
        ready!(self.poll_read_exact(cx, reader, size, false))?;

        match &mut self.cipher {
            VMessDataCipher::Aead(aead) => {
                // size = data_len + tag_len + padding
                let encrypted_size = size - padding;
                let plaintext = aead.open(&self.raw_buf[..encrypted_size])?;
                self.data.extend_from_slice(&plaintext);
            }
            VMessDataCipher::Cfb(cfb) => {
                let mut decrypted = vec![0u8; size];
                cfb.update(&self.raw_buf[..size], &mut decrypted)?;
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
    Writing {
        buf: BytesMut,
        pos: usize,
        payload_len: usize,
    },
}

/// Encrypts and writes VMess standard data stream chunks.
pub struct ChunkWriter {
    method: VMessEncryptMethod,
    cipher: VMessDataCipher,
    size_parser: Option<ShakeSizeParser>,
    step: WriteStep,
}

impl ChunkWriter {
    pub fn new(method: VMessEncryptMethod, cipher: VMessDataCipher, req_iv: &[u8]) -> Self {
        let size_parser = if method.is_aead() {
            Some(ShakeSizeParser::new(req_iv))
        } else {
            None
        };
        Self {
            method,
            cipher,
            size_parser,
            step: WriteStep::Idle,
        }
    }

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

                    let tag_len = self.method.tag_size();
                    let padding_len = 0; // No OPTION_P, no padding
                    let max_payload = MAX_CHUNK_PAYLOAD - tag_len - padding_len;
                    let payload_len = cmp::min(data.len(), max_payload);
                    let payload = &data[..payload_len];
                    let chunk = self.encrypt_chunk(payload, padding_len)?;

                    self.step = WriteStep::Writing {
                        buf: BytesMut::from(chunk.as_slice()),
                        pos: 0,
                        payload_len,
                    };
                }
                WriteStep::Writing {
                    buf,
                    pos,
                    payload_len,
                } => {
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
                        let consumed = *payload_len;
                        self.step = WriteStep::Idle;
                        return Poll::Ready(Ok(consumed));
                    }
                }
            }
        }
    }

    pub fn poll_flush_encrypted<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<Result<()>> {
        if let WriteStep::Writing { buf, pos, .. } = &mut self.step {
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

    fn encrypt_chunk(&mut self, payload: &[u8], padding_len: usize) -> Result<Vec<u8>> {
        match &mut self.cipher {
            VMessDataCipher::Aead(aead) => {
                // Size field: Shake-masked u16(payload_len + tag_len + padding_len)
                let total_data_len = payload.len() + 16 + padding_len;
                let mut size_field = [0u8; 2];
                if let Some(ref mut sp) = self.size_parser {
                    sp.encode(total_data_len as u16, &mut size_field);
                }

                // Encrypted payload
                let sealed_data = aead.seal(payload)?;

                // Assemble: size_field(2) + sealed_data(payload+16) + padding
                let mut chunk = Vec::with_capacity(2 + sealed_data.len() + padding_len);
                chunk.extend_from_slice(&size_field);
                chunk.extend_from_slice(&sealed_data);
                if padding_len > 0 {
                    let padding: Vec<u8> = (0..padding_len).map(|_| rand::random()).collect();
                    chunk.extend_from_slice(&padding);
                }
                Ok(chunk)
            }
            VMessDataCipher::Cfb(cfb) => {
                let total_len = (payload.len() + 4) as u16;
                let len_bytes = total_len.to_be_bytes();
                let checksum = fnv1a(payload).to_be_bytes();

                let mut plaintext = Vec::with_capacity(2 + 4 + payload.len());
                plaintext.extend_from_slice(&len_bytes);
                plaintext.extend_from_slice(&checksum);
                plaintext.extend_from_slice(payload);

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
