use crate::crypto::{VMessDataCipher, VMessEncryptMethod};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;

/// Decrypt an AES-128-GCM ciphertext with AAD; tag must be appended to ciphertext
/// by the caller (standard AEAD convention).
fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("AES-GCM key: {e}")))?;
    let mut joined = Vec::with_capacity(ct.len() + tag.len());
    joined.extend_from_slice(ct);
    joined.extend_from_slice(tag);
    cipher
        .decrypt(nonce.into(), Payload { msg: &joined, aad })
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("AEAD decrypt: {e}")))
}
use crate::protocol::{
    build_command, decrypt_aead_response_header, decrypt_response_header, derive_command_key,
    derive_response_iv, derive_response_iv_aead, derive_response_key, derive_response_key_aead,
    encrypt_command, generate_auth, parse_uuid, seal_vmess_aead_header, CMD_TCP,
};
use crate::stream::{ChunkReader, ChunkWriter};
use config::Address;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// VMess TCP stream with encrypted chunked data framing.
pub struct VMessTcpStream {
    conn: TcpStream,
    // Read state (response direction)
    reader: ChunkReader,
    response_parsed: bool,
    is_aead: bool,
    resp_header_key: [u8; 16],
    resp_header_iv: [u8; 16],
    expected_auth_v: u8,
    resp_header_buf: Vec<u8>,
    // Write state (request direction)
    writer: ChunkWriter,
}

impl VMessTcpStream {
    /// Connect to a VMess server and establish an encrypted tunnel.
    pub async fn connect(
        server: SocketAddr,
        uuid: &str,
        addr: Address,
        encrypt_method: &str,
    ) -> Result<Self> {
        let user_id = parse_uuid(uuid)?;
        let method = VMessEncryptMethod::from_str_name(encrypt_method)?;
        // AEAD header format is determined by alterId, not encryption method.
        // Modern VMess (alterId=0) always uses AEAD headers regardless of data cipher.
        let is_aead = true;

        // Timestamp (current UTC seconds)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::other(format!("system time error: {e}")))?
            .as_secs();

        // Generate random session values
        let mut data_key = [0u8; 16];
        let mut data_iv = [0u8; 16];
        let resp_auth_v: u8 = rand::random();
        rand::fill(&mut data_key[..]);
        rand::fill(&mut data_iv[..]);

        // Build command header plaintext
        let command = build_command(&data_iv, &data_key, resp_auth_v, method, CMD_TCP, &addr);
        let cmd_key = derive_command_key(&user_id);

        // Build handshake bytes
        let handshake = if is_aead {
            // AEAD header format: auth_id + sealed_length + nonce + sealed_command
            seal_vmess_aead_header(&cmd_key, &command)?
        } else {
            // Legacy header format: HMAC-MD5 auth + AES-128-CFB encrypted command
            let auth = generate_auth(&user_id, timestamp);
            let cmd_iv = crate::protocol::derive_command_iv(timestamp);
            let encrypted_cmd = encrypt_command(&cmd_key, &cmd_iv, &command)?;
            let mut h = Vec::with_capacity(16 + encrypted_cmd.len());
            h.extend_from_slice(&auth);
            h.extend_from_slice(&encrypted_cmd);
            h
        };

        // Connect and send handshake
        let mut tcp_stream = TcpStream::connect(server).await?;
        tcp_stream.set_nodelay(true)?;
        tcp_stream.write_all(&handshake).await?;

        // Derive response key/IV (AEAD uses SHA256, legacy uses MD5)
        let (resp_key, resp_iv) = if is_aead {
            (
                derive_response_key_aead(&data_key),
                derive_response_iv_aead(&data_iv),
            )
        } else {
            (derive_response_key(&data_key), derive_response_iv(&data_iv))
        };

        // Initialize write cipher (request direction: uses original data_key/data_iv)
        let write_cipher = VMessDataCipher::new_encrypt(method, &data_key, &data_iv)?;
        let writer = ChunkWriter::new(method, write_cipher, &data_iv);

        // Initialize read cipher (response direction: uses derived resp_key/resp_iv)
        let read_cipher = VMessDataCipher::new_decrypt(method, &resp_key, &resp_iv)?;
        let reader = ChunkReader::new(method, read_cipher, &resp_iv);

        Ok(VMessTcpStream {
            conn: tcp_stream,
            reader,
            response_parsed: false,
            is_aead,
            resp_header_key: resp_key,
            resp_header_iv: resp_iv,
            expected_auth_v: resp_auth_v,
            resp_header_buf: Vec::new(),
            writer,
        })
    }

    /// Read and parse the response header (called lazily on first read).
    fn poll_read_response_header(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.is_aead {
            self.poll_read_aead_response_header(cx)
        } else {
            self.poll_read_legacy_response_header(cx)
        }
    }

    /// Legacy response header: 4 bytes AES-128-CFB encrypted.
    fn poll_read_legacy_response_header(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        while self.resp_header_buf.len() < 4 {
            let remaining = 4 - self.resp_header_buf.len();
            let mut buf = vec![0u8; remaining];
            let mut read_buf = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut self.conn).poll_read(cx, &mut read_buf))?;
            let n = read_buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "connection closed before response header",
                )));
            }
            self.resp_header_buf.extend_from_slice(&buf[..n]);
        }

        let header = decrypt_response_header(
            &self.resp_header_key,
            &self.resp_header_iv,
            &self.resp_header_buf,
        )?;

        if header.auth_v != self.expected_auth_v {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "response auth mismatch: expected 0x{:02x}, got 0x{:02x}",
                    self.expected_auth_v, header.auth_v
                ),
            )));
        }

        self.response_parsed = true;
        Poll::Ready(Ok(()))
    }

    /// AEAD response header: sealed_length(18) + sealed_payload(len+16).
    fn poll_read_aead_response_header(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        // Phase 1: Read sealed length (18 bytes)
        if self.resp_header_buf.len() < 18 {
            while self.resp_header_buf.len() < 18 {
                let remaining = 18 - self.resp_header_buf.len();
                let mut buf = vec![0u8; remaining];
                let mut read_buf = ReadBuf::new(&mut buf);
                ready!(Pin::new(&mut self.conn).poll_read(cx, &mut read_buf))?;
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "connection closed before AEAD response header",
                    )));
                }
                self.resp_header_buf.extend_from_slice(&buf[..n]);
            }
        }

        // Once we have 18 bytes, decrypt length to know how many more bytes to read
        if self.resp_header_buf.len() == 18 {
            // Peek at the length to determine total header size
            let len_key = crate::kdf::vmess_kdf16(
                &self.resp_header_key,
                crate::kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
            );
            let len_iv = &crate::kdf::vmess_kdf_1_one_shot(
                &self.resp_header_iv,
                crate::kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
            )[..12];

            let (len_ct, len_tag) = self.resp_header_buf[..18].split_at(2);
            let len_plain = aes_gcm_decrypt(&len_key, len_iv, &[], len_ct, len_tag)
                .map_err(|e| Error::other(format!("AEAD resp header len: {e}")))?;

            let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            // Reserve space for the full header: 18 + header_len + 16(tag)
            let total = 18 + header_len + 16;
            self.resp_header_buf.reserve(total - 18);
            // Mark that we've decoded the length by extending the buffer to indicate we need more
            // Continue to phase 2 below
        }

        // Phase 2: Read the remaining payload bytes
        // Total size = 18 + header_len + 16
        // We need to figure out header_len from what we decoded...
        // Re-derive since we don't store it
        let total_needed = {
            let len_key = crate::kdf::vmess_kdf16(
                &self.resp_header_key,
                crate::kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
            );
            let len_iv = &crate::kdf::vmess_kdf_1_one_shot(
                &self.resp_header_iv,
                crate::kdf::KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
            )[..12];

            let (len_ct, len_tag) = self.resp_header_buf[..18].split_at(2);
            let len_plain = aes_gcm_decrypt(&len_key, len_iv, &[], len_ct, len_tag)
                .map_err(|e| Error::other(format!("AEAD resp header len: {e}")))?;

            let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            18 + header_len + 16
        };

        while self.resp_header_buf.len() < total_needed {
            let remaining = total_needed - self.resp_header_buf.len();
            let mut buf = vec![0u8; remaining];
            let mut read_buf = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut self.conn).poll_read(cx, &mut read_buf))?;
            let n = read_buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "connection closed during AEAD response header payload",
                )));
            }
            self.resp_header_buf.extend_from_slice(&buf[..n]);
        }

        // Decrypt the full AEAD response header
        let header_bytes = decrypt_aead_response_header(
            &self.resp_header_key,
            &self.resp_header_iv,
            &self.resp_header_buf,
        )?;

        if header_bytes.is_empty() || header_bytes[0] != self.expected_auth_v {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "AEAD response auth mismatch: expected 0x{:02x}, got 0x{:02x}",
                    self.expected_auth_v,
                    header_bytes.first().copied().unwrap_or(0)
                ),
            )));
        }

        self.response_parsed = true;
        tracing::debug!(
            bytes = self.resp_header_buf.len(),
            "AEAD response header parsed"
        );
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VMessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let me = &mut *self;

        // Parse response header on first read
        if !me.response_parsed {
            ready!(me.poll_read_response_header(cx))?;
        }

        // Delegate to chunk reader
        me.reader.poll_read_decrypted(cx, &mut me.conn, buf)
    }
}

impl AsyncWrite for VMessTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let me = &mut *self;
        me.writer.poll_write_encrypted(cx, &mut me.conn, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let me = &mut *self;
        me.writer.poll_flush_encrypted(cx, &mut me.conn)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let me = &mut *self;
        me.writer.poll_shutdown_encrypted(cx, &mut me.conn)
    }
}
