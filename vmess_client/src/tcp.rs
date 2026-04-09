use crate::crypto::{VMessDataCipher, VMessEncryptMethod};
use crate::protocol::{
    build_command, decrypt_response_header, derive_command_iv, derive_command_key,
    derive_response_iv, derive_response_key, encrypt_command, generate_auth, parse_uuid, CMD_TCP,
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

        // Build auth credential
        let auth = generate_auth(&user_id, timestamp);

        // Build and encrypt command header
        let command = build_command(&data_iv, &data_key, resp_auth_v, method, CMD_TCP, &addr);
        let cmd_key = derive_command_key(&user_id);
        let cmd_iv = derive_command_iv(timestamp);
        let encrypted_cmd = encrypt_command(&cmd_key, &cmd_iv, &command)?;

        // Connect and send handshake
        let mut tcp_stream = TcpStream::connect(server).await?;
        tcp_stream.set_nodelay(true)?;

        let mut handshake = Vec::with_capacity(16 + encrypted_cmd.len());
        handshake.extend_from_slice(&auth);
        handshake.extend_from_slice(&encrypted_cmd);
        tcp_stream.write_all(&handshake).await?;

        // Derive response key/IV
        let resp_key = derive_response_key(&data_key);
        let resp_iv = derive_response_iv(&data_iv);

        // Initialize write cipher (request direction: uses original data_key/data_iv)
        let write_cipher = VMessDataCipher::new_encrypt(method, &data_key, &data_iv)?;
        let writer = ChunkWriter::new(method, write_cipher);

        // Initialize read cipher (response direction: uses derived resp_key/resp_iv)
        let read_cipher = VMessDataCipher::new_decrypt(method, &resp_key, &resp_iv)?;
        let reader = ChunkReader::new(method, read_cipher);

        Ok(VMessTcpStream {
            conn: tcp_stream,
            reader,
            response_parsed: false,
            resp_header_key: resp_key,
            resp_header_iv: resp_iv,
            expected_auth_v: resp_auth_v,
            resp_header_buf: Vec::new(),
            writer,
        })
    }

    /// Read and parse the 4-byte response header (called lazily on first read).
    fn poll_read_response_header(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
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

        // Decrypt and validate response header
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
