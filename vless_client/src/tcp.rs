use crate::protocol::{encode_vless_request, CMD_TCP, VLESS_VERSION};
use crate::tls::get_tls_connector;
use crate::vision::{VisionFilter, COMMAND_PADDING_DIRECT};
use bytes::BytesMut;
use config::Address;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;
use std::io::{BufRead, Error, ErrorKind, Read, Result, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use uuid::Uuid;

static CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn normalize_flow(flow: Option<&str>) -> Result<Option<&'static str>> {
    match flow {
        None | Some("") => Ok(None),
        Some("xtls-rprx-vision") | Some("xtls-rprx-vision-udp443") => Ok(Some("xtls-rprx-vision")),
        Some(other) => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("unsupported VLESS flow: {other}"),
        )),
    }
}

pub struct VlessTcpStream {
    id: u64,
    tcp: TcpStream,
    /// Outer TLS session. `None` when both read and write are in Direct mode.
    tls: Option<ClientConnection>,
    /// XTLS-Vision padding filter (None for plain VLESS).
    vision: Option<VisionFilter>,

    // --- Mode tracking (independent read/write) ---
    read_direct: bool,
    write_direct: bool,

    // --- Response header parsing ---
    /// Whether VLESS response header has been consumed.
    response_header_parsed: bool,
    /// For Vision mode: accumulates unpadded data until response header is complete.
    response_buf: Vec<u8>,

    // --- Read buffers ---
    /// Overflow app data from a previous read (after Vision unpad + response parse).
    read_buf: Vec<u8>,
    read_offset: usize,

    // --- Write buffers ---
    /// Encrypted TLS data waiting to be written to TCP.
    tls_write_pending: Vec<u8>,
    tls_write_offset: usize,
    /// Padded Vision frame waiting to be TLS-encrypted and sent.
    write_buf: Vec<u8>,
    write_offset: usize,
    write_pending_plain_len: usize,
}

impl VlessTcpStream {
    pub async fn connect(
        server: SocketAddr,
        sni: &str,
        addr: Address,
        uuid: &str,
        flow: Option<&str>,
        insecure: bool,
    ) -> Result<Self> {
        let connector = get_tls_connector(insecure);
        let flow = normalize_flow(flow)?;

        let uuid_parsed =
            Uuid::parse_str(uuid).map_err(|e| Error::other(format!("invalid VLESS uuid: {e}")))?;

        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| Error::other(format!("invalid SNI: {e}")))?;

        let tcp_stream = TcpStream::connect(server).await?;
        let mut tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(Error::other)?;

        let is_vision = flow == Some("xtls-rprx-vision");

        // Build and send VLESS request header through TLS
        let mut header_buf = BytesMut::with_capacity(128);
        encode_vless_request(&uuid_parsed, CMD_TCP, &addr, flow, &mut header_buf)?;

        tls_stream.write_all(&header_buf).await?;
        tls_stream.flush().await?;

        // Split into raw TCP + TLS session for manual management.
        // At this point: writes flushed, no reads done, so buffers are clean.
        let (tcp, tls_conn) = tls_stream.into_inner();

        let vision = if is_vision {
            Some(VisionFilter::new(*uuid_parsed.as_bytes()))
        } else {
            None
        };

        let id = CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        info!(
            id,
            server = %server,
            sni,
            flow = flow.unwrap_or("none"),
            addr = %addr,
            header_len = header_buf.len(),
            vision = is_vision,
            "VLESS connected, header sent, switched to manual TLS"
        );

        Ok(VlessTcpStream {
            id,
            tcp,
            tls: Some(tls_conn),
            vision,
            read_direct: false,
            write_direct: false,
            response_header_parsed: false,
            response_buf: Vec::new(),
            read_buf: Vec::new(),
            read_offset: 0,
            tls_write_pending: Vec::new(),
            tls_write_offset: 0,
            write_buf: Vec::new(),
            write_offset: 0,
            write_pending_plain_len: 0,
        })
    }

    // -------------------------------------------------------
    // Read helpers
    // -------------------------------------------------------

    /// Drain buffered read data into caller's buf. Returns true if data was copied.
    fn drain_read_buf(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_offset >= self.read_buf.len() {
            return false;
        }
        let remaining = &self.read_buf[self.read_offset..];
        let to_copy = remaining.len().min(buf.remaining());
        if to_copy == 0 {
            return false;
        }
        buf.put_slice(&remaining[..to_copy]);
        self.read_offset += to_copy;
        if self.read_offset >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_offset = 0;
        }
        true
    }

    /// Read from TCP, feed to TLS session, return decrypted plaintext.
    fn poll_read_tls_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>>> {
        let tls = self
            .tls
            .as_mut()
            .expect("poll_read_tls_plaintext called without TLS session");

        // Read raw bytes from TCP
        let mut tcp_buf = vec![0u8; 16384];
        let mut rb = ReadBuf::new(&mut tcp_buf);
        ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut rb))?;
        let filled = rb.filled().len();
        if filled == 0 {
            return Poll::Ready(Ok(Vec::new())); // EOF
        }

        // Feed to TLS session
        let mut cursor = std::io::Cursor::new(&tcp_buf[..filled]);
        tls.read_tls(&mut cursor)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("TLS read_tls: {e}")))?;

        let state = tls.process_new_packets().map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("TLS process_new_packets: {e}"),
            )
        })?;

        let available = state.plaintext_bytes_to_read();
        if available == 0 {
            // TLS record not complete yet, need more TCP data
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // Read decrypted plaintext
        let mut plaintext = Vec::with_capacity(available);
        let mut reader = tls.reader();
        loop {
            match reader.fill_buf() {
                Ok([]) => break,
                Ok(buf) => {
                    plaintext.extend_from_slice(buf);
                    let len = buf.len();
                    reader.consume(len);
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(plaintext))
    }

    /// Parse VLESS response header from accumulated unpadded data.
    /// Returns remaining data after response header, or None if more data needed.
    fn try_parse_response_from_buf(&mut self) -> Result<Option<Vec<u8>>> {
        if self.response_buf.len() < 2 {
            return Ok(None); // need more data
        }

        let version = self.response_buf[0];
        let addons_len = self.response_buf[1] as usize;
        let total = 2 + addons_len;

        if self.response_buf.len() < total {
            return Ok(None); // need more data
        }

        if version != VLESS_VERSION {
            let err_msg = format!(
                "VLESS: unexpected response version {:#04x}, expected {:#04x}. Raw bytes: {:02x?}",
                version,
                VLESS_VERSION,
                &self.response_buf[..self.response_buf.len().min(16)]
            );
            warn!(id = self.id, "{}", err_msg);
            return Err(Error::new(ErrorKind::InvalidData, err_msg));
        }

        debug!(
            id = self.id,
            version, addons_len, "VLESS response header parsed"
        );
        self.response_header_parsed = true;

        // Return remaining data after response header
        let remaining = self.response_buf[total..].to_vec();
        self.response_buf.clear();
        Ok(Some(remaining))
    }

    /// Consume VLESS response header directly from TLS stream (non-Vision mode).
    fn poll_read_response_header_plain(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        // Need at least 2 bytes (version + addons_len)
        while self.response_buf.len() < 2 {
            let need = 2 - self.response_buf.len();
            let mut tmp = vec![0u8; need];
            let mut rb = ReadBuf::new(&mut tmp);
            let tls = self.tls.as_mut().expect("plain response needs TLS session");
            // Read from TCP -> TLS
            ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "VLESS: EOF reading response header",
                )));
            }
            // Feed to TLS
            let mut cursor = std::io::Cursor::new(&tmp[..filled]);
            tls.read_tls(&mut cursor)
                .map_err(|e| Error::new(ErrorKind::InvalidData, format!("TLS read_tls: {e}")))?;
            let state = tls.process_new_packets().map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("TLS process_new_packets: {e}"),
                )
            })?;
            let avail = state.plaintext_bytes_to_read();
            if avail > 0 {
                let mut reader = tls.reader();
                let mut buf = vec![0u8; avail];
                reader.read_exact(&mut buf)?;
                self.response_buf.extend_from_slice(&buf);
            }
        }

        // Read addons if any
        let addons_len = self.response_buf[1] as usize;
        let total = 2 + addons_len;
        while self.response_buf.len() < total {
            let tls = self.tls.as_mut().expect("plain response needs TLS session");
            let mut tmp = vec![0u8; 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "VLESS: EOF reading response addons",
                )));
            }
            let mut cursor = std::io::Cursor::new(&tmp[..filled]);
            tls.read_tls(&mut cursor)
                .map_err(|e| Error::new(ErrorKind::InvalidData, format!("TLS read_tls: {e}")))?;
            let state = tls.process_new_packets().map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("TLS process_new_packets: {e}"),
                )
            })?;
            let avail = state.plaintext_bytes_to_read();
            if avail > 0 {
                let mut reader = tls.reader();
                let mut buf = vec![0u8; avail];
                reader.read_exact(&mut buf)?;
                self.response_buf.extend_from_slice(&buf);
            }
        }

        if self.response_buf[0] != VLESS_VERSION {
            let err_msg = format!(
                "VLESS: unexpected response version {:#04x}, expected {:#04x}. Raw header bytes: {:02x?}",
                self.response_buf[0], VLESS_VERSION, &self.response_buf
            );
            warn!(id = self.id, "{}", err_msg);
            return Poll::Ready(Err(Error::new(ErrorKind::InvalidData, err_msg)));
        }

        debug!(
            id = self.id,
            version = self.response_buf[0],
            addons_len,
            "VLESS response header parsed (plain)"
        );
        self.response_header_parsed = true;

        // Buffer any data beyond the response header
        if self.response_buf.len() > total {
            let remaining = self.response_buf[total..].to_vec();
            self.read_buf = remaining;
            self.read_offset = 0;
        }
        self.response_buf.clear();
        Poll::Ready(Ok(()))
    }

    // -------------------------------------------------------
    // Write helpers
    // -------------------------------------------------------

    /// Drain pending encrypted TLS data to TCP.
    fn poll_flush_tls_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        while self.tls_write_offset < self.tls_write_pending.len() {
            match Pin::new(&mut self.tcp)
                .poll_write(cx, &self.tls_write_pending[self.tls_write_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "VLESS: zero bytes written to TCP",
                    )));
                }
                Poll::Ready(Ok(n)) => self.tls_write_offset += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.tls_write_pending.clear();
        self.tls_write_offset = 0;
        Poll::Ready(Ok(()))
    }

    /// Write plaintext to TLS session and extract encrypted output.
    fn tls_encrypt_and_queue(&mut self, plaintext: &[u8]) -> Result<()> {
        let tls = self
            .tls
            .as_mut()
            .expect("tls_encrypt_and_queue called without TLS session");

        // Write plaintext to TLS session
        tls.writer().write_all(plaintext)?;

        // Extract encrypted TLS records
        tls.write_tls(&mut self.tls_write_pending)
            .map_err(|e| Error::other(format!("TLS write_tls: {e}")))?;

        Ok(())
    }

    /// Drain Vision write_buf: TLS-encrypt and queue for TCP write.
    fn poll_write_pending_vision(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<usize>>> {
        // First flush any pending encrypted data
        ready!(self.poll_flush_tls_write(cx))?;

        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(None));
        }

        // Take the write_buf to avoid borrow conflict
        let pending = std::mem::take(&mut self.write_buf);
        let result = self.tls_encrypt_and_queue(&pending[self.write_offset..]);
        self.write_offset = 0;
        result?;

        // Try to flush encrypted data
        ready!(self.poll_flush_tls_write(cx))?;

        let plain_len = self.write_pending_plain_len;
        self.write_pending_plain_len = 0;
        Poll::Ready(Ok(Some(plain_len)))
    }

    /// After sending COMMAND_PADDING_DIRECT, flush the TLS session and switch to direct writes.
    fn finalize_write_direct_switch(&mut self) -> Result<()> {
        if let Some(tls) = self.tls.as_mut() {
            // Extract any remaining encrypted data from the TLS session
            tls.write_tls(&mut self.tls_write_pending)
                .map_err(|e| Error::other(format!("TLS write_tls: {e}")))?;
        }
        self.write_direct = true;
        debug!(id = self.id, "write side switched to direct TCP");
        self.maybe_drop_tls();
        Ok(())
    }

    /// After receiving COMMAND_PADDING_DIRECT, drain TLS plaintext and switch to direct reads.
    fn finalize_read_direct_switch(&mut self) -> Result<Vec<u8>> {
        let mut extra = Vec::new();
        if let Some(tls) = self.tls.as_mut() {
            // Drain any remaining decrypted plaintext from the TLS session
            let mut reader = tls.reader();
            loop {
                match reader.fill_buf() {
                    Ok([]) => break,
                    Ok(buf) => {
                        extra.extend_from_slice(buf);
                        let len = buf.len();
                        reader.consume(len);
                    }
                    Err(_) => break,
                }
            }
        }
        self.read_direct = true;
        debug!(
            id = self.id,
            extra_len = extra.len(),
            "read side switched to direct TCP"
        );
        self.maybe_drop_tls();
        Ok(extra)
    }

    /// Drop the TLS session if both read and write are in direct mode.
    fn maybe_drop_tls(&mut self) {
        if self.read_direct && self.write_direct {
            self.tls = None;
            debug!(id = self.id, "TLS session dropped (both sides direct)");
        }
    }
}

// -------------------------------------------------------
// AsyncRead
// -------------------------------------------------------

impl AsyncRead for VlessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let me = &mut *self;

        // 1. Drain buffered data first
        if me.drain_read_buf(buf) {
            return Poll::Ready(Ok(()));
        }

        // 2. Direct mode: read raw TCP
        if me.read_direct {
            return Pin::new(&mut me.tcp).poll_read(cx, buf);
        }

        // 3. Non-Vision: parse response header directly from TLS
        if me.vision.is_none() && !me.response_header_parsed {
            ready!(me.poll_read_response_header_plain(cx))?;
            // Drain any data buffered during response parsing
            if me.drain_read_buf(buf) {
                return Poll::Ready(Ok(()));
            }
        }

        // 4. Read TLS plaintext
        let plaintext = ready!(me.poll_read_tls_plaintext(cx))?;
        if plaintext.is_empty() {
            return Poll::Ready(Ok(())); // EOF
        }

        // 5. Apply Vision unpadding if active
        let data = if let Some(vision) = &mut me.vision {
            let result = vision.unpad(&plaintext);

            // Check for mode switch
            if let Some(cmd) = result.finished_command {
                if cmd == COMMAND_PADDING_DIRECT {
                    let extra = me.finalize_read_direct_switch()?;
                    // Combine unpadded data + drained TLS plaintext
                    let mut combined = result.data;
                    combined.extend_from_slice(&extra);
                    combined
                } else {
                    // COMMAND_PADDING_END: padding done, keep using TLS
                    debug!(id = me.id, "Vision padding ended (END), continuing TLS");
                    result.data
                }
            } else if result.data.is_empty() {
                // Need more data for unpadding (incomplete frame)
                cx.waker().wake_by_ref();
                return Poll::Pending;
            } else {
                result.data
            }
        } else {
            plaintext
        };

        if data.is_empty() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // 6. Vision mode: parse response header from unpadded data
        if me.vision.is_some() && !me.response_header_parsed {
            me.response_buf.extend_from_slice(&data);
            match me.try_parse_response_from_buf()? {
                Some(remaining) => {
                    // Response parsed! Return remaining data to caller.
                    if remaining.is_empty() {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    let to_copy = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..to_copy]);
                    if to_copy < remaining.len() {
                        me.read_buf = remaining;
                        me.read_offset = to_copy;
                    }
                    return Poll::Ready(Ok(()));
                }
                None => {
                    // Need more data for response header
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }

        // 7. Copy data to caller, buffer overflow
        let to_copy = data.len().min(buf.remaining());
        buf.put_slice(&data[..to_copy]);
        if to_copy < data.len() {
            me.read_buf = data;
            me.read_offset = to_copy;
        }
        Poll::Ready(Ok(()))
    }
}

// -------------------------------------------------------
// AsyncWrite
// -------------------------------------------------------

impl AsyncWrite for VlessTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let me = &mut *self;

        // Flush pending TLS writes first
        ready!(me.poll_flush_tls_write(cx))?;

        // Drain pending Vision write buffer
        if !me.write_buf.is_empty() {
            return match ready!(me.poll_write_pending_vision(cx))? {
                Some(n) => Poll::Ready(Ok(n)),
                None => Poll::Ready(Ok(0)),
            };
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Direct mode: write raw TCP
        if me.write_direct {
            return Pin::new(&mut me.tcp).poll_write(cx, buf);
        }

        // Apply Vision padding if active
        if let Some(vision) = &mut me.vision {
            if vision.write_is_padding {
                let padded = vision.pad(buf);
                let should_switch_direct = vision.write_direct_copy;

                // Encrypt and queue padded data
                me.tls_encrypt_and_queue(&padded)?;
                me.write_pending_plain_len = buf.len();

                if should_switch_direct {
                    // Flush TLS before switching to direct
                    ready!(me.poll_flush_tls_write(cx))?;
                    me.finalize_write_direct_switch()?;
                } else {
                    // Try to flush
                    ready!(me.poll_flush_tls_write(cx))?;
                }

                return Poll::Ready(Ok(buf.len()));
            }
        }

        // Normal TLS write (no Vision padding or padding ended)
        me.tls_encrypt_and_queue(buf)?;
        ready!(me.poll_flush_tls_write(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let me = &mut *self;

        // Flush pending TLS encrypted data
        ready!(me.poll_flush_tls_write(cx))?;

        // If TLS session active, ensure it has flushed
        if let Some(tls) = me.tls.as_mut() {
            tls.write_tls(&mut me.tls_write_pending)
                .map_err(|e| Error::other(format!("TLS write_tls: {e}")))?;
            ready!(me.poll_flush_tls_write(cx))?;
        }

        // Flush TCP
        Pin::new(&mut me.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let me = &mut *self;

        // Flush everything first
        ready!(Pin::new(&mut *me).poll_flush(cx))?;

        // Send TLS close_notify if session is active
        if let Some(tls) = me.tls.as_mut() {
            tls.send_close_notify();
            tls.write_tls(&mut me.tls_write_pending)
                .map_err(|e| Error::other(format!("TLS write_tls: {e}")))?;
            ready!(me.poll_flush_tls_write(cx))?;
        }

        Pin::new(&mut me.tcp).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_flow;

    #[test]
    fn test_normalize_flow() {
        assert_eq!(normalize_flow(None).unwrap(), None);
        assert_eq!(normalize_flow(Some("")).unwrap(), None);
        assert_eq!(
            normalize_flow(Some("xtls-rprx-vision")).unwrap(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            normalize_flow(Some("xtls-rprx-vision-udp443")).unwrap(),
            Some("xtls-rprx-vision")
        );
        assert!(normalize_flow(Some("unsupported-flow")).is_err());
    }
}
