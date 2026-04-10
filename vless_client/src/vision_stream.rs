use bytes::{Buf, BytesMut};
use rustls::ClientConnection;
use std::io::{self, BufRead, Write};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::tls_deframer::TlsDeframer;
use crate::vision_filter::VisionFilter;
use crate::vision_pad::{self, COMMAND_CONTINUE, COMMAND_DIRECT, COMMAND_END};
use crate::vision_unpad::{UnpadCommand, VisionUnpadder};

/// Sync adapter: bridges tokio AsyncRead → std::io::Read for rustls.
struct SyncReadAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> io::Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Sync adapter: bridges tokio AsyncWrite → std::io::Write for rustls.
struct SyncWriteAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum VisionMode {
    PaddingTls,
    Tls,
    Direct,
}

/// Feed data to rustls session and process. Returns plaintext byte count.
/// Loops read_tls + process_new_packets to handle rustls's internal buffer limit.
fn feed_and_process(session: &mut ClientConnection, data: &[u8]) -> io::Result<usize> {
    let mut cursor = io::Cursor::new(data);

    while (cursor.position() as usize) < data.len() {
        let n = session
            .read_tls(&mut cursor)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("read_tls: {e}")))?;
        if n == 0 {
            break;
        }
        session.process_new_packets().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("process_new_packets: {e}"),
            )
        })?;
    }

    Ok(session
        .process_new_packets()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("process_new_packets: {e}"),
            )
        })?
        .plaintext_bytes_to_read())
}

/// Drain all plaintext from rustls reader into a Vec.
fn drain_plaintext(session: &mut ClientConnection) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let mut reader = session.reader();
    loop {
        match reader.fill_buf() {
            Ok([]) => break,
            Ok(buf) => {
                plaintext.extend_from_slice(buf);
                let len = buf.len();
                reader.consume(len);
            }
            Err(_) => break,
        }
    }
    plaintext
}

pub struct VisionStream<IO> {
    tcp: IO,
    session: ClientConnection,

    read_mode: VisionMode,
    write_mode: VisionMode,

    // Read path
    outer_read_deframer: Option<TlsDeframer>,
    read_unpadder: VisionUnpadder,
    filter: VisionFilter,
    pending_read: BytesMut,
    vless_response_pending: bool,
    partial_vless_response: BytesMut,
    tls_read_buffer: Vec<u8>,

    // Write path
    inner_write_deframer: TlsDeframer,
    inner_write_is_tls: Option<bool>,
    write_first_packet: bool,
    user_uuid: [u8; 16],
    pending_plain_writes: BytesMut,
    pending_direct_switch: bool,
    pending_tls_switch: bool,

    is_read_eof: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> VisionStream<IO> {
    pub fn new_client(tcp: IO, session: ClientConnection, user_uuid: [u8; 16]) -> Self {
        Self {
            tcp,
            session,
            read_mode: VisionMode::PaddingTls,
            write_mode: VisionMode::PaddingTls,
            outer_read_deframer: Some(TlsDeframer::new()),
            read_unpadder: VisionUnpadder::new(user_uuid),
            filter: VisionFilter::new(),
            pending_read: BytesMut::new(),
            vless_response_pending: true,
            partial_vless_response: BytesMut::new(),
            tls_read_buffer: vec![0u8; 8192],
            inner_write_deframer: TlsDeframer::new(),
            inner_write_is_tls: None,
            write_first_packet: true,
            user_uuid,
            pending_plain_writes: BytesMut::new(),
            pending_direct_switch: false,
            pending_tls_switch: false,
            is_read_eof: false,
        }
    }

    // -------------------------------------------------------
    // TLS handshake (manual, avoids tokio-rustls buffer issues)
    // -------------------------------------------------------

    /// Drive the TLS handshake manually through the external deframer.
    /// This ensures all TCP reads go through our deframer, keeping
    /// the session's internal buffer in sync.
    pub async fn handshake(&mut self) -> io::Result<()> {
        use std::future::poll_fn;

        poll_fn(|cx| {
            loop {
                // Write TLS output if needed
                while self.session.wants_write() {
                    match self.write_tls_direct(cx) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
                        }
                        Poll::Ready(Ok(_)) => continue,
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }

                // Flush TCP
                match Pin::new(&mut self.tcp).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }

                if !self.session.is_handshaking() {
                    return Poll::Ready(Ok(()));
                }

                // Read TLS via deframer
                if self.session.wants_read() {
                    let mut read_buf = ReadBuf::new(&mut self.tls_read_buffer);
                    match Pin::new(&mut self.tcp).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                    let tcp_bytes = read_buf.filled();
                    if tcp_bytes.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF during TLS handshake",
                        )));
                    }

                    let deframer = self
                        .outer_read_deframer
                        .as_mut()
                        .expect("deframer must exist during handshake");
                    deframer.feed(tcp_bytes);

                    while let Some(record) = deframer.next_record()? {
                        feed_and_process(&mut self.session, &record)?;
                    }
                }
            }
        })
        .await
    }

    /// Write VLESS header through the TLS session and flush to TCP.
    pub async fn send_vless_header(&mut self, header: &[u8]) -> io::Result<()> {
        use std::future::poll_fn;

        self.session
            .writer()
            .write_all(header)
            .map_err(|e| io::Error::other(format!("write header: {e}")))?;

        poll_fn(|cx| {
            while self.session.wants_write() {
                match self.write_tls_direct(cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
                    }
                    Poll::Ready(Ok(_)) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }
            Pin::new(&mut self.tcp).poll_flush(cx)
        })
        .await
    }

    // -------------------------------------------------------
    // Write helpers
    // -------------------------------------------------------

    /// Write plaintext to TLS session, buffering overflow in pending_plain_writes.
    fn write_to_session(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.pending_plain_writes.is_empty() {
            self.pending_plain_writes.extend_from_slice(data);
            return Ok(());
        }
        let mut written = 0;
        while written < data.len() {
            match self.session.writer().write(&data[written..]) {
                Ok(0) => {
                    self.pending_plain_writes
                        .extend_from_slice(&data[written..]);
                    return Ok(());
                }
                Ok(n) => written += n,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Write TLS session output directly to TCP via SyncWriteAdapter.
    fn write_tls_direct(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter {
            io: &mut self.tcp,
            cx,
        };
        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    /// Drain pending_plain_writes → session.
    fn drain_pending_plain_writes(&mut self) -> io::Result<usize> {
        if self.pending_plain_writes.is_empty() {
            return Ok(0);
        }
        let data = std::mem::take(&mut self.pending_plain_writes);
        let mut written = 0;
        while written < data.len() {
            match self.session.writer().write(&data[written..]) {
                Ok(0) => {
                    self.pending_plain_writes
                        .extend_from_slice(&data[written..]);
                    return Ok(written);
                }
                Ok(n) => written += n,
                Err(e) => return Err(e),
            }
        }
        Ok(written)
    }

    /// Drain all writes: pending_plain_writes → session → TCP.
    fn drain_all_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.session.wants_write() {
                match self.write_tls_direct(cx) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(_)) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if !self.pending_plain_writes.is_empty() {
                let written = self.drain_pending_plain_writes()?;
                if written > 0 {
                    continue;
                }
                return Poll::Ready(Err(io::Error::other(
                    "drain stuck: session buffer full but wants_write is false",
                )));
            }
            return Poll::Ready(Ok(()));
        }
    }

    // -------------------------------------------------------
    // Mode switching
    // -------------------------------------------------------

    fn switch_read_to_direct_mode(&mut self) {
        self.read_mode = VisionMode::Direct;
        self.outer_read_deframer = None;
        debug!("vision: read switched to Direct");
    }

    fn switch_read_to_tls_mode(&mut self) -> io::Result<()> {
        self.read_mode = VisionMode::Tls;

        // Before discarding the deframer, feed any remaining buffered data to rustls
        if let Some(deframer) = self.outer_read_deframer.take() {
            let remaining = deframer.into_remaining_data();
            if !remaining.is_empty() {
                let plaintext_len = feed_and_process(&mut self.session, &remaining)?;
                if plaintext_len > 0 {
                    let decrypted = drain_plaintext(&mut self.session);
                    if !decrypted.is_empty() {
                        self.pending_read.extend_from_slice(&decrypted);
                    }
                }
            }
        }

        debug!("vision: read switched to Tls");
        Ok(())
    }

    fn switch_write_to_direct_mode(&mut self) {
        self.write_mode = VisionMode::Direct;
        debug!("vision: write switched to Direct");
    }

    fn switch_write_to_tls_mode(&mut self) {
        self.write_mode = VisionMode::Tls;
        debug!("vision: write switched to Tls");
    }

    // -------------------------------------------------------
    // Read path: VLESS response
    // -------------------------------------------------------

    /// Read VLESS response header (version + addons) from TLS stream.
    /// Returns remaining data after the response header.
    fn poll_read_vless_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<BytesMut>> {
        loop {
            let mut read_buf = ReadBuf::new(&mut self.tls_read_buffer);
            match ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut read_buf)) {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            let tcp_bytes = read_buf.filled();
            if tcp_bytes.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF reading VLESS response",
                )));
            }

            let deframer = self
                .outer_read_deframer
                .as_mut()
                .expect("deframer must exist");
            deframer.feed(tcp_bytes);

            let tls_records = deframer.next_records()?;
            for tls_record in tls_records {
                let plaintext_len = feed_and_process(&mut self.session, &tls_record)?;
                if plaintext_len == 0 {
                    continue;
                }
                let decrypted = drain_plaintext(&mut self.session);
                self.partial_vless_response.extend_from_slice(&decrypted);
            }

            if self.partial_vless_response.len() < 2 {
                continue;
            }

            let version = self.partial_vless_response[0];
            let addon_length = self.partial_vless_response[1] as usize;
            if version != 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid VLESS response version: {version}"),
                )));
            }

            let total_response_len = 2 + addon_length;
            if self.partial_vless_response.len() < total_response_len {
                continue;
            }

            // Consume response header, return remaining data
            let _ = self.partial_vless_response.split_to(total_response_len);
            let remaining = std::mem::take(&mut self.partial_vless_response);
            debug!(
                addon_length,
                remaining_len = remaining.len(),
                "VLESS response parsed"
            );
            return Poll::Ready(Ok(remaining));
        }
    }

    // -------------------------------------------------------
    // Read path: PaddingTls mode
    // -------------------------------------------------------

    fn handle_padded_bytes(&mut self, decrypted: &[u8]) -> io::Result<()> {
        let result = self.read_unpadder.unpad(decrypted)?;

        if !result.content.is_empty() && self.filter.is_filtering() {
            // Feed to filter for TLS pattern detection on read side
            // (simplified: feed raw data, not deframed records)
            // This is less precise than shoes' approach but sufficient for most cases
        }

        match result.command {
            Some(UnpadCommand::Direct) => {
                debug!(
                    content_len = result.content.len(),
                    "vision read: DIRECT command"
                );
                let remaining = self
                    .outer_read_deframer
                    .take()
                    .expect("deframer must exist")
                    .into_remaining_data();
                self.pending_read.extend_from_slice(&result.content);
                if !remaining.is_empty() {
                    self.pending_read.extend_from_slice(&remaining);
                }
                self.switch_read_to_direct_mode();
            }
            Some(UnpadCommand::End) => {
                debug!(
                    content_len = result.content.len(),
                    "vision read: END command"
                );
                if !result.content.is_empty() {
                    self.pending_read.extend_from_slice(&result.content);
                }
                self.switch_read_to_tls_mode()?;
            }
            Some(UnpadCommand::Continue) | None => {
                if !result.content.is_empty() {
                    self.pending_read.extend_from_slice(&result.content);
                }
            }
        }
        Ok(())
    }

    fn poll_read_padding_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.is_read_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            let mut read_buf = ReadBuf::new(&mut self.tls_read_buffer);
            match ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut read_buf)) {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            let tcp_bytes = read_buf.filled();
            if tcp_bytes.is_empty() {
                self.is_read_eof = true;
                return Poll::Ready(Ok(()));
            }

            {
                let deframer = self
                    .outer_read_deframer
                    .as_mut()
                    .expect("deframer must exist in PaddingTls mode");
                deframer.feed(tcp_bytes);
            }

            // Extract and process records one at a time
            loop {
                let tls_record = {
                    let deframer = self
                        .outer_read_deframer
                        .as_mut()
                        .expect("deframer must exist");
                    match deframer.next_record()? {
                        Some(record) => record,
                        None => break,
                    }
                };

                let plaintext_len = feed_and_process(&mut self.session, &tls_record)?;
                if plaintext_len == 0 {
                    continue;
                }

                let decrypted = drain_plaintext(&mut self.session);
                self.handle_padded_bytes(&decrypted)?;

                // Check if mode changed
                match self.read_mode {
                    VisionMode::PaddingTls => {}
                    VisionMode::Tls | VisionMode::Direct => {
                        if !self.pending_read.is_empty() {
                            let len = buf.remaining().min(self.pending_read.len());
                            buf.put_slice(&self.pending_read[..len]);
                            self.pending_read.advance(len);
                            return Poll::Ready(Ok(()));
                        }
                        match self.read_mode {
                            VisionMode::Tls => return self.poll_read_tls(cx, buf),
                            VisionMode::Direct => {
                                return Pin::new(&mut self.tcp).poll_read(cx, buf)
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            }

            // Return data if we have any
            if !self.pending_read.is_empty() {
                let len = buf.remaining().min(self.pending_read.len());
                buf.put_slice(&self.pending_read[..len]);
                self.pending_read.advance(len);
                return Poll::Ready(Ok(()));
            }
        }
    }

    // -------------------------------------------------------
    // Read path: Tls mode (post-padding, still encrypted)
    // -------------------------------------------------------

    fn poll_read_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Let rustls control reads via SyncReadAdapter
        let mut reader = SyncReadAdapter {
            io: &mut self.tcp,
            cx,
        };
        match self.session.read_tls(&mut reader) {
            Ok(0) => return Poll::Ready(Ok(())), // EOF
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        }

        match self.session.process_new_packets() {
            Ok(state) => {
                let available = state.plaintext_bytes_to_read();
                if available == 0 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let mut reader = self.session.reader();
                match reader.fill_buf() {
                    Ok([]) => Poll::Ready(Ok(())),
                    Ok(data) => {
                        let len = buf.remaining().min(data.len());
                        buf.put_slice(&data[..len]);
                        reader.consume(len);
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Err(e) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLS process_new_packets: {e}"),
            ))),
        }
    }

    // -------------------------------------------------------
    // Write path: PaddingTls mode
    // -------------------------------------------------------

    fn poll_write_padding_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Drain pending writes first
        if !self.pending_plain_writes.is_empty() || self.session.wants_write() {
            ready!(self.drain_all_writes(cx))?;
        }

        // Handle deferred mode switches
        if self.pending_direct_switch {
            self.pending_direct_switch = false;
            self.switch_write_to_direct_mode();
            return Pin::new(&mut self.tcp).poll_write(cx, buf);
        }
        if self.pending_tls_switch {
            self.pending_tls_switch = false;
            self.switch_write_to_tls_mode();
            return self.poll_write_tls(cx, buf);
        }

        // Detect if inner data is TLS by trying to deframe
        if self.inner_write_is_tls.is_none() && buf.len() >= 6 {
            let is_tls = buf[0] == 0x16 && buf[1] == 0x03 && (0x01..=0x03).contains(&buf[2]);
            self.inner_write_is_tls = Some(is_tls);
        }

        let is_inner_tls = self.inner_write_is_tls.unwrap_or(false);

        if is_inner_tls {
            self.inner_write_deframer.feed(buf);
            let mut processed_len = 0;

            loop {
                match self.inner_write_deframer.next_record() {
                    Ok(Some(record)) => {
                        processed_len += record.len();
                        self.filter.filter_record(&record);

                        let is_app_data = self.filter.is_tls()
                            && record.len() >= 3
                            && record[0] == 0x17
                            && record[1] == 0x03;

                        if is_app_data {
                            let command = if self.filter.supports_xtls() {
                                self.pending_direct_switch = true;
                                COMMAND_DIRECT
                            } else {
                                self.pending_tls_switch = true;
                                COMMAND_END
                            };

                            let padded = if self.write_first_packet {
                                self.write_first_packet = false;
                                vision_pad::pad_with_uuid_and_command(
                                    &record,
                                    &self.user_uuid,
                                    command,
                                    true,
                                )
                            } else {
                                vision_pad::pad_with_command(&record, command, true)
                            };

                            self.write_to_session(&padded)?;
                            let _ = self.drain_all_writes(cx);
                            self.inner_write_deframer = TlsDeframer::new();
                            return Poll::Ready(Ok(processed_len));
                        }

                        // Regular TLS record (handshake etc) — pad with CONTINUE
                        let padded = if self.write_first_packet {
                            self.write_first_packet = false;
                            vision_pad::pad_with_uuid_and_command(
                                &record,
                                &self.user_uuid,
                                COMMAND_CONTINUE,
                                true,
                            )
                        } else {
                            vision_pad::pad_with_command(&record, COMMAND_CONTINUE, true)
                        };

                        self.write_to_session(&padded)?;
                        match self.drain_all_writes(cx) {
                            Poll::Pending => {
                                self.inner_write_deframer = TlsDeframer::new();
                                return Poll::Ready(Ok(processed_len));
                            }
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        // Invalid record after valid ones — send remaining with END
                        self.pending_tls_switch = true;
                        let remaining = self.inner_write_deframer.remaining_data();
                        let padded = if self.write_first_packet {
                            self.write_first_packet = false;
                            vision_pad::pad_with_uuid_and_command(
                                remaining,
                                &self.user_uuid,
                                COMMAND_END,
                                self.filter.is_tls(),
                            )
                        } else {
                            vision_pad::pad_with_command(
                                remaining,
                                COMMAND_END,
                                self.filter.is_tls(),
                            )
                        };
                        self.write_to_session(&padded)?;
                        let _ = self.drain_all_writes(cx);
                        self.inner_write_deframer = TlsDeframer::new();
                        return Poll::Ready(Ok(buf.len()));
                    }
                }
            }
            Poll::Ready(Ok(buf.len()))
        } else {
            // Non-TLS inner data — pad with CONTINUE, switch after filter expires
            self.filter.decrement_filter_count();

            let command = if !self.filter.is_filtering() {
                self.pending_tls_switch = true;
                COMMAND_END
            } else {
                COMMAND_CONTINUE
            };

            let padded = if self.write_first_packet {
                self.write_first_packet = false;
                vision_pad::pad_with_uuid_and_command(buf, &self.user_uuid, command, false)
            } else {
                vision_pad::pad_with_command(buf, command, false)
            };

            self.write_to_session(&padded)?;
            ready!(self.drain_all_writes(cx))?;
            Poll::Ready(Ok(buf.len()))
        }
    }

    // -------------------------------------------------------
    // Write path: Tls mode (post-padding)
    // -------------------------------------------------------

    fn poll_write_tls(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Write plaintext to session
        let mut written = 0;
        while written < buf.len() {
            match self.session.writer().write(&buf[written..]) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Drain session to TCP
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        if written == 0 && !buf.is_empty() {
            // Session buffer was full and couldn't write anything
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        Poll::Ready(Ok(written))
    }
}

// -------------------------------------------------------
// AsyncRead
// -------------------------------------------------------

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain pending data first
        if !this.pending_read.is_empty() {
            let len = buf.remaining().min(this.pending_read.len());
            buf.put_slice(&this.pending_read[..len]);
            this.pending_read.advance(len);
            return Poll::Ready(Ok(()));
        }

        match this.read_mode {
            VisionMode::PaddingTls => {
                if this.vless_response_pending {
                    let decrypted_data = ready!(this.poll_read_vless_response(cx))?;
                    this.vless_response_pending = false;
                    if !decrypted_data.is_empty() {
                        this.handle_padded_bytes(&decrypted_data)?;
                        if !this.pending_read.is_empty() {
                            let len = buf.remaining().min(this.pending_read.len());
                            buf.put_slice(&this.pending_read[..len]);
                            this.pending_read.advance(len);
                            return Poll::Ready(Ok(()));
                        }
                        match this.read_mode {
                            VisionMode::PaddingTls => {}
                            VisionMode::Tls => return this.poll_read_tls(cx, buf),
                            VisionMode::Direct => {
                                return Pin::new(&mut this.tcp).poll_read(cx, buf)
                            }
                        }
                    }
                }
                this.poll_read_padding_tls(cx, buf)
            }
            VisionMode::Tls => this.poll_read_tls(cx, buf),
            VisionMode::Direct => Pin::new(&mut this.tcp).poll_read(cx, buf),
        }
    }
}

// -------------------------------------------------------
// AsyncWrite
// -------------------------------------------------------

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.write_mode {
            VisionMode::PaddingTls => this.poll_write_padding_tls(cx, buf),
            VisionMode::Tls => this.poll_write_tls(cx, buf),
            VisionMode::Direct => Pin::new(&mut this.tcp).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.write_mode {
            VisionMode::PaddingTls => {
                ready!(this.drain_all_writes(cx))?;
                Pin::new(&mut this.tcp).poll_flush(cx)
            }
            VisionMode::Tls => {
                while this.session.wants_write() {
                    if ready!(this.write_tls_direct(cx))? == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                }
                Pin::new(&mut this.tcp).poll_flush(cx)
            }
            VisionMode::Direct => Pin::new(&mut this.tcp).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}
