use bytes::{Bytes, BytesMut};
use std::io;

const TLS_RECORD_HEADER_SIZE: usize = 5;
const MAX_TLS_CIPHERTEXT_LEN: usize = 16384 + 2048; // 18,432 bytes (TLS 1.2 limit)
pub const TLS_MAX_RECORD_SIZE: usize = MAX_TLS_CIPHERTEXT_LEN + TLS_RECORD_HEADER_SIZE;

/// Deframer that reassembles TLS records from partial TCP reads.
///
/// Feeds one complete TLS record at a time, preventing raw data
/// (after Direct mode transition) from being mixed with TLS records.
#[derive(Debug)]
pub struct TlsDeframer {
    buffer: BytesMut,
    state: DeframerState,
}

#[derive(Debug, Clone, Copy)]
enum DeframerState {
    ReadingHeader,
    ReadingPayload { payload_len: usize },
}

impl TlsDeframer {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(TLS_MAX_RECORD_SIZE),
            state: DeframerState::ReadingHeader,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Extract the next complete TLS record, or None if more data needed.
    pub fn next_record(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            match self.state {
                DeframerState::ReadingHeader => {
                    if self.buffer.len() < TLS_RECORD_HEADER_SIZE {
                        return Ok(None);
                    }

                    let content_type = self.buffer[0];
                    let version_major = self.buffer[1];
                    let version_minor = self.buffer[2];
                    let payload_len =
                        u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

                    if version_major != 0x03 || !(0x01..=0x03).contains(&version_minor) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Invalid TLS version: 0x{:02x}{:02x}",
                                version_major, version_minor
                            ),
                        ));
                    }

                    if payload_len > MAX_TLS_CIPHERTEXT_LEN {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "TLS record length {} exceeds max {}",
                                payload_len, MAX_TLS_CIPHERTEXT_LEN
                            ),
                        ));
                    }

                    if !(0x14..=0x18).contains(&content_type) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid TLS content type: 0x{:02x}", content_type),
                        ));
                    }

                    self.state = DeframerState::ReadingPayload { payload_len };
                }

                DeframerState::ReadingPayload { payload_len } => {
                    let total_len = TLS_RECORD_HEADER_SIZE + payload_len;
                    if self.buffer.len() < total_len {
                        return Ok(None);
                    }

                    let record = self.buffer.split_to(total_len).freeze();
                    self.state = DeframerState::ReadingHeader;
                    return Ok(Some(record));
                }
            }
        }
    }

    /// Extract all available complete TLS records.
    pub fn next_records(&mut self) -> io::Result<Vec<Bytes>> {
        let mut records = Vec::new();
        while let Some(record) = self.next_record()? {
            records.push(record);
        }
        Ok(records)
    }

    /// Consume deframer, return remaining buffered data (for Direct mode transition).
    pub fn into_remaining_data(self) -> Bytes {
        self.buffer.freeze()
    }

    #[allow(dead_code)]
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn remaining_data(&self) -> &[u8] {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.push(content_type);
        record.push(0x03);
        record.push(0x03);
        let len = payload.len() as u16;
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    #[test]
    fn test_single_record() {
        let mut d = TlsDeframer::new();
        let rec = make_tls_record(0x17, b"Hello");
        d.feed(&rec);
        assert_eq!(d.next_record().unwrap().unwrap(), &rec[..]);
        assert!(d.next_record().unwrap().is_none());
    }

    #[test]
    fn test_partial_header() {
        let mut d = TlsDeframer::new();
        let rec = make_tls_record(0x16, b"test");
        d.feed(&rec[..3]);
        assert!(d.next_record().unwrap().is_none());
        d.feed(&rec[3..]);
        assert_eq!(d.next_record().unwrap().unwrap(), &rec[..]);
    }

    #[test]
    fn test_multiple_records() {
        let mut d = TlsDeframer::new();
        let r1 = make_tls_record(0x16, b"First");
        let r2 = make_tls_record(0x17, b"Second");
        let mut combined = Vec::new();
        combined.extend_from_slice(&r1);
        combined.extend_from_slice(&r2);
        d.feed(&combined);
        let records = d.next_records().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], &r1[..]);
        assert_eq!(records[1], &r2[..]);
    }

    #[test]
    fn test_invalid_content_type() {
        let mut d = TlsDeframer::new();
        d.feed(&[0xFF, 0x03, 0x03, 0x00, 0x05, 0, 0, 0, 0, 0]);
        assert!(d.next_record().is_err());
    }

    #[test]
    fn test_remaining_data() {
        let mut d = TlsDeframer::new();
        let rec = make_tls_record(0x17, b"rec");
        let raw = b"raw_data";
        let mut data = Vec::new();
        data.extend_from_slice(&rec);
        data.extend_from_slice(raw);
        d.feed(&data);
        d.next_record().unwrap().unwrap();
        let remaining = d.into_remaining_data();
        assert_eq!(&remaining[..], raw);
    }
}
