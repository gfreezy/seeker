use rand::Rng;
use tracing::debug;

const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;

const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// XTLS-Vision padding filter, matching Xray-core's VisionReader/VisionWriter behavior.
pub struct VisionFilter {
    uuid: [u8; 16],

    // --- Unpadding state (read path) ---
    read_staging: Vec<u8>,
    read_remaining_command: i32,
    read_remaining_content: i32,
    read_remaining_padding: i32,
    read_current_command: u8,
    /// Whether padding phase is active for reads
    read_within_padding: bool,
    /// Whether to switch to direct copy (no more unpadding)
    pub read_direct_copy: bool,

    // --- Padding state (write path) ---
    write_uuid: Option<[u8; 16]>,
    pub write_is_padding: bool,
    pub write_direct_copy: bool,

    // --- TLS detection ---
    packets_to_filter: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    remaining_server_hello: i32,
}

impl VisionFilter {
    pub fn new(uuid: [u8; 16]) -> Self {
        VisionFilter {
            uuid,
            read_staging: Vec::new(),
            read_remaining_command: -1,
            read_remaining_content: -1,
            read_remaining_padding: -1,
            read_current_command: 0,
            read_within_padding: true,
            read_direct_copy: false,
            write_uuid: Some(uuid),
            write_is_padding: true,
            write_direct_copy: false,
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            remaining_server_hello: -1,
        }
    }

    /// Strip Vision padding from incoming data. Returns the actual application data.
    pub fn unpad(&mut self, input: &[u8]) -> Vec<u8> {
        if self.read_direct_copy {
            return input.to_vec();
        }

        if input.is_empty() {
            return Vec::new();
        }

        // Not within padding and no more packets to filter → passthrough
        if !self.read_within_padding && self.packets_to_filter <= 0 && self.read_staging.is_empty()
        {
            return input.to_vec();
        }

        self.read_staging.extend_from_slice(input);
        debug!(
            input_len = input.len(),
            staging_len = self.read_staging.len(),
            within_padding = self.read_within_padding,
            direct_copy = self.read_direct_copy,
            "vision unpad input"
        );

        let mut output = Vec::new();
        let mut pos = 0;

        loop {
            // Initial state: check for UUID prefix.
            // During padding phase we may need to wait for the full 16-byte UUID + 5-byte frame header.
            if self.read_remaining_command == -1
                && self.read_remaining_content == -1
                && self.read_remaining_padding == -1
            {
                if !self.read_within_padding {
                    output.extend_from_slice(&self.read_staging[pos..]);
                    pos = self.read_staging.len();
                    break;
                }

                let remaining = &self.read_staging[pos..];
                if remaining.len() < 21 {
                    let prefix_len = remaining.len().min(self.uuid.len());
                    if remaining[..prefix_len] == self.uuid[..prefix_len] {
                        break;
                    }

                    output.extend_from_slice(remaining);
                    pos = self.read_staging.len();
                    break;
                }

                if remaining[..16] == self.uuid {
                    pos += 16;
                    self.read_remaining_command = 5;
                    debug!("vision unpad: UUID matched, entering padded frame parsing");
                } else {
                    // No UUID prefix → not a padded frame, passthrough
                    debug!(
                        remaining_len = remaining.len(),
                        "vision unpad: no UUID match, passthrough"
                    );
                    output.extend_from_slice(remaining);
                    pos = self.read_staging.len();
                    break;
                }
            }

            if self.read_remaining_command > 0 {
                if pos >= self.read_staging.len() {
                    break;
                }

                let byte = self.read_staging[pos];
                pos += 1;
                match self.read_remaining_command {
                    5 => self.read_current_command = byte,
                    4 => self.read_remaining_content = (byte as i32) << 8,
                    3 => self.read_remaining_content |= byte as i32,
                    2 => self.read_remaining_padding = (byte as i32) << 8,
                    1 => self.read_remaining_padding |= byte as i32,
                    _ => {}
                }
                self.read_remaining_command -= 1;
            } else if self.read_remaining_content > 0 {
                let avail = (self.read_staging.len() - pos) as i32;
                let take = avail.min(self.read_remaining_content) as usize;
                if take == 0 {
                    break;
                }

                output.extend_from_slice(&self.read_staging[pos..pos + take]);
                pos += take;
                self.read_remaining_content -= take as i32;
            } else if self.read_remaining_padding > 0 {
                // Skip padding bytes
                let avail = (self.read_staging.len() - pos) as i32;
                let skip = avail.min(self.read_remaining_padding) as usize;
                if skip == 0 {
                    break;
                }

                pos += skip;
                self.read_remaining_padding -= skip as i32;
            }

            // Check if current block is complete
            if self.read_remaining_command <= 0
                && self.read_remaining_content <= 0
                && self.read_remaining_padding <= 0
            {
                if self.read_current_command == COMMAND_PADDING_CONTINUE {
                    // More blocks coming
                    self.read_remaining_command = 5;
                    self.read_within_padding = true;
                    debug!("vision unpad: block done, CONTINUE → next block");
                } else {
                    // PaddingEnd or PaddingDirect
                    self.read_remaining_command = -1;
                    self.read_remaining_content = -1;
                    self.read_remaining_padding = -1;
                    self.read_within_padding = false;
                    if self.read_current_command == COMMAND_PADDING_DIRECT {
                        // Server sent DIRECT — it will switch its writer to
                        // raw TCP (bypassing outer TLS). We must also switch
                        // our reader to raw TCP on the next read.
                        self.read_direct_copy = true;
                    }
                    debug!(
                        command = self.read_current_command,
                        direct_copy = self.read_direct_copy,
                        "vision unpad: block done, padding ended"
                    );
                    // Append any remaining data
                    if pos < self.read_staging.len() {
                        output.extend_from_slice(&self.read_staging[pos..]);
                        pos = self.read_staging.len();
                    }
                    break;
                }
            }
        }

        if pos > 0 {
            self.read_staging.drain(..pos);
        }

        if !output.is_empty() {
            self.filter_tls(&output);
        }

        debug!(
            output_len = output.len(),
            staging_remaining = self.read_staging.len(),
            is_tls = self.is_tls,
            enable_xtls = self.enable_xtls,
            "vision unpad result"
        );
        output
    }

    /// Add Vision padding to outgoing data. Returns the padded frame.
    pub fn pad(&mut self, data: &[u8]) -> Vec<u8> {
        if self.write_direct_copy || !self.write_is_padding {
            debug!(
                data_len = data.len(),
                direct_copy = self.write_direct_copy,
                is_padding = self.write_is_padding,
                "vision pad: bypass (no padding)"
            );
            return data.to_vec();
        }

        // Filter TLS on write path (mirrors Xray-core's XtlsFilterTls in VisionWriter)
        if self.packets_to_filter > 0 {
            self.filter_tls(data);
        }

        let content_len = data.len() as u16;
        let padding_len = self.calculate_padding_len(content_len);

        // Determine command
        let command = if self.is_tls && data.len() >= 3 && data[..3] == TLS_APPLICATION_DATA_START {
            // TLS Application Data found → end padding
            self.write_is_padding = false;
            if self.enable_xtls {
                self.write_direct_copy = true;
                COMMAND_PADDING_DIRECT
            } else {
                COMMAND_PADDING_END
            }
        } else if !self.is_tls12_or_above && self.packets_to_filter <= 1 {
            // Compatibility: end padding early for non-TLS 1.2+
            self.write_is_padding = false;
            COMMAND_PADDING_END
        } else {
            COMMAND_PADDING_CONTINUE
        };

        debug!(
            content_len,
            padding_len,
            command,
            is_tls = self.is_tls,
            enable_xtls = self.enable_xtls,
            is_padding = self.write_is_padding,
            has_uuid = self.write_uuid.is_some(),
            packets_to_filter = self.packets_to_filter,
            "vision pad"
        );

        let mut result = Vec::with_capacity(16 + 5 + data.len() + padding_len as usize);

        // First write: prepend UUID
        if let Some(uuid) = self.write_uuid.take() {
            result.extend_from_slice(&uuid);
        }

        // 5-byte header: command + content_len(BE) + padding_len(BE)
        result.push(command);
        result.push((content_len >> 8) as u8);
        result.push(content_len as u8);
        result.push((padding_len >> 8) as u8);
        result.push(padding_len as u8);

        // Content
        result.extend_from_slice(data);

        // Random padding
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len as usize];
            rand::rng().fill(&mut padding[..]);
            result.extend_from_slice(&padding);
        }

        result
    }

    fn calculate_padding_len(&self, content_len: u16) -> u16 {
        let mut rng = rand::rng();
        if (content_len as u32) < 900 && self.is_tls {
            // Long padding during TLS handshake phase
            let extra: u16 = rng.random_range(0..500);
            let target = 900u16.saturating_sub(content_len) + extra;
            target.min(16000 - 21 - content_len)
        } else {
            rng.random_range(0..256)
        }
    }

    /// Detect TLS records in the data stream. Updates internal TLS detection state.
    fn filter_tls(&mut self, data: &[u8]) {
        if self.packets_to_filter <= 0 {
            return;
        }
        self.packets_to_filter -= 1;

        if data.len() >= 6 {
            // Check for ServerHello
            if data[..3] == TLS_SERVER_HANDSHAKE_START && data[5] == HANDSHAKE_TYPE_SERVER_HELLO {
                self.remaining_server_hello = ((data[3] as i32) << 8 | data[4] as i32) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                debug!(
                    remaining_server_hello = self.remaining_server_hello,
                    "filter_tls: detected TLS ServerHello"
                );
            }
            // Check for ClientHello
            else if data[..2] == TLS_CLIENT_HANDSHAKE_START
                && data[5] == HANDSHAKE_TYPE_CLIENT_HELLO
            {
                self.is_tls = true;
                debug!(
                    data_len = data.len(),
                    "filter_tls: detected TLS ClientHello"
                );
            }
        }

        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(data.len());
            self.remaining_server_hello -= data.len() as i32;

            // Look for TLS 1.3 supported_versions extension
            if contains_subsequence(&data[..end], &TLS13_SUPPORTED_VERSIONS) {
                // NOTE: We intentionally keep enable_xtls = false.
                // XTLS direct copy requires bypassing the outer TLS layer
                // (UnwrapRawConn in Xray-core), which is not possible with
                // tokio-rustls. If we set enable_xtls = true, we'd send
                // COMMAND_PADDING_DIRECT, causing the server to switch to
                // raw TCP writes, resulting in DecryptError on our TLS reader.
                // Keeping enable_xtls = false means we use COMMAND_PADDING_END,
                // which still correctly ends the padding phase without bypassing TLS.
                self.packets_to_filter = 0;
                debug!(
                    "filter_tls: detected TLS 1.3 (enable_xtls stays false, no raw TCP support)"
                );
            } else if self.remaining_server_hello <= 0 {
                // TLS 1.2
                self.packets_to_filter = 0;
                debug!("filter_tls: TLS 1.2 (no TLS 1.3 extensions found)");
            }
        }
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid() -> [u8; 16] {
        [
            0xb7, 0xf1, 0xeb, 0xca, 0x54, 0x27, 0x3f, 0x91, 0xa4, 0xbd, 0xfd, 0xaa, 0x6a, 0x41,
            0x54, 0x7c,
        ]
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let uuid = test_uuid();
        let mut writer = VisionFilter::new(uuid);
        let mut reader = VisionFilter::new(uuid);

        let data = b"Hello, World!";
        let padded = writer.pad(data);
        let unpadded = reader.unpad(&padded);

        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_unpad_multiple_blocks() {
        let uuid = test_uuid();
        let mut writer = VisionFilter::new(uuid);
        let mut reader = VisionFilter::new(uuid);

        // First block (Continue)
        let data1 = b"block one";
        let padded1 = writer.pad(data1);

        // Second block
        let data2 = b"block two";
        let padded2 = writer.pad(data2);

        let unpadded1 = reader.unpad(&padded1);
        assert_eq!(unpadded1, data1);

        let unpadded2 = reader.unpad(&padded2);
        assert_eq!(unpadded2, data2);
    }

    #[test]
    fn test_pad_first_frame_has_uuid() {
        let uuid = test_uuid();
        let mut filter = VisionFilter::new(uuid);

        let padded = filter.pad(b"test");
        // First frame should start with UUID
        assert_eq!(&padded[..16], &uuid);
        // Then command byte
        assert_eq!(padded[16], COMMAND_PADDING_CONTINUE);
        // Then content_len = 4
        assert_eq!(u16::from_be_bytes([padded[17], padded[18]]), 4);

        // Second frame should NOT have UUID
        let padded2 = filter.pad(b"test2");
        assert_ne!(&padded2[..16], &uuid);
        assert_eq!(padded2[0], COMMAND_PADDING_CONTINUE);
    }

    #[test]
    fn test_unpad_passthrough_no_uuid() {
        let uuid = test_uuid();
        let mut filter = VisionFilter::new(uuid);

        // Data that doesn't start with UUID → passthrough
        let data = b"not padded data";
        let result = filter.unpad(data);
        assert_eq!(result, data);
    }

    #[test]
    fn test_unpad_split_initial_frame() {
        let uuid = test_uuid();
        let mut writer = VisionFilter::new(uuid);
        let mut reader = VisionFilter::new(uuid);

        let padded = writer.pad(b"fragmented");
        assert_eq!(reader.unpad(&padded[..10]), b"");
        assert_eq!(reader.unpad(&padded[10..]), b"fragmented");
    }
}
