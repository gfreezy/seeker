use tracing::debug;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS13_CIPHER_AES_128_CCM_8_SHA256: u16 = 0x1305;
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS_HEADER_LEN: usize = 5;

/// TLS pattern detector for XTLS-Vision.
///
/// Analyzes up to 8 TLS records to detect ClientHello, ServerHello,
/// TLS version (1.2 vs 1.3), and cipher suite.
#[derive(Debug)]
pub struct VisionFilter {
    record_filter_count: usize,
    is_tls: bool,
    is_tls12_or_above: bool,
    supports_xtls: bool,
}

impl VisionFilter {
    pub fn new() -> Self {
        Self {
            record_filter_count: 8,
            is_tls: false,
            is_tls12_or_above: false,
            supports_xtls: false,
        }
    }

    pub fn is_filtering(&self) -> bool {
        self.record_filter_count > 0
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    #[allow(dead_code)]
    pub fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    pub fn supports_xtls(&self) -> bool {
        self.supports_xtls
    }

    pub fn decrement_filter_count(&mut self) {
        self.record_filter_count = self.record_filter_count.saturating_sub(1);
    }

    pub fn stop_filtering(&mut self) {
        self.record_filter_count = 0;
    }

    /// Analyze a complete TLS record for patterns.
    pub fn filter_record(&mut self, data: &[u8]) {
        if self.record_filter_count == 0 {
            return;
        }
        self.record_filter_count = self.record_filter_count.saturating_sub(1);

        if data.len() < 6 {
            self.stop_filtering();
            return;
        }

        // Detect ClientHello
        if !self.is_tls
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03
            && data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            self.is_tls = true;
            debug!("vision filter: detected ClientHello");
        }

        // Detect ServerHello
        if !self.is_tls12_or_above
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03
            && data[2] == 0x03
            && data[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            self.is_tls12_or_above = true;
            self.is_tls = true;

            match parse_server_hello(data) {
                Ok((cipher_suite, is_tls13)) => {
                    debug!(cipher_suite, is_tls13, "vision filter: parsed ServerHello");
                    if is_tls13 {
                        if cipher_suite == TLS13_CIPHER_AES_128_CCM_8_SHA256 {
                            debug!("vision filter: TLS 1.3 cipher 0x1305 not supported for XTLS");
                        } else {
                            self.supports_xtls = true;
                            debug!("vision filter: TLS 1.3 with XTLS support enabled");
                        }
                        self.stop_filtering();
                    }
                }
                Err(e) => {
                    debug!("vision filter: failed to parse ServerHello: {e}");
                    self.stop_filtering();
                }
            }
        }
    }
}

/// Parse ServerHello to extract cipher_suite and TLS 1.3 detection.
/// Returns (cipher_suite, is_tls13).
fn parse_server_hello(data: &[u8]) -> std::io::Result<(u16, bool)> {
    if data.len() < 47 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello too short",
        ));
    }

    let payload = &data[TLS_HEADER_LEN..];
    if payload.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello handshake header too short",
        ));
    }

    // Skip handshake type (1) + length (3) + version (2) + random (32)
    let mut pos = 4 + 2 + 32;
    if pos >= payload.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello truncated before session_id",
        ));
    }

    // Skip session_id
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 3 > payload.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello truncated before cipher/compression",
        ));
    }

    let cipher_suite = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    pos += 2;
    pos += 1; // compression method

    // Parse extensions for supported_versions
    let mut is_tls13 = false;
    if pos + 2 <= payload.len() {
        let extensions_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + extensions_len;

        while pos + 4 <= ext_end && pos + 4 <= payload.len() {
            let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
            pos += 4;

            if ext_type == TLS_EXT_SUPPORTED_VERSIONS && ext_len == 2 && pos + 2 <= payload.len() {
                is_tls13 = payload[pos] == 0x03 && payload[pos + 1] == 0x04;
            }
            pos += ext_len;
        }
    }

    Ok((cipher_suite, is_tls13))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_client_hello() {
        let mut f = VisionFilter::new();
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0];
        f.filter_record(&data);
        assert!(f.is_tls());
        assert!(!f.supports_xtls());
    }

    #[test]
    fn test_detect_server_hello_tls12() {
        let mut f = VisionFilter::new();
        let data = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0, 0, 0, 0];
        f.filter_record(&data);
        assert!(f.is_tls());
        assert!(f.is_tls12_or_above());
        // Too short to parse properly, so XTLS stays false
        assert!(!f.supports_xtls());
    }

    #[test]
    fn test_filtering_count() {
        let mut f = VisionFilter::new();
        for _ in 0..8 {
            f.filter_record(&[0x16, 0x03, 0x01, 0x00, 0x00, 0x00]);
        }
        assert!(!f.is_filtering());
    }
}
