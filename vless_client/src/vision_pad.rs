use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

pub const COMMAND_CONTINUE: u8 = 0x00;
pub const COMMAND_END: u8 = 0x01;
pub const COMMAND_DIRECT: u8 = 0x02;

const LONG_PADDING_MIN: usize = 900;
const LONG_PADDING_RANDOM_MAX: usize = 500;
const SHORT_PADDING_RANDOM_MAX: usize = 256;
const MAX_PADDING_SIZE: usize = 8171;

/// Pad data with UUID (first packet only) and command.
pub fn pad_with_uuid_and_command(data: &[u8], uuid: &[u8; 16], command: u8, is_tls: bool) -> Bytes {
    pad(data, Some(uuid), command, is_tls)
}

/// Pad data with command (no UUID).
pub fn pad_with_command(data: &[u8], command: u8, is_tls: bool) -> Bytes {
    pad(data, None, command, is_tls)
}

fn pad(data: &[u8], uuid: Option<&[u8; 16]>, command: u8, is_tls: bool) -> Bytes {
    let content_len = data.len() as u16;
    let padding_len = calculate_padding_length(data.len(), is_tls);

    let uuid_len = if uuid.is_some() { 16 } else { 0 };
    let total_size = uuid_len + 1 + 2 + 2 + data.len() + padding_len;

    let mut output = BytesMut::with_capacity(total_size);

    if let Some(uuid) = uuid {
        output.put_slice(uuid);
    }

    output.put_u8(command);
    output.put_u16(content_len);
    output.put_u16(padding_len as u16);
    output.put_slice(data);

    if padding_len > 0 {
        let padding_start = output.len();
        output.resize(padding_start + padding_len, 0);
        rand::rng().fill(&mut output[padding_start..]);
    }

    output.freeze()
}

fn calculate_padding_length(content_len: usize, is_tls: bool) -> usize {
    let mut rng = rand::rng();
    let max_allowable = MAX_PADDING_SIZE.saturating_sub(content_len);

    if is_tls && content_len < LONG_PADDING_MIN {
        let random_part: usize = rng.random_range(0..LONG_PADDING_RANDOM_MAX);
        let padding = LONG_PADDING_MIN
            .saturating_sub(content_len)
            .saturating_add(random_part);
        std::cmp::min(padding, max_allowable)
    } else {
        let padding: usize = rng.random_range(0..SHORT_PADDING_RANDOM_MAX);
        std::cmp::min(padding, max_allowable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_with_uuid() {
        let uuid = [0xAA; 16];
        let data = b"hello";
        let padded = pad_with_uuid_and_command(data, &uuid, COMMAND_CONTINUE, false);
        assert!(padded.len() >= 16 + 5 + data.len());
        assert_eq!(&padded[..16], &uuid);
        assert_eq!(padded[16], COMMAND_CONTINUE);
        let content_len = u16::from_be_bytes([padded[17], padded[18]]) as usize;
        assert_eq!(content_len, data.len());
        assert_eq!(&padded[21..21 + data.len()], data);
    }

    #[test]
    fn test_pad_without_uuid() {
        let data = b"world";
        let padded = pad_with_command(data, COMMAND_END, false);
        assert_eq!(padded[0], COMMAND_END);
        let content_len = u16::from_be_bytes([padded[1], padded[2]]) as usize;
        assert_eq!(content_len, data.len());
    }

    #[test]
    fn test_long_padding_for_tls() {
        let data = b"short";
        let padded = pad_with_command(data, COMMAND_CONTINUE, true);
        let padding_len = u16::from_be_bytes([padded[3], padded[4]]) as usize;
        assert!(padding_len >= LONG_PADDING_MIN - data.len());
    }
}
