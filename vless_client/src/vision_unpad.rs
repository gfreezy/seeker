use std::io;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpadCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for UnpadCommand {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UnpadCommand::Continue),
            1 => Ok(UnpadCommand::End),
            2 => Ok(UnpadCommand::Direct),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid padding command: {}", value),
            )),
        }
    }
}

#[derive(Debug, Default)]
pub struct UnpadResult {
    pub content: Vec<u8>,
    pub command: Option<UnpadCommand>,
}

#[derive(Debug, Clone)]
enum UnpadState {
    Initial { expected_uuid: [u8; 16] },
    ReadingCommand,
    ReadingContentLength {
        command: UnpadCommand,
        first_byte: Option<u8>,
    },
    ReadingPaddingLength {
        command: UnpadCommand,
        content_len: u16,
        first_byte: Option<u8>,
    },
    ReadingContent {
        command: UnpadCommand,
        partial_content: Vec<u8>,
        remaining_content_len: u16,
        padding_len: u16,
    },
    ReadingPadding {
        command: UnpadCommand,
        content: Vec<u8>,
        remaining_padding_len: u16,
    },
    Done,
}

#[derive(Debug, Clone)]
pub struct VisionUnpadder {
    state: UnpadState,
    first_block: bool,
    accumulated_buffer: Vec<u8>,
}

impl VisionUnpadder {
    pub fn new(expected_uuid: [u8; 16]) -> Self {
        Self {
            state: UnpadState::Initial { expected_uuid },
            first_block: true,
            accumulated_buffer: Vec::new(),
        }
    }

    /// Process input data and extract padding blocks.
    /// Accumulates content across Continue commands.
    /// Returns content eagerly when data runs out (prevents deadlock).
    pub fn unpad(&mut self, mut data: &[u8]) -> io::Result<UnpadResult> {
        self.accumulated_buffer.clear();

        loop {
            match &mut self.state {
                UnpadState::Initial { expected_uuid } => {
                    if data.len() < 16 {
                        return Ok(UnpadResult::default());
                    }
                    if data[..16] != *expected_uuid {
                        return Ok(UnpadResult {
                            content: data.to_vec(),
                            command: None,
                        });
                    }
                    data = &data[16..];
                    self.state = UnpadState::ReadingCommand;
                }

                UnpadState::ReadingCommand => {
                    if data.is_empty() {
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        return Ok(UnpadResult::default());
                    }
                    let command = UnpadCommand::try_from(data[0])?;
                    data = &data[1..];
                    self.state = UnpadState::ReadingContentLength {
                        command,
                        first_byte: None,
                    };
                }

                UnpadState::ReadingContentLength {
                    command,
                    first_byte,
                } => {
                    if data.is_empty() {
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        return Ok(UnpadResult::default());
                    }
                    match first_byte {
                        None => {
                            *first_byte = Some(data[0]);
                            data = &data[1..];
                        }
                        Some(high_byte) => {
                            let content_len = ((*high_byte as u16) << 8) | (data[0] as u16);
                            data = &data[1..];
                            self.state = UnpadState::ReadingPaddingLength {
                                command: *command,
                                content_len,
                                first_byte: None,
                            };
                        }
                    }
                }

                UnpadState::ReadingPaddingLength {
                    command,
                    content_len,
                    first_byte,
                } => {
                    if data.is_empty() {
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        return Ok(UnpadResult::default());
                    }
                    match first_byte {
                        None => {
                            *first_byte = Some(data[0]);
                            data = &data[1..];
                        }
                        Some(high_byte) => {
                            let padding_len = ((*high_byte as u16) << 8) | (data[0] as u16);
                            data = &data[1..];
                            debug!(
                                command = ?*command,
                                content_len = *content_len,
                                padding_len,
                                "vision unpad: parsed header"
                            );
                            self.state = UnpadState::ReadingContent {
                                command: *command,
                                partial_content: Vec::with_capacity(
                                    (*content_len as usize).min(data.len()),
                                ),
                                remaining_content_len: *content_len,
                                padding_len,
                            };
                        }
                    }
                }

                UnpadState::ReadingContent {
                    command,
                    partial_content,
                    remaining_content_len,
                    padding_len,
                } => {
                    if *remaining_content_len > 0 {
                        if data.is_empty() {
                            self.accumulated_buffer.append(partial_content);
                            if !self.first_block {
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: Some(UnpadCommand::Continue),
                                });
                            }
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: None,
                            });
                        }
                        let to_read = (*remaining_content_len as usize).min(data.len());
                        partial_content.extend_from_slice(&data[..to_read]);
                        data = &data[to_read..];
                        *remaining_content_len -= to_read as u16;
                    }

                    if *remaining_content_len == 0 {
                        let content = std::mem::take(partial_content);
                        self.state = UnpadState::ReadingPadding {
                            command: *command,
                            content,
                            remaining_padding_len: *padding_len,
                        };
                    }
                }

                UnpadState::ReadingPadding {
                    command,
                    content,
                    remaining_padding_len,
                } => {
                    if *remaining_padding_len > 0 {
                        if data.is_empty() {
                            // Return content eagerly to prevent deadlock.
                            // Don't return the command yet — wait until all padding is consumed.
                            self.accumulated_buffer.append(content);
                            if !self.first_block {
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: Some(UnpadCommand::Continue),
                                });
                            }
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: None,
                            });
                        }
                        let to_skip = (*remaining_padding_len as usize).min(data.len());
                        data = &data[to_skip..];
                        *remaining_padding_len -= to_skip as u16;
                    }

                    if *remaining_padding_len == 0 {
                        self.first_block = false;
                        self.accumulated_buffer.append(content);

                        match *command {
                            UnpadCommand::Continue => {
                                self.state = UnpadState::ReadingCommand;
                            }
                            end_or_direct => {
                                self.accumulated_buffer.extend_from_slice(data);
                                self.state = UnpadState::Done;
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: Some(end_or_direct),
                                });
                            }
                        }
                    }
                }

                UnpadState::Done => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unpadder already in Done state",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_end() {
        let uuid = [0u8; 16];
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut data = vec![0u8; 16]; // UUID
        data.extend_from_slice(&[1, 0, 5, 0, 3]); // End, content=5, padding=3
        data.extend_from_slice(&[1, 2, 3, 4, 5]); // content
        data.extend_from_slice(&[0, 0, 0]); // padding

        let result = unpadder.unpad(&data).unwrap();
        assert_eq!(result.content, vec![1, 2, 3, 4, 5]);
        assert_eq!(result.command, Some(UnpadCommand::End));
    }

    #[test]
    fn test_continue_then_end() {
        let uuid = [1u8; 16];
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut data = vec![1u8; 16];
        data.extend_from_slice(&[0, 0, 2, 0, 1, 10, 11, 0]); // Continue, 2 bytes, 1 pad
        data.extend_from_slice(&[1, 0, 2, 0, 1, 20, 21, 0]); // End, 2 bytes, 1 pad

        let result = unpadder.unpad(&data).unwrap();
        assert_eq!(result.content, vec![10, 11, 20, 21]);
        assert_eq!(result.command, Some(UnpadCommand::End));
    }

    #[test]
    fn test_non_xtls_data() {
        let uuid = [0u8; 16];
        let mut unpadder = VisionUnpadder::new(uuid);
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let result = unpadder.unpad(&data).unwrap();
        assert_eq!(result.content, data);
        assert_eq!(result.command, None);
    }

    #[test]
    fn test_direct_with_remaining() {
        let uuid = [2u8; 16];
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut data = vec![2u8; 16];
        data.extend_from_slice(&[2, 0, 3, 0, 2, 10, 11, 12, 0, 0]); // Direct, 3 content, 2 pad
        data.extend_from_slice(&[99, 98, 97]); // raw data after

        let result = unpadder.unpad(&data).unwrap();
        assert_eq!(result.content, vec![10, 11, 12, 99, 98, 97]);
        assert_eq!(result.command, Some(UnpadCommand::Direct));
    }

    #[test]
    fn test_incremental() {
        let uuid = [3u8; 16];
        let mut unpadder = VisionUnpadder::new(uuid);

        let mut chunk1 = vec![3u8; 16];
        chunk1.extend_from_slice(&[1, 0, 3]); // End, content_len high byte, partial
        let r1 = unpadder.unpad(&chunk1).unwrap();
        assert!(r1.content.is_empty());

        let chunk2 = vec![0, 2, 10, 11, 12, 0, 0]; // rest of header + content + padding
        let r2 = unpadder.unpad(&chunk2).unwrap();
        assert_eq!(r2.content, vec![10, 11, 12]);
        assert_eq!(r2.command, Some(UnpadCommand::End));
    }

    #[test]
    fn test_incomplete_padding_returns_content() {
        let uuid = [6u8; 16];
        let mut unpadder = VisionUnpadder::new(uuid);

        let mut chunk1 = vec![6u8; 16];
        chunk1.extend_from_slice(&[1, 0, 3, 0, 5, 10, 11, 12, 0, 0]); // End, 3 content, 5 pad, only 2 pad bytes
        let r1 = unpadder.unpad(&chunk1).unwrap();
        assert_eq!(r1.content, vec![10, 11, 12]);
        assert_eq!(r1.command, None); // command deferred until padding complete

        let chunk2 = vec![0, 0, 0]; // remaining 3 padding bytes
        let r2 = unpadder.unpad(&chunk2).unwrap();
        assert!(r2.content.is_empty());
        assert_eq!(r2.command, Some(UnpadCommand::End));
    }
}
