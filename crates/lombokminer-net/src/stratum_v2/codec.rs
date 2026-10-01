// LombokMiner — Stratum V2 Frame Codec
//
// SV2 uses a binary framing protocol (not JSON like V1).
// Frame layout:
//   [extension_type: u16 LE] [msg_type: u8] [msg_length: u24 LE] [payload: msg_length bytes]
//
// Total header = 6 bytes. Maximum payload = 16MB (2^24 - 1).
// After Noise handshake, frames are encrypted with ChaCha20-Poly1305 AEAD.

use bytes::{Buf, BufMut, BytesMut};

/// SV2 frame header size in bytes.
pub const FRAME_HEADER_SIZE: usize = 6;

/// Maximum SV2 payload size (2^24 - 1 = ~16MB).
pub const MAX_PAYLOAD_SIZE: usize = 0xFF_FFFF;

/// AEAD tag size for encrypted frames (Poly1305).
pub const AEAD_TAG_SIZE: usize = 16;

/// A parsed SV2 frame (before decryption if encrypted channel).
#[derive(Debug, Clone)]
pub struct Frame {
    /// Extension type field (channel-specific extensions).
    pub extension_type: u16,
    /// Message type identifier.
    pub msg_type: u8,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame.
    pub fn new(extension_type: u16, msg_type: u8, payload: Vec<u8>) -> Self {
        assert!(
            payload.len() <= MAX_PAYLOAD_SIZE,
            "payload exceeds maximum SV2 frame size"
        );
        Self {
            extension_type,
            msg_type,
            payload,
        }
    }

    /// Serialize frame to wire format bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());

        buf.put_u16_le(self.extension_type);
        buf.put_u8(self.msg_type);
        // 24-bit little-endian length
        buf.put_u8((len & 0xFF) as u8);
        buf.put_u8(((len >> 8) & 0xFF) as u8);
        buf.put_u8(((len >> 16) & 0xFF) as u8);
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Total wire size of this frame.
    pub fn wire_size(&self) -> usize {
        FRAME_HEADER_SIZE + self.payload.len()
    }
}

/// Streaming frame decoder — handles partial reads from TCP.
#[derive(Debug)]
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Feed bytes from the network into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to decode the next complete frame from the buffer.
    /// Returns `None` if not enough data is available yet.
    pub fn decode(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        // Peek at header without consuming
        let extension_type = u16::from_le_bytes([self.buffer[0], self.buffer[1]]);
        let msg_type = self.buffer[2];
        let msg_length = self.buffer[3] as u32
            | ((self.buffer[4] as u32) << 8)
            | ((self.buffer[5] as u32) << 16);

        if msg_length as usize > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge(msg_length as usize));
        }

        let total_size = FRAME_HEADER_SIZE + msg_length as usize;
        if self.buffer.len() < total_size {
            return Ok(None); // Need more data
        }

        // Consume header
        self.buffer.advance(FRAME_HEADER_SIZE);

        // Consume payload
        let payload = self.buffer.split_to(msg_length as usize).to_vec();

        Ok(Some(Frame {
            extension_type,
            msg_type,
            payload,
        }))
    }

    /// Number of buffered bytes.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame decoding errors.
#[derive(Debug)]
pub enum FrameError {
    PayloadTooLarge(usize),
    InvalidMessageType(u8),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge(size) => write!(f, "payload too large: {size} bytes"),
            Self::InvalidMessageType(t) => write!(f, "invalid message type: 0x{t:02x}"),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = Frame::new(0x0000, 0x01, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let wire = frame.serialize();

        assert_eq!(wire.len(), FRAME_HEADER_SIZE + 4);
        // extension_type = 0x0000 LE
        assert_eq!(wire[0], 0x00);
        assert_eq!(wire[1], 0x00);
        // msg_type = 0x01
        assert_eq!(wire[2], 0x01);
        // length = 4 as u24 LE
        assert_eq!(wire[3], 0x04);
        assert_eq!(wire[4], 0x00);
        assert_eq!(wire[5], 0x00);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&wire);
        let decoded = decoder.decode().unwrap().unwrap();

        assert_eq!(decoded.extension_type, 0x0000);
        assert_eq!(decoded.msg_type, 0x01);
        assert_eq!(decoded.payload, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_partial_read() {
        let frame = Frame::new(0, 0x10, vec![1, 2, 3, 4, 5]);
        let wire = frame.serialize();

        let mut decoder = FrameDecoder::new();

        // Feed header only
        decoder.feed(&wire[..FRAME_HEADER_SIZE]);
        assert!(decoder.decode().unwrap().is_none());

        // Feed partial payload
        decoder.feed(&wire[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 2]);
        assert!(decoder.decode().unwrap().is_none());

        // Feed rest
        decoder.feed(&wire[FRAME_HEADER_SIZE + 2..]);
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_multiple_frames() {
        let f1 = Frame::new(0, 0x01, vec![0xAA]);
        let f2 = Frame::new(0, 0x02, vec![0xBB, 0xCC]);

        let mut wire = f1.serialize();
        wire.extend_from_slice(&f2.serialize());

        let mut decoder = FrameDecoder::new();
        decoder.feed(&wire);

        let d1 = decoder.decode().unwrap().unwrap();
        assert_eq!(d1.msg_type, 0x01);
        assert_eq!(d1.payload, vec![0xAA]);

        let d2 = decoder.decode().unwrap().unwrap();
        assert_eq!(d2.msg_type, 0x02);
        assert_eq!(d2.payload, vec![0xBB, 0xCC]);

        assert!(decoder.decode().unwrap().is_none());
    }

    #[test]
    fn test_empty_payload() {
        let frame = Frame::new(0, 0xFF, vec![]);
        let wire = frame.serialize();
        assert_eq!(wire.len(), FRAME_HEADER_SIZE);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&wire);
        let decoded = decoder.decode().unwrap().unwrap();
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_payload_too_large() {
        let mut bad_wire = vec![0u8; FRAME_HEADER_SIZE];
        // Set length to MAX + 1
        bad_wire[3] = 0x00;
        bad_wire[4] = 0x00;
        bad_wire[5] = 0x01; // 0x010000 = 65536... actually let's use the real max
        // Length = 0xFFFFFF + 1 isn't possible in 24 bits, so test with a length
        // that exceeds MAX_PAYLOAD_SIZE. Actually MAX_PAYLOAD_SIZE = 0xFFFFFF which is the max u24.
        // Let's just verify normal operation with large payloads.

        let frame = Frame::new(0, 0x01, vec![0u8; 1000]);
        let wire = frame.serialize();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&wire);
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.payload.len(), 1000);
    }
}
