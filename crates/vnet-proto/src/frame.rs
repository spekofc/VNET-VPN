//! Frame structure and types

use super::constants::*;
use crate::codec::{CodecError, Decode, Encode};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Frame type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrameType {
    /// Handshake initiation
    Handshake = 0x01,
    /// Handshake response
    HandshakeResponse = 0x02,
    /// Handshake confirmation
    HandshakeConfirm = 0x03,
    /// Encrypted data payload
    Data = 0x10,
    /// Control message (keepalive, ack, etc.)
    Control = 0x20,
    /// Key rotation / rekey
    Rekey = 0x30,
    /// Error / close notification
    Error = 0xFF,
}

impl FrameType {
    /// Convert from raw byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::HandshakeResponse),
            0x03 => Some(Self::HandshakeConfirm),
            0x10 => Some(Self::Data),
            0x20 => Some(Self::Control),
            0x30 => Some(Self::Rekey),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }

    /// Check if this frame type is a handshake frame
    pub fn is_handshake(&self) -> bool {
        matches!(
            self,
            Self::Handshake | Self::HandshakeResponse | Self::HandshakeConfirm
        )
    }

    /// Check if this frame type carries encrypted payload
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Data | Self::Control | Self::Rekey)
    }
}

/// Frame flags (bitfield)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// No flags
    pub const NONE: Self = Self(0x00);
    /// Frame is fragmented (more fragments follow)
    pub const FRAGMENTED: Self = Self(0x01);
    /// This is the last fragment
    pub const LAST_FRAGMENT: Self = Self(0x02);
    /// Request acknowledgment
    pub const ACK_REQUESTED: Self = Self(0x04);
    /// Frame contains padding
    pub const PADDED: Self = Self(0x08);
    /// High priority / expedited
    pub const PRIORITY: Self = Self(0x10);
    /// Encrypted with ChaCha20-Poly1305 (vs AES-GCM)
    pub const CHACHA20: Self = Self(0x20);
    /// Compressed payload
    pub const COMPRESSED: Self = Self(0x40);

    /// Create from raw byte
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u8 {
        self.0
    }

    /// Check if a flag is set
    pub const fn has(&self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Set a flag
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }
}

impl fmt::Display for FrameFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.has(Self::FRAGMENTED) {
            flags.push("FRAGMENTED");
        }
        if self.has(Self::LAST_FRAGMENT) {
            flags.push("LAST_FRAGMENT");
        }
        if self.has(Self::ACK_REQUESTED) {
            flags.push("ACK_REQUESTED");
        }
        if self.has(Self::PADDED) {
            flags.push("PADDED");
        }
        if self.has(Self::PRIORITY) {
            flags.push("PRIORITY");
        }
        if self.has(Self::CHACHA20) {
            flags.push("CHACHA20");
        }
        if self.has(Self::COMPRESSED) {
            flags.push("COMPRESSED");
        }
        if flags.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", flags.join(" | "))
        }
    }
}

/// Frame header (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    /// Magic bytes: "RDVP" (0x52445650)
    pub magic: u32,
    /// Protocol version
    pub version: u8,
    /// Frame type
    pub frame_type: FrameType,
    /// Flags
    pub flags: FrameFlags,
    /// Sequence number (for ordering and replay protection)
    pub sequence: u64,
    /// Session ID (16 bytes)
    pub session_id: [u8; SESSION_ID_SIZE],
    /// Payload length (excluding header and tag)
    pub payload_len: u16,
    /// Reserved for future use
    pub reserved: [u8; 6],
}

impl FrameHeader {
    /// Size of header in bytes
    pub const SIZE: usize = HEADER_SIZE;

    /// Create a new header
    pub fn new(
        frame_type: FrameType,
        flags: FrameFlags,
        sequence: u64,
        session_id: [u8; SESSION_ID_SIZE],
        payload_len: u16,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            frame_type,
            flags,
            sequence,
            session_id,
            payload_len,
            reserved: [0; 6],
        }
    }

    /// Validate header magic and version
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.magic != MAGIC {
            return Err(CodecError::InvalidMagic {
                expected: MAGIC,
                found: self.magic,
            });
        }
        if self.version != VERSION {
            return Err(CodecError::UnsupportedVersion { version: self.version });
        }
        if self.payload_len as usize > MAX_PAYLOAD_SIZE {
            return Err(CodecError::PayloadTooLarge { size: self.payload_len as usize });
        }
        Ok(())
    }
}

impl Encode for FrameHeader {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        buf.put_u32(self.magic);
        buf.put_u8(self.version);
        buf.put_u8(self.frame_type as u8);
        buf.put_u8(self.flags.bits());
        buf.put_u64(self.sequence);
        buf.put_slice(&self.session_id);
        buf.put_u16(self.payload_len);
        buf.put_slice(&self.reserved);
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        Self::SIZE
    }
}

impl Decode for FrameHeader {
    fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        if buf.remaining() < Self::SIZE {
            return Err(CodecError::BufferTooSmall {
                need: Self::SIZE,
                have: buf.remaining(),
            });
        }

        let magic = buf.get_u32();
        let version = buf.get_u8();
        let frame_type = FrameType::from_byte(buf.get_u8())
            .ok_or(CodecError::InvalidFrameType { frame_type: buf[3] })?;
        let flags = FrameFlags::from_bits(buf.get_u8());
        let sequence = buf.get_u64();
        let mut session_id = [0u8; SESSION_ID_SIZE];
        buf.copy_to_slice(&mut session_id);
        let payload_len = buf.get_u16();
        let mut reserved = [0u8; 6];
        buf.copy_to_slice(&mut reserved);

        let header = Self {
            magic,
            version,
            frame_type,
            flags,
            sequence,
            session_id,
            payload_len,
            reserved,
        };

        header.validate()?;
        Ok(header)
    }
}

/// Complete frame with header, payload, and authentication tag
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame header
    pub header: FrameHeader,
    /// Frame payload (plaintext for handshake, ciphertext for data)
    pub payload: Bytes,
    /// Authentication tag (HMAC-SHA256 or AEAD tag)
    pub tag: [u8; TAG_SIZE],
}

impl Frame {
    /// Create a new frame
    pub fn new(
        header: FrameHeader,
        payload: Bytes,
        tag: [u8; TAG_SIZE],
    ) -> Self {
        Self { header, payload, tag }
    }

    /// Total frame size (header + payload + tag)
    pub fn total_len(&self) -> usize {
        FrameHeader::SIZE + self.payload.len() + TAG_SIZE
    }

    /// Check if frame is a handshake frame
    pub fn is_handshake(&self) -> bool {
        self.header.frame_type.is_handshake()
    }

    /// Check if frame payload is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.header.frame_type.is_encrypted()
    }

    /// Get the AEAD algorithm from flags
    pub fn aead_algorithm(&self) -> AeadAlgorithm {
        if self.header.flags.has(FrameFlags::CHACHA20) {
            AeadAlgorithm::ChaCha20Poly1305
        } else {
            AeadAlgorithm::Aes256Gcm
        }
    }
}

impl Encode for Frame {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        self.header.encode(buf)?;
        buf.put_slice(&self.payload);
        buf.put_slice(&self.tag);
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.total_len()
    }
}

impl Decode for Frame {
    fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        let header = FrameHeader::decode(buf)?;
        let payload_len = header.payload_len as usize;

        if buf.remaining() < payload_len + TAG_SIZE {
            return Err(CodecError::BufferTooSmall {
                need: payload_len + TAG_SIZE,
                have: buf.remaining(),
            });
        }

        let mut payload = vec![0u8; payload_len];
        buf.copy_to_slice(&mut payload);

        let mut tag = [0u8; TAG_SIZE];
        buf.copy_to_slice(&mut tag);

        Ok(Self {
            header,
            payload: Bytes::from(payload),
            tag,
        })
    }
}

/// AEAD algorithm used for frame encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AeadAlgorithm {
    /// AES-256-GCM
    Aes256Gcm = 0x01,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 0x02,
}

impl AeadAlgorithm {
    /// Get key size for this algorithm
    pub const fn key_size(&self) -> usize {
        CHANNEL_KEY_SIZE
    }

    /// Get nonce size for this algorithm
    pub const fn nonce_size(&self) -> usize {
        NONCE_SIZE
    }

    /// Get tag size for this algorithm
    pub const fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}