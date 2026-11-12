//! Frame codec for encoding/decoding

use super::frame::{Frame, FrameHeader, FrameFlags, FrameType};
use super::handshake::HandshakeMessage;
use super::message::{Message, ControlMessage, DataMessage};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use vnet_crypto::{aead::AeadKey, keys::ChannelKeys, AeadAlgorithm};
use thiserror::Error;

/// Codec errors
#[derive(Debug, Error)]
pub enum CodecError {
    #[error("Buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },
    #[error("Invalid magic: expected {expected:#010X}, found {found:#010X}")]
    InvalidMagic { expected: u32, found: u32 },
    #[error("Unsupported protocol version: {version}")]
    UnsupportedVersion { version: u8 },
    #[error("Invalid frame type: {frame_type}")]
    InvalidFrameType { frame_type: u8 },
    #[error("Invalid handshake subtype: {subtype}")]
    InvalidHandshakeSubtype { subtype: u8 },
    #[error("Invalid control message type: {msg_type}")]
    InvalidControlType { msg_type: u8 },
    #[error("Invalid AEAD algorithm")]
    InvalidAeadAlgorithm,
    #[error("Invalid IP version: {version}")]
    InvalidIpVersion { version: u8 },
    #[error("Invalid peer state")]
    InvalidPeerState,
    #[error("Payload too large: {size} bytes (max {})", super::constants::MAX_PAYLOAD_SIZE)]
    PayloadTooLarge { size: usize },
    #[error("Invalid tag size: expected {expected}, found {found}")]
    InvalidTagSize { expected: usize, found: usize },
    #[error("Invalid UTF-8 sequence")]
    InvalidUtf8,
    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },
    #[error("Tag verification failed")]
    TagVerificationFailed,
    #[error("Sequence number overflow")]
    SequenceOverflow,
    #[error("Replay detected: sequence {seq}")]
    ReplayDetected { seq: u64 },
    #[error("Missing session keys")]
    MissingSessionKeys,
    #[error("Invalid key size: expected {expected}, found {found}")]
    InvalidKeySize { expected: usize, found: usize },
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
}

/// Trait for encoding to bytes
pub trait Encode {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError>;
    fn encoded_len(&self) -> usize {
        0 // Default implementation - override for better performance
    }
}

/// Trait for decoding from bytes
pub trait Decode: Sized {
    fn decode(buf: &mut Bytes) -> Result<Self, CodecError>;
}

/// Frame codec for encrypting/decrypting frames
pub struct FrameCodec {
    /// Encryption keys for outbound frames
    enc_keys: ChannelKeys,
    /// Decryption keys for inbound frames
    dec_keys: ChannelKeys,
    /// Replay protection window
    replay_window: u64,
    /// Highest seen sequence number
    highest_sequence: u64,
    /// Bitmap of seen sequences (for replay protection)
    replay_bitmap: u64,
}

impl FrameCodec {
    /// Create new frame codec with channel keys
    pub fn new(enc_keys: ChannelKeys, dec_keys: ChannelKeys) -> Self {
        Self {
            enc_keys,
            dec_keys,
            replay_window: super::constants::REPLAY_WINDOW,
            highest_sequence: 0,
            replay_bitmap: 0,
        }
    }

    /// Create codec from session keys (client side)
    pub fn from_session_keys_client(
        session_keys: &vnet_crypto::keys::SessionKeys,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, vnet_crypto::error::CryptoError> {
        let enc_keys = session_keys.client_channel_keys(algorithm)?;
        let dec_keys = session_keys.server_channel_keys(algorithm)?;
        Ok(Self::new(enc_keys, dec_keys))
    }

    /// Create codec from session keys (server side)
    pub fn from_session_keys_server(
        session_keys: &vnet_crypto::keys::SessionKeys,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, vnet_crypto::error::CryptoError> {
        let enc_keys = session_keys.server_channel_keys(algorithm)?;
        let dec_keys = session_keys.client_channel_keys(algorithm)?;
        Ok(Self::new(enc_keys, dec_keys))
    }

    /// Encrypt a plaintext frame
    pub fn encrypt(&mut self, mut frame: Frame) -> Result<Frame, CodecError> {
        // Set sequence number
        frame.header.sequence = self.enc_keys.enc_nonce()[0] as u64; // Simplified
        
        // Encrypt payload
        let aad = self.header_to_aad(&frame.header);
        let mut payload = frame.payload.to_vec();
        self.enc_keys.encrypt(&aad, &mut payload)
            .map_err(|e| CodecError::EncryptionFailed { reason: e.to_string() })?;

        // Compute tag over header + payload
        let tag = self.compute_tag(&frame.header, &payload)?;

        Ok(Frame {
            header: frame.header,
            payload: Bytes::from(payload),
            tag,
        })
    }

    /// Decrypt an encrypted frame
    pub fn decrypt(&mut self, frame: Frame) -> Result<Frame, CodecError> {
        // Verify sequence number (replay protection)
        self.verify_sequence(frame.header.sequence)?;

        // Verify tag
        self.verify_tag(&frame.header, &frame.payload, &frame.tag)?;

        // Decrypt payload
        let aad = self.header_to_aad(&frame.header);
        let mut payload = frame.payload.to_vec();
        let len = self.dec_keys.decrypt(&aad, &mut payload)
            .map_err(|e| CodecError::DecryptionFailed { reason: e.to_string() })?;
        payload.truncate(len);

        // Update replay window
        self.update_replay(frame.header.sequence);

        Ok(Frame {
            header: frame.header,
            payload: Bytes::from(payload),
            tag: frame.tag,
        })
    }

    /// Encode a message into an encrypted frame
    pub fn encode_message(&mut self, msg: Message) -> Result<Frame, CodecError> {
        let (frame_type, payload) = match msg {
            Message::Handshake(h) => {
                let payload = h.encode()?;
                (h.frame_type(), payload)
            }
            Message::Control(c) => {
                let payload = c.encode()?;
                (FrameType::Control, payload)
            }
            Message::Data(d) => {
                let payload = d.packet;
                (FrameType::Data, payload)
            }
        };

        let header = FrameHeader::new(
            frame_type,
            FrameFlags::NONE,
            self.enc_keys.enc_nonce()[0] as u64, // Simplified
            [0; super::constants::SESSION_ID_SIZE], // Session ID from context
            payload.len() as u16,
        );

        let frame = Frame::new(header, payload, [0; super::constants::TAG_SIZE]);
        self.encrypt(frame)
    }

    /// Decode an encrypted frame into a message
    pub fn decode_message(&mut self, frame: Frame) -> Result<Message, CodecError> {
        let frame = self.decrypt(frame)?;

        match frame.header.frame_type {
            FrameType::Handshake | FrameType::HandshakeResponse | FrameType::HandshakeConfirm => {
                let msg = HandshakeMessage::decode(&mut frame.payload.clone())?;
                Ok(Message::Handshake(msg))
            }
            FrameType::Control => {
                let msg = ControlMessage::decode(&mut frame.payload.clone())?;
                Ok(Message::Control(msg))
            }
            FrameType::Data => {
                let msg = DataMessage::new(frame.payload);
                Ok(Message::Data(msg))
            }
            _ => Err(CodecError::InvalidFrameType { frame_type: frame.header.frame_type as u8 }),
        }
    }

    /// Compute authentication tag for frame
    fn compute_tag(&self, header: &FrameHeader, payload: &[u8]) -> Result<[u8; super::constants::TAG_SIZE], CodecError> {
        use vnet_crypto::mac::HmacSha256;
        // In practice, this would use the AEAD tag from encryption
        // For now, compute HMAC over header + payload
        let mac_key = self.enc_keys.enc_key.key_bytes();
        let hmac = HmacSha256::new(mac_key)
            .map_err(|e| CodecError::EncryptionFailed { reason: e.to_string() })?;
        
        let mut header_bytes = BytesMut::new();
        header.encode(&mut header_bytes)?;
        let mut streaming = hmac.streaming();
        streaming.update(&header_bytes);
        streaming.update(payload);
        let tag = streaming.finalize();
        
        let mut result = [0u8; super::constants::TAG_SIZE];
        result.copy_from_slice(&tag[..super::constants::TAG_SIZE]);
        Ok(result)
    }

    /// Verify authentication tag
    fn verify_tag(
        &self,
        header: &FrameHeader,
        payload: &[u8],
        tag: &[u8; super::constants::TAG_SIZE],
    ) -> Result<(), CodecError> {
        let expected = self.compute_tag(header, payload)?;
        if tag != &expected {
            return Err(CodecError::TagVerificationFailed);
        }
        Ok(())
    }

    /// Convert header to AAD for AEAD
    fn header_to_aad(&self, header: &FrameHeader) -> Bytes {
        let mut buf = BytesMut::new();
        header.encode(&mut buf).expect("Header encoding should not fail");
        buf.freeze()
    }

    /// Verify sequence number for replay protection
    fn verify_sequence(&self, sequence: u64) -> Result<(), CodecError> {
        if sequence <= self.highest_sequence.saturating_sub(self.replay_window) {
            return Err(CodecError::ReplayDetected { seq: sequence });
        }
        Ok(())
    }

    /// Update replay window
    fn update_replay(&mut self, sequence: u64) {
        if sequence > self.highest_sequence {
            let shift = sequence - self.highest_sequence;
            if shift >= 64 {
                self.replay_bitmap = 0;
            } else {
                self.replay_bitmap <<= shift as u32;
            }
            self.highest_sequence = sequence;
        }
        self.replay_bitmap |= 1u64 << (self.highest_sequence - sequence) as u32;
    }

    /// Get outbound channel keys
    pub fn enc_keys(&self) -> &ChannelKeys {
        &self.enc_keys
    }

    /// Get inbound channel keys
    pub fn dec_keys(&self) -> &ChannelKeys {
        &self.dec_keys
    }

    /// Get mutable outbound keys
    pub fn enc_keys_mut(&mut self) -> &mut ChannelKeys {
        &mut self.enc_keys
    }

    /// Get mutable inbound keys
    pub fn dec_keys_mut(&mut self) -> &mut ChannelKeys {
        &mut self.dec_keys
    }
}

/// Convenience functions for simple encode/decode
pub mod simple {
    use super::{CodecError, Encode, Decode};
    use bytes::{Bytes, BytesMut};

    /// Encode any type implementing Encode
    pub fn encode<T: Encode>(value: &T) -> Result<Bytes, CodecError> {
        let mut buf = BytesMut::with_capacity(value.encoded_len());
        value.encode(&mut buf)?;
        Ok(buf.freeze())
    }

    /// Decode any type implementing Decode
    pub fn decode<T: Decode>(bytes: Bytes) -> Result<T, CodecError> {
        let mut buf = bytes;
        T::decode(&mut buf)
    }
}