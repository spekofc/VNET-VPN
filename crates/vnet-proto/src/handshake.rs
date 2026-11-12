//! Handshake protocol and state machine

use super::frame::{Frame, FrameHeader, FrameType, FrameFlags, AeadAlgorithm};
use super::constants::*;
use crate::codec::{CodecError, Decode, Encode};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use vnet_nat::ice::{IceCandidate, CandidateType};

/// Handshake state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeState {
    /// Initial state, waiting to send ClientHello
    ClientInit,
    /// Sent ClientHello, waiting for ServerHello
    ClientWaitingServerHello,
    /// Received ServerHello, sending ClientAuth
    ClientSendingAuth,
    /// Sent ClientAuth, waiting for Confirm
    ClientWaitingConfirm,
    /// Handshake complete
    Established,
    /// Initial state, waiting for ClientHello
    ServerInit,
    /// Received ClientHello, sending ServerHello
    ServerSendingHello,
    /// Received ClientAuth, verifying
    ServerVerifyingAuth,
    /// Sending Confirm
    ServerSendingConfirm,
    /// Handshake failed
    Failed,
}

impl HandshakeState {
    /// Check if handshake is complete
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Established)
    }

    /// Check if handshake failed
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Check if we're in a client role
    pub fn is_client(&self) -> bool {
        matches!(
            self,
            Self::ClientInit
                | Self::ClientWaitingServerHello
                | Self::ClientSendingAuth
                | Self::ClientWaitingConfirm
        )
    }

    /// Check if we're in a server role
    pub fn is_server(&self) -> bool {
        matches!(
            self,
            Self::ServerInit
                | Self::ServerSendingHello
                | Self::ServerVerifyingAuth
                | Self::ServerSendingConfirm
        )
    }
}

/// Handshake message types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Client hello: contains client's ECDH public key, supported algorithms, session ID, and ICE candidates
    ClientHello {
        /// Client's ephemeral ECDH public key (compressed, 33 bytes)
        ecdh_public: Vec<u8>,
        /// Supported AEAD algorithms (bitmap)
        aead_algorithms: u8,
        /// Client's session ID
        session_id: [u8; SESSION_ID_SIZE],
        /// Protocol version
        version: u8,
        /// Random nonce (32 bytes)
        nonce: [u8; 32],
        /// ICE candidates for NAT traversal
        ice_candidates: Vec<IceCandidate>,
    },
    /// Server hello: contains server's ECDH public key, selected algorithm, session ID, and ICE candidates
    ServerHello {
        /// Server's ephemeral ECDH public key (compressed, 33 bytes)
        ecdh_public: Vec<u8>,
        /// Selected AEAD algorithm
        aead_algorithm: AeadAlgorithm,
        /// Server's session ID
        session_id: [u8; SESSION_ID_SIZE],
        /// Protocol version
        version: u8,
        /// Random nonce (32 bytes)
        nonce: [u8; 32],
        /// Cookie for DoS protection (optional)
        cookie: Option<Vec<u8>>,
        /// ICE candidates for NAT traversal
        ice_candidates: Vec<IceCandidate>,
    },
    /// Client authentication: contains proof of possession of static key
    ClientAuth {
        /// Client's long-term static public key (compressed, 33 bytes)
        static_public: Vec<u8>,
        /// Signature over transcript hash using static private key
        signature: Vec<u8>,
        /// Optional certificate chain
        certificates: Vec<Vec<u8>>,
    },
    /// Server authentication (mutual auth)
    ServerAuth {
        /// Server's long-term static public key (compressed, 33 bytes)
        static_public: Vec<u8>,
        /// Signature over transcript hash using static private key
        signature: Vec<u8>,
        /// Optional certificate chain
        certificates: Vec<Vec<u8>>,
    },
    /// Handshake confirmation: contains handshake transcript hash
    Confirm {
        /// HMAC-SHA256 of handshake transcript using confirm key
        confirm_tag: [u8; 32],
    },
    /// Error message
    Error {
        /// Error code
        code: u16,
        /// Human-readable message
        message: String,
    },
}

impl HandshakeMessage {
    /// Get the message type as a frame type
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::ClientHello { .. } => FrameType::Handshake,
            Self::ServerHello { .. } => FrameType::HandshakeResponse,
            Self::ClientAuth { .. } | Self::ServerAuth { .. } => FrameType::Handshake,
            Self::Confirm { .. } => FrameType::HandshakeConfirm,
            Self::Error { .. } => FrameType::Error,
        }
    }

    /// Serialize to bytes
    pub fn encode(&self) -> Result<Bytes, CodecError> {
        let mut buf = BytesMut::new();
        Encode::encode(self, &mut buf)?;
        Ok(buf.freeze())
    }

    /// Deserialize from bytes
    pub fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        Decode::decode(buf)
    }
}

impl Encode for HandshakeMessage {
    fn encode(&self, buf: &mut BytesMut) -> Result<(), CodecError> {
        match self {
            Self::ClientHello {
                ecdh_public,
                aead_algorithms,
                session_id,
                version,
                nonce,
                ice_candidates,
            } => {
                buf.put_u8(0x01); // message subtype
                buf.put_slice(ecdh_public);
                buf.put_u8(*aead_algorithms);
                buf.put_slice(session_id);
                buf.put_u8(*version);
                buf.put_slice(nonce);
                // Encode ICE candidates
                buf.put_u16(ice_candidates.len() as u16);
                for candidate in ice_candidates {
                    encode_ice_candidate(candidate, buf)?;
                }
            }
            Self::ServerHello {
                ecdh_public,
                aead_algorithm,
                session_id,
                version,
                nonce,
                cookie,
                ice_candidates,
            } => {
                buf.put_u8(0x02);
                buf.put_slice(ecdh_public);
                buf.put_u8(*aead_algorithm as u8);
                buf.put_slice(session_id);
                buf.put_u8(*version);
                buf.put_slice(nonce);
                if let Some(c) = cookie {
                    buf.put_u8(0x01);
                    buf.put_slice(&c);
                } else {
                    buf.put_u8(0x00);
                }
                // Encode ICE candidates
                buf.put_u16(ice_candidates.len() as u16);
                for candidate in ice_candidates {
                    encode_ice_candidate(candidate, buf)?;
                }
            }
            Self::ClientAuth {
                static_public,
                signature,
                certificates,
            } => {
                buf.put_u8(0x03);
                buf.put_slice(static_public);
                buf.put_u16(signature.len() as u16);
                buf.put_slice(signature);
                buf.put_u16(certificates.len() as u16);
                for cert in certificates {
                    buf.put_u16(cert.len() as u16);
                    buf.put_slice(cert);
                }
            }
            Self::ServerAuth {
                static_public,
                signature,
                certificates,
            } => {
                buf.put_u8(0x04);
                buf.put_slice(static_public);
                buf.put_u16(signature.len() as u16);
                buf.put_slice(signature);
                buf.put_u16(certificates.len() as u16);
                for cert in certificates {
                    buf.put_u16(cert.len() as u16);
                    buf.put_slice(cert);
                }
            }
            Self::Confirm { confirm_tag } => {
                buf.put_u8(0x05);
                buf.put_slice(confirm_tag);
            }
            Self::Error { code, message } => {
                buf.put_u8(0xFF);
                buf.put_u16(*code);
                let msg_bytes = message.as_bytes();
                buf.put_u16(msg_bytes.len() as u16);
                buf.put_slice(msg_bytes);
            }
        }
        Ok(())
    }
}

impl Decode for HandshakeMessage {
    fn decode(buf: &mut Bytes) -> Result<Self, CodecError> {
        if buf.is_empty() {
            return Err(CodecError::BufferTooSmall {
                need: 1,
                have: 0,
            });
        }

        let subtype = buf.get_u8();
        match subtype {
            0x01 => {
                // ClientHello
                if buf.remaining() < ECDH_PUBLIC_KEY_COMPRESSED + 1 + SESSION_ID_SIZE + 1 + 32 + 2 {
                    return Err(CodecError::BufferTooSmall {
                        need: ECDH_PUBLIC_KEY_COMPRESSED + 1 + SESSION_ID_SIZE + 1 + 32 + 2,
                        have: buf.remaining(),
                    });
                }
                let mut ecdh_public = vec![0u8; ECDH_PUBLIC_KEY_COMPRESSED];
                buf.copy_to_slice(&mut ecdh_public);
                let aead_algorithms = buf.get_u8();
                let mut session_id = [0u8; SESSION_ID_SIZE];
                buf.copy_to_slice(&mut session_id);
                let version = buf.get_u8();
                let mut nonce = [0u8; 32];
                buf.copy_to_slice(&mut nonce);
                // Decode ICE candidates
                let num_candidates = buf.get_u16() as usize;
                let mut ice_candidates = Vec::with_capacity(num_candidates);
                for _ in 0..num_candidates {
                    ice_candidates.push(decode_ice_candidate(buf)?);
                }
                Ok(Self::ClientHello {
                    ecdh_public,
                    aead_algorithms,
                    session_id,
                    version,
                    nonce,
                    ice_candidates,
                })
            }
            0x02 => {
                // ServerHello
                if buf.remaining() < ECDH_PUBLIC_KEY_COMPRESSED + 1 + SESSION_ID_SIZE + 1 + 32 + 1 + 2 {
                    return Err(CodecError::BufferTooSmall {
                        need: ECDH_PUBLIC_KEY_COMPRESSED + 1 + SESSION_ID_SIZE + 1 + 32 + 1 + 2,
                        have: buf.remaining(),
                    });
                }
                let mut ecdh_public = vec![0u8; ECDH_PUBLIC_KEY_COMPRESSED];
                buf.copy_to_slice(&mut ecdh_public);
                let aead_algorithm = AeadAlgorithm::try_from(buf.get_u8())
                    .map_err(|_| CodecError::InvalidAeadAlgorithm)?;
                let mut session_id = [0u8; SESSION_ID_SIZE];
                buf.copy_to_slice(&mut session_id);
                let version = buf.get_u8();
                let mut nonce = [0u8; 32];
                buf.copy_to_slice(&mut nonce);
                let has_cookie = buf.get_u8();
                let cookie = if has_cookie != 0 {
                    if buf.remaining() < COOKIE_SIZE {
                        return Err(CodecError::BufferTooSmall {
                            need: COOKIE_SIZE,
                            have: buf.remaining(),
                        });
                    }
                    let mut cookie = vec![0u8; COOKIE_SIZE];
                    buf.copy_to_slice(&mut cookie);
                    Some(cookie)
                } else {
                    None
                };
                // Decode ICE candidates
                let num_candidates = buf.get_u16() as usize;
                let mut ice_candidates = Vec::with_capacity(num_candidates);
                for _ in 0..num_candidates {
                    ice_candidates.push(decode_ice_candidate(buf)?);
                }
                Ok(Self::ServerHello {
                    ecdh_public,
                    aead_algorithm,
                    session_id,
                    version,
                    nonce,
                    cookie,
                    ice_candidates,
                })
            }
            0x03 => {
                // ClientAuth
                if buf.remaining() < ECDH_PUBLIC_KEY_COMPRESSED + 2 {
                    return Err(CodecError::BufferTooSmall {
                        need: ECDH_PUBLIC_KEY_COMPRESSED + 2,
                        have: buf.remaining(),
                    });
                }
                let mut static_public = vec![0u8; ECDH_PUBLIC_KEY_COMPRESSED];
                buf.copy_to_slice(&mut static_public);
                let sig_len = buf.get_u16() as usize;
                if buf.remaining() < sig_len {
                    return Err(CodecError::BufferTooSmall {
                        need: sig_len,
                        have: buf.remaining(),
                    });
                }
                let mut signature = vec![0u8; sig_len];
                buf.copy_to_slice(&mut signature);
                let cert_count = buf.get_u16() as usize;
                let mut certificates = Vec::with_capacity(cert_count);
                for _ in 0..cert_count {
                    if buf.remaining() < 2 {
                        return Err(CodecError::BufferTooSmall {
                            need: 2,
                            have: buf.remaining(),
                        });
                    }
                    let cert_len = buf.get_u16() as usize;
                    if buf.remaining() < cert_len {
                        return Err(CodecError::BufferTooSmall {
                            need: cert_len,
                            have: buf.remaining(),
                        });
                    }
                    let mut cert = vec![0u8; cert_len];
                    buf.copy_to_slice(&mut cert);
                    certificates.push(cert);
                }
                Ok(Self::ClientAuth {
                    static_public,
                    signature,
                    certificates,
                })
            }
            0x04 => {
                // ServerAuth
                if buf.remaining() < ECDH_PUBLIC_KEY_COMPRESSED + 2 {
                    return Err(CodecError::BufferTooSmall {
                        need: ECDH_PUBLIC_KEY_COMPRESSED + 2,
                        have: buf.remaining(),
                    });
                }
                let mut static_public = vec![0u8; ECDH_PUBLIC_KEY_COMPRESSED];
                buf.copy_to_slice(&mut static_public);
                let sig_len = buf.get_u16() as usize;
                if buf.remaining() < sig_len {
                    return Err(CodecError::BufferTooSmall {
                        need: sig_len,
                        have: buf.remaining(),
                    });
                }
                let mut signature = vec![0u8; sig_len];
                buf.copy_to_slice(&mut signature);
                let cert_count = buf.get_u16() as usize;
                let mut certificates = Vec::with_capacity(cert_count);
                for _ in 0..cert_count {
                    if buf.remaining() < 2 {
                        return Err(CodecError::BufferTooSmall {
                            need: 2,
                            have: buf.remaining(),
                        });
                    }
                    let cert_len = buf.get_u16() as usize;
                    if buf.remaining() < cert_len {
                        return Err(CodecError::BufferTooSmall {
                            need: cert_len,
                            have: buf.remaining(),
                        });
                    }
                    let mut cert = vec![0u8; cert_len];
                    buf.copy_to_slice(&mut cert);
                    certificates.push(cert);
                }
                Ok(Self::ServerAuth {
                    static_public,
                    signature,
                    certificates,
                })
            }
            0x05 => {
                // Confirm
                if buf.remaining() < 32 {
                    return Err(CodecError::BufferTooSmall {
                        need: 32,
                        have: buf.remaining(),
                    });
                }
                let mut confirm_tag = [0u8; 32];
                buf.copy_to_slice(&mut confirm_tag);
                Ok(Self::Confirm { confirm_tag })
            }
            0xFF => {
                // Error
                if buf.remaining() < 4 {
                    return Err(CodecError::BufferTooSmall {
                        need: 4,
                        have: buf.remaining(),
                    });
                }
                let code = buf.get_u16();
                let msg_len = buf.get_u16() as usize;
                if buf.remaining() < msg_len {
                    return Err(CodecError::BufferTooSmall {
                        need: msg_len,
                        have: buf.remaining(),
                    });
                }
                let mut msg_bytes = vec![0u8; msg_len];
                buf.copy_to_slice(&mut msg_bytes);
                let message = String::from_utf8(msg_bytes)
                    .map_err(|_| CodecError::InvalidUtf8)?;
                Ok(Self::Error { code, message })
            }
            _ => Err(CodecError::InvalidHandshakeSubtype { subtype }),
        }
    }
}

/// Handshake transcript for confirm key derivation
#[derive(Debug, Clone)]
pub struct HandshakeTranscript {
    /// All handshake messages in order
    messages: Vec<Bytes>,
}

impl HandshakeTranscript {
    /// Create new transcript
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Add a message to the transcript
    pub fn add(&mut self, message: &HandshakeMessage) -> Result<(), CodecError> {
        let encoded = message.encode()?;
        self.messages.push(encoded);
        Ok(())
    }

    /// Compute transcript hash (SHA-256 of all messages)
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for msg in &self.messages {
            hasher.update(msg);
        }
        hasher.finalize().into()
    }

    /// Get transcript length
    pub fn len(&self) -> usize {
        self.messages.iter().map(|m| m.len()).sum()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Handshake error types
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Invalid handshake state: {0}")]
    InvalidState(String),
    #[error("Timeout waiting for {0}")]
    Timeout(String),
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Key agreement failed: {0}")]
    KeyAgreementFailed(String),
    #[error("Confirm mismatch")]
    ConfirmMismatch,
    #[error("Replay detected")]
    ReplayDetected,
    #[error("Codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] vnet_crypto::error::CryptoError),
}

/// Handshake context for managing state
pub struct HandshakeContext {
    /// Current state
    state: HandshakeState,
    /// Local session ID
    local_session_id: [u8; SESSION_ID_SIZE],
    /// Remote session ID
    remote_session_id: [u8; SESSION_ID_SIZE],
    /// Handshake transcript
    transcript: HandshakeTranscript,
    /// Selected AEAD algorithm
    aead_algorithm: AeadAlgorithm,
    /// Local ephemeral ECDH key pair
    local_ecdh: Option<vnet_crypto::ecdh::EcdhKeyPair>,
    /// Remote ephemeral ECDH public key
    remote_ecdh_public: Option<[u8; ECDH_PUBLIC_KEY_COMPRESSED]>,
    /// Local static key pair (for auth)
    local_static: Option<vnet_crypto::signature::SignatureKeyPair>,
    /// Remote static public key
    remote_static_public: Option<[u8; ECDH_PUBLIC_KEY_COMPRESSED]>,
    /// Derived session keys
    session_keys: Option<vnet_crypto::keys::SessionKeys>,
    /// Handshake start time
    start_time: Instant,
    /// Timeout
    timeout: Duration,
    /// Sequence number for frames
    sequence: u64,
}

impl HandshakeContext {
    /// Create new client handshake context
    pub fn new_client(
        local_session_id: [u8; SESSION_ID_SIZE],
        static_key: Option<vnet_crypto::signature::SignatureKeyPair>,
    ) -> Self {
        Self {
            state: HandshakeState::ClientInit,
            local_session_id,
            remote_session_id: [0; SESSION_ID_SIZE],
            transcript: HandshakeTranscript::new(),
            aead_algorithm: AeadAlgorithm::ChaCha20Poly1305,
            local_ecdh: None,
            remote_ecdh_public: None,
            local_static: static_key,
            remote_static_public: None,
            session_keys: None,
            start_time: Instant::now(),
            timeout: Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
            sequence: 0,
        }
    }

    /// Create new server handshake context
    pub fn new_server(
        local_session_id: [u8; SESSION_ID_SIZE],
        static_key: Option<vnet_crypto::signature::SignatureKeyPair>,
    ) -> Self {
        Self {
            state: HandshakeState::ServerInit,
            local_session_id,
            remote_session_id: [0; SESSION_ID_SIZE],
            transcript: HandshakeTranscript::new(),
            aead_algorithm: AeadAlgorithm::ChaCha20Poly1305,
            local_ecdh: None,
            remote_ecdh_public: None,
            local_static: static_key,
            remote_static_public: None,
            session_keys: None,
            start_time: Instant::now(),
            timeout: Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
            sequence: 0,
        }
    }

    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Check if handshake is complete
    pub fn is_established(&self) -> bool {
        self.state.is_established()
    }

    /// Check if handshake timed out
    pub fn is_timed_out(&self) -> bool {
        self.start_time.elapsed() > self.timeout
    }

    /// Get derived session keys
    pub fn session_keys(&self) -> Option<&vnet_crypto::keys::SessionKeys> {
        self.session_keys.as_ref()
    }

    /// Get selected AEAD algorithm
    pub fn aead_algorithm(&self) -> AeadAlgorithm {
        self.aead_algorithm
    }

    /// Get local session ID
    pub fn local_session_id(&self) -> [u8; SESSION_ID_SIZE] {
        self.local_session_id
    }

    /// Get remote session ID
    pub fn remote_session_id(&self) -> [u8; SESSION_ID_SIZE] {
        self.remote_session_id
    }

    /// Get next sequence number
    pub fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;
        seq
    }

    /// Build initial ClientHello message (for client-initiated handshakes)
    pub fn build_client_hello(&mut self) -> Result<HandshakeMessage, HandshakeError> {
        self.build_client_hello_with_candidates(Vec::new())
    }

    /// Build initial ClientHello message with ICE candidates (for NAT traversal)
    pub fn build_client_hello_with_candidates(&mut self, ice_candidates: Vec<IceCandidate>) -> Result<HandshakeMessage, HandshakeError> {
        let ecdh = vnet_crypto::ecdh::EcdhKeyPair::generate()?;
        let ecdh_public = ecdh.public_key().to_compressed_bytes();
        self.local_ecdh = Some(ecdh);

        let mut nonce = [0u8; 32];
        vnet_crypto::rand::secure_random(&mut nonce)?;

        let msg = HandshakeMessage::ClientHello {
            ecdh_public: ecdh_public.to_vec(),
            aead_algorithms: 0x03, // AES-GCM | ChaCha20-Poly1305
            session_id: self.local_session_id,
            version: VERSION,
            nonce,
            ice_candidates,
        };
        self.transcript.add(&msg)?;
        self.state = HandshakeState::ClientWaitingServerHello;
        Ok(msg)
    }

    /// Process incoming handshake message
    pub fn process_message(
        &mut self,
        message: HandshakeMessage,
    ) -> Result<Option<HandshakeMessage>, HandshakeError> {
        // Add to transcript
        self.transcript.add(&message)?;

        match (&self.state, &message) {
            // Client receives ServerHello
            (HandshakeState::ClientWaitingServerHello, HandshakeMessage::ServerHello { .. }) => {
                self.state = HandshakeState::ClientSendingAuth;
                Ok(self.build_client_auth()?)
            }
            // Server receives ClientHello
            (HandshakeState::ServerInit, HandshakeMessage::ClientHello { .. }) => {
                self.state = HandshakeState::ServerSendingHello;
                Ok(Some(self.build_server_hello()?))
            }
            // Server receives ClientAuth
            (HandshakeState::ServerVerifyingAuth, HandshakeMessage::ClientAuth { .. }) => {
                self.verify_client_auth(&message)?;
                self.state = HandshakeState::ServerSendingConfirm;
                Ok(Some(self.build_confirm()?))
            }
            // Client receives Confirm
            (HandshakeState::ClientWaitingConfirm, HandshakeMessage::Confirm { .. }) => {
                self.verify_confirm(&message)?;
                self.derive_session_keys()?;
                self.state = HandshakeState::Established;
                Ok(None)
            }
            // Error message
            (_, HandshakeMessage::Error { code, message }) => {
                self.state = HandshakeState::Failed;
                Err(HandshakeError::AuthFailed(format!(
                    "Remote error {}: {}",
                    code, message
                )))
            }
            _ => Err(HandshakeError::InvalidState(format!(
                "Unexpected message {:?} in state {:?}",
                message.frame_type(),
                self.state
            ))),
        }
    } 

    /// Build ServerHello message
    fn build_server_hello(&mut self) -> Result<HandshakeMessage, HandshakeError> {
        let ecdh = vnet_crypto::ecdh::EcdhKeyPair::generate()?;
        let ecdh_public = ecdh.public_key().to_compressed_bytes();
        self.local_ecdh = Some(ecdh);

        let mut nonce = [0u8; 32];
        vnet_crypto::rand::secure_random(&mut nonce)?;

        let msg = HandshakeMessage::ServerHello {
            ecdh_public: ecdh_public.to_vec(),
            aead_algorithm: self.aead_algorithm,
            session_id: self.local_session_id,
            version: VERSION,
            nonce,
            cookie: None,
            ice_candidates: Vec::new(),
        };
        self.transcript.add(&msg)?;
        Ok(msg)
    }

    /// Build ClientAuth message
    fn build_client_auth(&mut self) -> Result<Option<HandshakeMessage>, HandshakeError> {
        let static_key = self.local_static.as_ref()
            .ok_or(HandshakeError::AuthFailed("No static key configured".into()))?;

        let static_public = static_key.verifying_key().to_compressed_bytes();
        let transcript_hash = self.transcript.hash();
        let signature = static_key.sign(&transcript_hash)?;

        let msg = HandshakeMessage::ClientAuth {
            static_public: static_public.to_vec(),
            signature: signature.to_raw()?.to_vec(),
            certificates: Vec::new(),
        };
        self.transcript.add(&msg)?;
        Ok(Some(msg))
    }

    /// Verify ClientAuth message
    fn verify_client_auth(&mut self, message: &HandshakeMessage) -> Result<(), HandshakeError> {
        let HandshakeMessage::ClientAuth {
            static_public,
            signature,
            ..
        } = message else {
            return Err(HandshakeError::InvalidMessage("Expected ClientAuth".into()));
        };

        self.remote_static_public = Some(static_public.as_slice().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid static public key length".into()))?);

        let verifying_key = vnet_crypto::signature::VerifyingKey::from_compressed_bytes(static_public)?;
        let sig = vnet_crypto::signature::Signature::from_raw(signature)?;
        let transcript_hash = self.transcript.hash();

        if !verifying_key.verify(&transcript_hash, &sig)? {
            return Err(HandshakeError::AuthFailed("Invalid signature".into()));
        }

        self.state = HandshakeState::ServerVerifyingAuth;
        Ok(())
    }

    /// Build Confirm message
    fn build_confirm(&mut self) -> Result<HandshakeMessage, HandshakeError> {
        // Derive confirm key from handshake
        let confirm_key = self.derive_confirm_key()?;
        let transcript_hash = self.transcript.hash();
        let hmac = vnet_crypto::mac::HmacSha256::new(&confirm_key)?;
        let confirm_tag = hmac.sign(&transcript_hash);

        let msg = HandshakeMessage::Confirm {
            confirm_tag,
        };
        self.transcript.add(&msg)?;
        Ok(msg)
    }

    /// Verify Confirm message
    fn verify_confirm(&mut self, message: &HandshakeMessage) -> Result<(), HandshakeError> {
        let HandshakeMessage::Confirm { confirm_tag } = message else {
            return Err(HandshakeError::InvalidMessage("Expected Confirm".into()));
        };

        let confirm_key = self.derive_confirm_key()?;
        let transcript_hash = self.transcript.hash();
        let hmac = vnet_crypto::mac::HmacSha256::new(&confirm_key)?;
        let expected_tag = hmac.sign(&transcript_hash);

        if *confirm_tag != expected_tag {
            return Err(HandshakeError::ConfirmMismatch);
        }

        Ok(())
    }

    /// Derive confirm key from handshake
    fn derive_confirm_key(&self) -> Result<[u8; 32], HandshakeError> {
        let shared = self.compute_shared_secret()?;
        let master_secret = vnet_crypto::hkdf::hkdf_extract(&[0u8; 32], shared.as_bytes());
        let confirm_key = vnet_crypto::hkdf::hkdf_expand(
            master_secret.as_bytes(),
            b"vnet-handshake-confirm",
            32,
        )?;
        let mut key = [0u8; 32];
        key.copy_from_slice(confirm_key.as_bytes());
        Ok(key)
    }

    /// Compute shared secret from ECDH
    fn compute_shared_secret(&self) -> Result<vnet_crypto::ecdh::SharedSecret, HandshakeError> {
        let local_ecdh = self.local_ecdh.as_ref()
            .ok_or(HandshakeError::KeyAgreementFailed("No local ECDH key".into()))?;
        let remote_public = self.remote_ecdh_public
            .ok_or(HandshakeError::KeyAgreementFailed("No remote ECDH public key".into()))?;

        let remote = vnet_crypto::ecdh::EcdhPublicKey::from_compressed_bytes(&remote_public)?;
        Ok(local_ecdh.agree(&remote))
    }

    /// Derive session keys after handshake
    fn derive_session_keys(&mut self) -> Result<(), HandshakeError> {
        let shared = self.compute_shared_secret()?;
        let (client_enc, server_enc, client_mac, server_mac) =
            vnet_crypto::hkdf::derive_session_keys(shared.as_bytes())?;

        let mut master_secret = [0u8; 32];
        let master_secret_material = vnet_crypto::hkdf::hkdf_extract(&[0u8; 32], shared.as_bytes());
        master_secret.copy_from_slice(
            vnet_crypto::hkdf::hkdf_expand(
                master_secret_material.as_bytes(),
                b"vnet-master-secret",
                32,
            )?.as_bytes(),
        );

        let is_client = self.state.is_client();
        let session_keys = vnet_crypto::keys::SessionKeys::new(
            master_secret,
            if is_client {
                client_enc.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            } else {
                server_enc.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            },
            if is_client {
                server_enc.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            } else {
                client_enc.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            },
            if is_client {
                client_mac.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            } else {
                server_mac.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            },
            if is_client {
                server_mac.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            } else {
                client_mac.as_bytes().try_into().map_err(|_| HandshakeError::InvalidMessage("Invalid key length".into()))?
            },
        );

        self.session_keys = Some(session_keys);
        self.state = HandshakeState::Established;
        Ok(())
    }
}

impl TryFrom<u8> for AeadAlgorithm {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Aes256Gcm),
            0x02 => Ok(Self::ChaCha20Poly1305),
            _ => Err(()),
        }
    }
}

/// Encode an ICE candidate to bytes
fn encode_ice_candidate(candidate: &IceCandidate, buf: &mut BytesMut) -> Result<(), CodecError> {
    // Foundation (string: length + data)
    let foundation = candidate.foundation.as_bytes();
    buf.put_u16(foundation.len() as u16);
    buf.put_slice(foundation);
    
    buf.put_u8(candidate.component_id);
    
    // Transport (string)
    let transport = candidate.transport.as_bytes();
    buf.put_u16(transport.len() as u16);
    buf.put_slice(transport);
    
    buf.put_u32(candidate.priority);
    
    // Address
    match candidate.address {
        IpAddr::V4(ip) => {
            buf.put_u8(0x01); // IPv4
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.put_u8(0x02); // IPv6
            buf.put_slice(&ip.octets());
        }
    }
    
    buf.put_u16(candidate.port);
    buf.put_u8(candidate.candidate_type as u8);
    
    // Related address (optional)
    if let Some(raddr) = candidate.related_address {
        buf.put_u8(0x01);
        match raddr {
            IpAddr::V4(ip) => {
                buf.put_u8(0x01);
                buf.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(0x02);
                buf.put_slice(&ip.octets());
            }
        }
    } else {
        buf.put_u8(0x00);
    }
    
    // Related port (optional)
    if let Some(rport) = candidate.related_port {
        buf.put_u8(0x01);
        buf.put_u16(rport);
    } else {
        buf.put_u8(0x00);
    }
    
    // TCP type (optional)
    if let Some(tcp_type) = &candidate.tcp_type {
        let tcp_type_bytes = tcp_type.as_bytes();
        buf.put_u8(0x01);
        buf.put_u16(tcp_type_bytes.len() as u16);
        buf.put_slice(tcp_type_bytes);
    } else {
        buf.put_u8(0x00);
    }
    
    Ok(())
}

/// Decode an ICE candidate from bytes
fn decode_ice_candidate(buf: &mut Bytes) -> Result<IceCandidate, CodecError> {
    // Foundation
    let foundation_len = buf.get_u16() as usize;
    if buf.remaining() < foundation_len {
        return Err(CodecError::BufferTooSmall {
            need: foundation_len,
            have: buf.remaining(),
        });
    }
    let mut foundation = vec![0u8; foundation_len];
    buf.copy_to_slice(&mut foundation);
    let foundation = String::from_utf8(foundation).map_err(|_| CodecError::InvalidMessage("Invalid foundation string".into()))?;
    
    let component_id = buf.get_u8();
    
    // Transport
    let transport_len = buf.get_u16() as usize;
    if buf.remaining() < transport_len {
        return Err(CodecError::BufferTooSmall {
            need: transport_len,
            have: buf.remaining(),
        });
    }
    let mut transport = vec![0u8; transport_len];
    buf.copy_to_slice(&mut transport);
    let transport = String::from_utf8(transport).map_err(|_| CodecError::InvalidMessage("Invalid transport string".into()))?;
    
    let priority = buf.get_u32();
    
    // Address
    let ip_version = buf.get_u8();
    let address = if ip_version == 0x01 {
        if buf.remaining() < 4 {
            return Err(CodecError::BufferTooSmall { need: 4, have: buf.remaining() });
        }
        let mut octets = [0u8; 4];
        buf.copy_to_slice(&mut octets);
        IpAddr::V4(Ipv4Addr::from(octets))
    } else if ip_version == 0x02 {
        if buf.remaining() < 16 {
            return Err(CodecError::BufferTooSmall { need: 16, have: buf.remaining() });
        }
        let mut octets = [0u8; 16];
        buf.copy_to_slice(&mut octets);
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        return Err(CodecError::InvalidMessage("Invalid IP version".into()));
    };
    
    let port = buf.get_u16();
    let candidate_type = CandidateType::try_from(buf.get_u8()).map_err(|_| CodecError::InvalidMessage("Invalid candidate type".into()))?;
    
    // Related address
    let has_related = buf.get_u8();
    let related_address = if has_related != 0 {
        let ip_version = buf.get_u8();
        if ip_version == 0x01 {
            if buf.remaining() < 4 {
                return Err(CodecError::BufferTooSmall { need: 4, have: buf.remaining() });
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        } else if ip_version == 0x02 {
            if buf.remaining() < 16 {
                return Err(CodecError::BufferTooSmall { need: 16, have: buf.remaining() });
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            return Err(CodecError::InvalidMessage("Invalid related IP version".into()));
        }
    } else {
        None
    };
    
    // Related port
    let has_related_port = buf.get_u8();
    let related_port = if has_related_port != 0 {
        Some(buf.get_u16())
    } else {
        None
    };
    
    // TCP type
    let has_tcp_type = buf.get_u8();
    let tcp_type = if has_tcp_type != 0 {
        let tcp_type_len = buf.get_u16() as usize;
        if buf.remaining() < tcp_type_len {
            return Err(CodecError::BufferTooSmall {
                need: tcp_type_len,
                have: buf.remaining(),
            });
        }
        let mut tcp_type_bytes = vec![0u8; tcp_type_len];
        buf.copy_to_slice(&mut tcp_type_bytes);
        Some(String::from_utf8(tcp_type_bytes).map_err(|_| CodecError::InvalidMessage("Invalid TCP type string".into()))?)
    } else {
        None
    };
    
    Ok(IceCandidate {
        foundation,
        component_id,
        transport,
        priority,
        address,
        port,
        candidate_type,
        related_address,
        related_port,
        tcp_type,
    })
}