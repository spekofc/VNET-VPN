//! Error types for crypto operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize { expected: usize, actual: usize },

    #[error("Invalid tag size: expected {expected}, got {actual}")]
    InvalidTagSize { expected: usize, actual: usize },

    #[error("Invalid public key format: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key format: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("AEAD decryption failed: authentication tag mismatch")]
    AeadDecryptFailed,

    #[error("AEAD encryption failed: {0}")]
    AeadEncryptFailed(String),

    #[error("ECDH key agreement failed: {0}")]
    EcdhFailed(String),

    #[error("HKDF derivation failed: {0}")]
    HkdfFailed(String),

    #[error("Random generation failed: {0}")]
    RandomFailed(String),

    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Key not initialized")]
    KeyNotInitialized,

    #[error("Replay detected: sequence number {seq} already used")]
    ReplayDetected { seq: u64 },

    #[error("Buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;