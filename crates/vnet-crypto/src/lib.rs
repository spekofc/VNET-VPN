//! VNET Crypto Primitives
//!
//! This crate implements the cryptographic operations used by VNET,
//! built on modern RustCrypto.
//!
//! Algorithms:
//! - AEAD: AES-256-GCM, ChaCha20-Poly1305 (preferred)
//! - KEM: ECDH over P-256 (secp256r1) + HKDF-SHA256
//! - Signatures: ECDSA P-256 (for certificates)
//! - Hash: SHA-256, SHA-384
//! - MAC: HMAC-SHA256

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod aead;
pub mod ecdh;
pub mod error;
pub mod hkdf;
pub mod keys;
pub mod mac;
pub mod rand;
pub mod signature;

pub use aead::{AeadAlgorithm, AeadKey, ChaCha20Poly1305Key, Aes256GcmKey};
pub use ecdh::{EcdhKeyPair, EcdhPublicKey, SharedSecret};
pub use error::{CryptoError, Result};
pub use hkdf::{derive_keys, hkdf_extract, hkdf_expand, KeyMaterial};
pub use keys::{ChannelKeys, SessionKeys, UserParams};
pub use mac::HmacSha256;
pub use rand::secure_random;
pub use signature::{SignatureKeyPair, VerifyingKey};

/// Current protocol version
pub const PROTOCOL_VERSION: u8 = 2;

/// Magic bytes for frame identification: "RDVP" (0x52445650)
pub const MAGIC_BYTES: u32 = 0x52445650;

/// Maximum frame payload size (64KB)
pub const MAX_PAYLOAD_SIZE: usize = 65536;

/// AES-GCM nonce size (12 bytes / 96 bits)
pub const GCM_NONCE_SIZE: usize = 12;

/// AES-GCM tag size (16 bytes / 128 bits)
pub const GCM_TAG_SIZE: usize = 16;

/// ChaCha20-Poly1305 nonce size (12 bytes / 96 bits)
pub const CHACHA_NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 tag size (16 bytes / 128 bits)
pub const CHACHA_TAG_SIZE: usize = 16;

/// ECDH P-256 public key size (compressed: 33 bytes, uncompressed: 65 bytes)
pub const ECDH_PUBLIC_KEY_COMPRESSED: usize = 33;
pub const ECDH_PUBLIC_KEY_UNCOMPRESSED: usize = 65;

/// ECDH P-256 private key size (32 bytes)
pub const ECDH_PRIVATE_KEY_SIZE: usize = 32;

/// Shared secret size (32 bytes for P-256)
pub const SHARED_SECRET_SIZE: usize = 32;

/// HKDF output sizes
pub const MASTER_SECRET_SIZE: usize = 32;
pub const CHANNEL_KEY_SIZE: usize = 32;
pub const MAC_KEY_SIZE: usize = 32;

/// Handshake labels for key derivation
pub const HANDSHAKE_LABEL_CLIENT: &[u8] = b"vnet-handshake-client";
pub const HANDSHAKE_LABEL_SERVER: &[u8] = b"vnet-handshake-server";
pub const KEY_DERIVATION_LABEL_ENC: &[u8] = b"vnet-enc-keys";
pub const KEY_DERIVATION_LABEL_MAC: &[u8] = b"vnet-mac-keys";
pub const KEY_DERIVATION_LABEL_MASTER: &[u8] = b"vnet-master-secret";

/// Re-export commonly used types
pub mod prelude {
    pub use crate::aead::{AeadAlgorithm, AeadKey, ChaCha20Poly1305Key, Aes256GcmKey};
    pub use crate::ecdh::{EcdhKeyPair, EcdhPublicKey, SharedSecret};
    pub use crate::error::{CryptoError, Result};
    pub use crate::hkdf::{derive_keys, hkdf_extract, hkdf_expand, KeyMaterial};
    pub use crate::keys::{ChannelKeys, SessionKeys, UserParams};
    pub use crate::mac::HmacSha256;
    pub use crate::rand::secure_random;
    pub use crate::signature::{SignatureKeyPair, VerifyingKey};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(PROTOCOL_VERSION, 2);
        assert_eq!(MAGIC_BYTES, 0x52445650);
        assert_eq!(GCM_NONCE_SIZE, 12);
        assert_eq!(GCM_TAG_SIZE, 16);
        assert_eq!(CHACHA_NONCE_SIZE, 12);
        assert_eq!(CHACHA_TAG_SIZE, 16);
    }
}