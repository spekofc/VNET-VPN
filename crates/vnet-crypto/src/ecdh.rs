//! ECDH (Elliptic Curve Diffie-Hellman) key agreement
//!
//! Uses P-256 (secp256r1) curve for key exchange. The shared secret is derived
//! using HKDF-SHA256 as specified in the protocol.

use crate::error::{CryptoError, Result};
use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    elliptic_curve::FieldBytes,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    EncodedPoint, PublicKey, SecretKey,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ECDH shared secret (32 bytes)
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    /// Get the shared secret as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the shared secret as mutable bytes
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// ECDH public key for P-256
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdhPublicKey(PublicKey);

impl EcdhPublicKey {
    /// Create from raw compressed public key bytes (33 bytes: 0x02/0x03 + 32 bytes x)
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(CryptoError::InvalidKeySize { expected: 33, actual: bytes.len() });
        }
        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        let public_key = PublicKey::from_encoded_point(&encoded)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey("Invalid point".into()))?;
        Ok(Self(public_key))
    }

    /// Create from raw uncompressed public key bytes (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(CryptoError::InvalidKeySize { expected: 65, actual: bytes.len() });
        }
        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        let public_key = PublicKey::from_encoded_point(&encoded)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey("Invalid point".into()))?;
        Ok(Self(public_key))
    }

    /// Create from SEC1 DER-encoded public key
    pub fn from_sec1_der(der: &[u8]) -> Result<Self> {
        let encoded = EncodedPoint::from_bytes(der)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        let public_key = PublicKey::from_encoded_point(&encoded)
            .into_option()
            .ok_or(CryptoError::InvalidPublicKey("Invalid point".into()))?;
        Ok(Self(public_key))
    }

    /// Create from SEC1 PEM-encoded public key
    pub fn from_sec1_pem(pem_str: &str) -> Result<Self> {
        let pem_obj = pem::parse(pem_str)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Self::from_sec1_der(&pem_obj.contents)
    }

    /// Get compressed public key bytes (33 bytes)
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        self.0.to_encoded_point(true).as_bytes().try_into().expect("33 bytes")
    }

    /// Get uncompressed public key bytes (65 bytes)
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        self.0.to_encoded_point(false).as_bytes().try_into().expect("65 bytes")
    }

    /// Export as SEC1 DER
    pub fn to_sec1_der(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Export as SEC1 PEM
    pub fn to_sec1_pem(&self) -> Result<String> {
        let der = self.to_sec1_der();
        let pem_obj = pem::Pem {
            tag: String::from("PUBLIC KEY"),
            contents: der,
        };
        Ok(pem::encode(&pem_obj))
    }

    /// Get the underlying PublicKey
    pub fn as_public_key(&self) -> &PublicKey {
        &self.0
    }
}

/// ECDH private/public key pair for P-256
pub struct EcdhKeyPair {
    secret_bytes: [u8; 32],
    public_key: EcdhPublicKey,
}

impl Zeroize for EcdhKeyPair {
    fn zeroize(&mut self) {
        self.secret_bytes.zeroize();
    }
}

impl Drop for EcdhKeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl EcdhKeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Result<Self> {
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let secret_bytes = secret_key.to_bytes().into();
        let public_key = EcdhPublicKey(secret_key.public_key());
        Ok(Self { secret_bytes, public_key })
    }

    /// Create from raw private key bytes (32 bytes, big-endian)
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize { expected: 32, actual: bytes.len() });
        }
        let secret_key = SecretKey::from_bytes(bytes.into())
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        let secret_bytes = secret_key.to_bytes().into();
        let public_key = EcdhPublicKey(secret_key.public_key());
        Ok(Self { secret_bytes, public_key })
    }

    /// Create from PKCS#8 DER-encoded private key
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::from_pkcs8_der(der)
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        let secret_bytes = secret_key.to_bytes().into();
        let public_key = EcdhPublicKey(secret_key.public_key());
        Ok(Self { secret_bytes, public_key })
    }

    /// Create from PKCS#8 PEM-encoded private key
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let secret_key = SecretKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        let secret_bytes = secret_key.to_bytes().into();
        let public_key = EcdhPublicKey(secret_key.public_key());
        Ok(Self { secret_bytes, public_key })
    }

    /// Get the public key
    pub fn public_key(&self) -> &EcdhPublicKey {
        &self.public_key
    }

    /// Get the raw private key bytes (32 bytes)
    pub fn private_bytes(&self) -> [u8; 32] {
        self.secret_bytes
    }

    /// Export private key as PKCS#8 DER
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let secret_key = SecretKey::from_bytes(&self.secret_bytes.into())
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        secret_key
            .to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| CryptoError::SerializationFailed(e.to_string()))
    }

    /// Export private key as PKCS#8 PEM
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        let secret_key = SecretKey::from_bytes(&self.secret_bytes.into())
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        secret_key
            .to_pkcs8_pem(Default::default())
            .map(|pem| pem.to_string())
            .map_err(|e| CryptoError::SerializationFailed(e.to_string()))
    }

    /// Perform ECDH key agreement with a peer's public key
    pub fn agree(&self, peer_public: &EcdhPublicKey) -> SharedSecret {
        let secret_key = SecretKey::from_bytes(&self.secret_bytes.into())
            .expect("valid secret key");
        let shared = diffie_hellman(
            secret_key.to_nonzero_scalar(),
            peer_public.0.as_affine(),
        );
        SharedSecret(shared.raw_secret_bytes().clone().into())
    }
}