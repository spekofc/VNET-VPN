//! HMAC-SHA256 implementation for message authentication

use crate::error::{CryptoError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// HMAC-SHA256 key
#[derive(Debug)]
pub struct HmacSha256 {
    key: [u8; 32],
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 key from raw bytes
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize { expected: 32, actual: key.len() });
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);
        Ok(Self { key: key_arr })
    }

    /// Generate a random HMAC key
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        crate::rand::secure_random(&mut key)?;
        Ok(Self { key })
    }

    /// Compute HMAC-SHA256 of data
    pub fn sign(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key creation failed");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verify HMAC-SHA256 of data (constant-time)
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> Result<bool> {
        if tag.len() != 32 {
            return Err(CryptoError::InvalidTagSize { expected: 32, actual: tag.len() });
        }
        let expected = self.sign(data);
        Ok(expected.ct_eq(tag).into())
    }

    /// Create a streaming MAC for incremental computation
    pub fn streaming(&self) -> StreamingMac {
        StreamingMac {
            mac: Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key creation failed"),
        }
    }

    /// Get the key bytes
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Streaming HMAC for incremental computation
pub struct StreamingMac {
    mac: Hmac<Sha256>,
}

impl StreamingMac {
    /// Update with more data
    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// Finalize and return the tag
    pub fn finalize(self) -> [u8; 32] {
        self.mac.finalize().into_bytes().into()
    }

    /// Finalize and verify against expected tag
    pub fn finalize_verify(self, expected: &[u8]) -> Result<()> {
        let tag = self.finalize();
        if tag.ct_eq(expected).into() {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature("HMAC verification failed".into()))
        }
    }
}

/// Compute HMAC-SHA256 with a one-time key (for key derivation)
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeySize { expected: 32, actual: key.len() });
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key creation failed");
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sign_verify() {
        let key = HmacSha256::generate().unwrap();
        let data = b"Hello, VNET!";

        let tag = key.sign(data);
        assert_eq!(tag.len(), 32);

        assert!(key.verify(data, &tag).unwrap());

        // Wrong data should fail
        assert!(!key.verify(b"Wrong data", &tag).unwrap());
    }

    #[test]
    fn test_hmac_tamper_detection() {
        let key = HmacSha256::generate().unwrap();
        let data = b"Hello, VNET!";

        let mut tag = key.sign(data);
        tag[0] ^= 0xFF; // Tamper

        assert!(!key.verify(data, &tag).unwrap());
    }

    #[test]
    fn test_hmac_streaming() {
        let key = HmacSha256::generate().unwrap();
        let data1 = b"Hello, ";
        let data2 = b"VNET!";

        let mut streaming = key.streaming();
        streaming.update(data1);
        streaming.update(data2);
        let tag = streaming.finalize();

        let combined: Vec<u8> = data1.iter().chain(data2.iter()).copied().collect();
        let expected = key.sign(&combined);
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_hmac_streaming_verify() {
        let key = HmacSha256::generate().unwrap();
        let data = b"Hello, VNET!";

        let mut streaming = key.streaming();
        streaming.update(data);
        streaming.finalize_verify(&key.sign(data)).unwrap();
    }

    #[test]
    fn test_hmac_wrong_key_size() {
        let result = HmacSha256::new(b"short");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidKeySize { .. }));
    }

    #[test]
    fn test_hmac_wrong_tag_size() {
        let key = HmacSha256::generate().unwrap();
        let result = key.verify(b"data", b"short");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidTagSize { .. }));
    }

    #[test]
    fn test_hmac_deterministic() {
        let key = HmacSha256::new(&[0x42; 32]).unwrap();
        let data = b"test data";

        let tag1 = key.sign(data);
        let tag2 = key.sign(data);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_different_keys() {
        let key1 = HmacSha256::new(&[0x42; 32]).unwrap();
        let key2 = HmacSha256::new(&[0x43; 32]).unwrap();
        let data = b"test data";

        let tag1 = key1.sign(data);
        let tag2 = key2.sign(data);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_hmac_one_shot() {
        let key = [0xAA; 32];
        let data = b"test data";
        let tag = hmac_sha256(&key, data).unwrap();

        let mac = HmacSha256::new(&key).unwrap();
        let expected = mac.sign(data);
        assert_eq!(tag, expected);
    }
}