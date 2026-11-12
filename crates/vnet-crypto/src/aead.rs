//! AEAD (Authenticated Encryption with Associated Data) implementations
//!
//! Provides AES-256-GCM and ChaCha20-Poly1305 with a unified interface.

use crate::error::{CryptoError, Result};
use aes_gcm::{Aes256Gcm, AeadInPlace, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaChaKeyInit, Nonce as ChaChaNonce};
use generic_array::GenericArray;

/// AEAD algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum AeadAlgorithm {
    /// AES-256-GCM (128-bit tag, 96-bit nonce)
    Aes256Gcm = 0x01,
    /// ChaCha20-Poly1305 (128-bit tag, 96-bit nonce) - preferred for performance
    ChaCha20Poly1305 = 0x02,
}

impl AeadAlgorithm {
    /// Get the key size for this algorithm
    pub const fn key_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size for this algorithm
    pub const fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::ChaCha20Poly1305 => 12,
        }
    }

    /// Get the tag size for this algorithm
    pub const fn tag_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 16,
            Self::ChaCha20Poly1305 => 16,
        }
    }
}

/// Trait for AEAD keys
pub trait AeadKey: Send + Sync {
    /// Get the algorithm
    fn algorithm(&self) -> AeadAlgorithm;

    /// Get the key bytes
    fn key_bytes(&self) -> &[u8];

    /// Encrypt data in-place with associated data
    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<()>;

    /// Decrypt data in-place with associated data
    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<usize>;

    /// Encrypt with separate output buffer
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt with separate output buffer
    fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// AES-256-GCM key
pub struct Aes256GcmKey {
    key: GenericArray<u8, generic_array::typenum::U32>,
    cipher: Aes256Gcm,
}

impl Aes256GcmKey {
    /// Create a new AES-256-GCM key from raw bytes
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize { expected: 32, actual: key.len() });
        }
        let key_arr = GenericArray::clone_from_slice(key);
        let cipher = Aes256Gcm::new(&key_arr);
        Ok(Self { key: key_arr, cipher })
    }

    /// Generate a random key
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        crate::rand::secure_random(&mut key)?;
        Self::new(&key)
    }
}

impl AeadKey for Aes256GcmKey {
    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::Aes256Gcm
    }

    fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }
        let nonce_arr = Nonce::from_slice(nonce);
        self.cipher
            .encrypt_in_place(nonce_arr, aad, buffer)
            .map_err(|_| CryptoError::AeadEncryptFailed("AES-GCM encryption failed".into()))?;
        Ok(())
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<usize> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }
        let nonce_arr = Nonce::from_slice(nonce);
        self.cipher
            .decrypt_in_place(nonce_arr, aad, buffer)
            .map_err(|_| CryptoError::AeadDecryptFailed)?;
        Ok(buffer.len())
    }

    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = plaintext.to_vec();
        self.encrypt_in_place(nonce, aad, &mut buffer)?;
        Ok(buffer)
    }

    fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = ciphertext.to_vec();
        let len = self.decrypt_in_place(nonce, aad, &mut buffer)?;
        buffer.truncate(len);
        Ok(buffer)
    }
}

/// ChaCha20-Poly1305 key
pub struct ChaCha20Poly1305Key {
    key: GenericArray<u8, generic_array::typenum::U32>,
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Key {
    /// Create a new ChaCha20-Poly1305 key from raw bytes
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeySize { expected: 32, actual: key.len() });
        }
        let key_arr = GenericArray::clone_from_slice(key);
        let cipher = ChaCha20Poly1305::new(&key_arr);
        Ok(Self { key: key_arr, cipher })
    }

    /// Generate a random key
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        crate::rand::secure_random(&mut key)?;
        Self::new(&key)
    }
}

impl AeadKey for ChaCha20Poly1305Key {
    fn algorithm(&self) -> AeadAlgorithm {
        AeadAlgorithm::ChaCha20Poly1305
    }

    fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    fn encrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }
        let nonce_arr = ChaChaNonce::from_slice(nonce);
        self.cipher
            .encrypt_in_place(nonce_arr, aad, buffer)
            .map_err(|_| CryptoError::AeadEncryptFailed("ChaCha20-Poly1305 encryption failed".into()))?;
        Ok(())
    }

    fn decrypt_in_place(&self, nonce: &[u8], aad: &[u8], buffer: &mut Vec<u8>) -> Result<usize> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceSize { expected: 12, actual: nonce.len() });
        }
        let nonce_arr = ChaChaNonce::from_slice(nonce);
        let len = buffer.len();
        self.cipher
            .decrypt_in_place(nonce_arr, aad, buffer)
            .map_err(|_| CryptoError::AeadDecryptFailed)?;
        Ok(len)
    }

    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = plaintext.to_vec();
        self.encrypt_in_place(nonce, aad, &mut buffer)?;
        Ok(buffer)
    }

    fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = ciphertext.to_vec();
        let len = self.decrypt_in_place(nonce, aad, &mut buffer)?;
        buffer.truncate(len);
        Ok(buffer)
    }
}

/// Construct an AEAD key from algorithm and raw bytes
pub fn new_aead_key(algorithm: AeadAlgorithm, key: &[u8]) -> Result<Box<dyn AeadKey>> {
    match algorithm {
        AeadAlgorithm::Aes256Gcm => Ok(Box::new(Aes256GcmKey::new(key)?)),
        AeadAlgorithm::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Key::new(key)?)),
    }
}

/// Generate a random AEAD key for the given algorithm
pub fn generate_aead_key(algorithm: AeadAlgorithm) -> Result<Box<dyn AeadKey>> {
    match algorithm {
        AeadAlgorithm::Aes256Gcm => Ok(Box::new(Aes256GcmKey::generate()?)),
        AeadAlgorithm::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Key::generate()?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::secure_random;

    #[test]
    fn test_aes256gcm_encrypt_decrypt() {
        let key = Aes256GcmKey::generate().unwrap();
        let mut nonce = [0u8; 12];
        secure_random(&mut nonce).unwrap();
        let aad = b"associated-data";
        let plaintext = b"Hello, VNET!";

        let ciphertext = key.encrypt(&nonce, aad, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // + tag

        let decrypted = key.decrypt(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt() {
        let key = ChaCha20Poly1305Key::generate().unwrap();
        let mut nonce = [0u8; 12];
        secure_random(&mut nonce).unwrap();
        let aad = b"associated-data";
        let plaintext = b"Hello, VNET!";

        let ciphertext = key.encrypt(&nonce, aad, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // + tag

        let decrypted = key.decrypt(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_tamper_detection() {
        let key = Aes256GcmKey::generate().unwrap();
        let mut nonce = [0u8; 12];
        secure_random(&mut nonce).unwrap();
        let aad = b"associated-data";
        let plaintext = b"Hello, VNET!";

        let mut ciphertext = key.encrypt(&nonce, aad, plaintext).unwrap();
        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        let result = key.decrypt(&nonce, aad, &ciphertext);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::AeadDecryptFailed));
    }

    #[test]
    fn test_aead_wrong_nonce() {
        let key = Aes256GcmKey::generate().unwrap();
        let mut nonce1 = [0u8; 12];
        let mut nonce2 = [0u8; 12];
        secure_random(&mut nonce1).unwrap();
        secure_random(&mut nonce2).unwrap();
        let aad = b"associated-data";
        let plaintext = b"Hello, VNET!";

        let ciphertext = key.encrypt(&nonce1, aad, plaintext).unwrap();
        let result = key.decrypt(&nonce2, aad, &ciphertext);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::AeadDecryptFailed));
    }

    #[test]
    fn test_aead_wrong_aad() {
        let key = Aes256GcmKey::generate().unwrap();
        let mut nonce = [0u8; 12];
        secure_random(&mut nonce).unwrap();
        let plaintext = b"Hello, VNET!";

        let ciphertext = key.encrypt(&nonce, b"aad1", plaintext).unwrap();
        let result = key.decrypt(&nonce, b"aad2", &ciphertext);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::AeadDecryptFailed));
    }

    #[test]
    fn test_generate_aead_key() {
        let aes_key = generate_aead_key(AeadAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(aes_key.algorithm(), AeadAlgorithm::Aes256Gcm);
        assert_eq!(aes_key.key_bytes().len(), 32);

        let chacha_key = generate_aead_key(AeadAlgorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(chacha_key.algorithm(), AeadAlgorithm::ChaCha20Poly1305);
        assert_eq!(chacha_key.key_bytes().len(), 32);
    }

    #[test]
    fn test_new_aead_key() {
        let mut key_bytes = [0u8; 32];
        secure_random(&mut key_bytes).unwrap();

        let aes_key = new_aead_key(AeadAlgorithm::Aes256Gcm, &key_bytes).unwrap();
        assert_eq!(aes_key.algorithm(), AeadAlgorithm::Aes256Gcm);

        let chacha_key = new_aead_key(AeadAlgorithm::ChaCha20Poly1305, &key_bytes).unwrap();
        assert_eq!(chacha_key.algorithm(), AeadAlgorithm::ChaCha20Poly1305);
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(AeadAlgorithm::Aes256Gcm.key_size(), 32);
        assert_eq!(AeadAlgorithm::Aes256Gcm.nonce_size(), 12);
        assert_eq!(AeadAlgorithm::Aes256Gcm.tag_size(), 16);

        assert_eq!(AeadAlgorithm::ChaCha20Poly1305.key_size(), 32);
        assert_eq!(AeadAlgorithm::ChaCha20Poly1305.nonce_size(), 12);
        assert_eq!(AeadAlgorithm::ChaCha20Poly1305.tag_size(), 16);
    }
}