//! Key structures for channel encryption, session management, and user parameters

use crate::aead::{AeadAlgorithm, new_aead_key};
use crate::error::{CryptoError, Result};
use crate::rand::secure_random;
use serde::{Deserialize, Serialize};

/// Channel encryption keys (one direction)
///
/// Each channel has separate encryption and decryption keys with independent nonces
pub struct ChannelKeys {
    pub algorithm: AeadAlgorithm,
    pub enc_key: Box<dyn crate::aead::AeadKey>,
    pub dec_key: Box<dyn crate::aead::AeadKey>,
    pub enc_nonce: [u8; 12],
    pub dec_nonce: [u8; 12],
}

impl ChannelKeys {
    /// Create new channel keys with random nonces
    pub fn new(algorithm: AeadAlgorithm, enc_key: &[u8], dec_key: &[u8]) -> Result<Self> {
        let enc_key = new_aead_key(algorithm, enc_key)?;
        let dec_key = new_aead_key(algorithm, dec_key)?;

        let mut enc_nonce = [0u8; 12];
        let mut dec_nonce = [0u8; 12];
        secure_random(&mut enc_nonce)?;
        secure_random(&mut dec_nonce)?;

        Ok(Self {
            algorithm,
            enc_key,
            dec_key,
            enc_nonce,
            dec_nonce,
        })
    }

    /// Create from pre-shared keys (for testing)
    pub fn from_keys(
        algorithm: AeadAlgorithm,
        enc_key: Box<dyn crate::aead::AeadKey>,
        dec_key: Box<dyn crate::aead::AeadKey>,
    ) -> Self {
        let mut enc_nonce = [0u8; 12];
        let mut dec_nonce = [0u8; 12];
        secure_random(&mut enc_nonce).unwrap();
        secure_random(&mut dec_nonce).unwrap();

        Self {
            algorithm,
            enc_key,
            dec_key,
            enc_nonce,
            dec_nonce,
        }
    }

    /// Encrypt a buffer (in-place, appends tag)
    pub fn encrypt(&mut self, aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        self.enc_key.encrypt_in_place(&self.enc_nonce, aad, buffer)?;
        self.increment_enc_nonce();
        Ok(())
    }

    /// Decrypt a buffer (in-place, verifies tag)
    pub fn decrypt(&mut self, aad: &[u8], buffer: &mut Vec<u8>) -> Result<usize> {
        let len = self.dec_key.decrypt_in_place(&self.dec_nonce, aad, buffer)?;
        self.increment_dec_nonce();
        Ok(len)
    }

    /// Encrypt with separate output
    pub fn encrypt_separate(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = plaintext.to_vec();
        self.encrypt(aad, &mut buf)?;
        Ok(buf)
    }

    /// Decrypt with separate output
    pub fn decrypt_separate(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        let len = self.decrypt(aad, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Increment encryption nonce (little-endian counter)
    fn increment_enc_nonce(&mut self) {
        for byte in self.enc_nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// Increment decryption nonce (little-endian counter)
    fn increment_dec_nonce(&mut self) {
        for byte in self.dec_nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// Get the current encryption nonce
    pub fn enc_nonce(&self) -> &[u8; 12] {
        &self.enc_nonce
    }

    /// Get the current decryption nonce
    pub fn dec_nonce(&self) -> &[u8; 12] {
        &self.dec_nonce
    }

    /// Set encryption nonce (for synchronization)
    pub fn set_enc_nonce(&mut self, nonce: [u8; 12]) {
        self.enc_nonce = nonce;
    }

    /// Set decryption nonce (for synchronization)
    pub fn set_dec_nonce(&mut self, nonce: [u8; 12]) {
        self.dec_nonce = nonce;
    }
}

/// Session keys derived from ECDH handshake
#[derive(Clone)]
pub struct SessionKeys {
    pub master_secret: [u8; 32],
    pub client_enc_key: [u8; 32],
    pub server_enc_key: [u8; 32],
    pub client_mac_key: [u8; 32],
    pub server_mac_key: [u8; 32],
}

impl SessionKeys {
    /// Create from derived key material
    pub fn new(
        master_secret: [u8; 32],
        client_enc_key: [u8; 32],
        server_enc_key: [u8; 32],
        client_mac_key: [u8; 32],
        server_mac_key: [u8; 32],
    ) -> Self {
        Self {
            master_secret,
            client_enc_key,
            server_enc_key,
            client_mac_key,
            server_mac_key,
        }
    }

    /// Create channel keys for client->server direction
    pub fn client_channel_keys(&self, algorithm: AeadAlgorithm) -> Result<ChannelKeys> {
        ChannelKeys::new(algorithm, &self.client_enc_key, &self.server_enc_key)
    }

    /// Create channel keys for server->client direction
    pub fn server_channel_keys(&self, algorithm: AeadAlgorithm) -> Result<ChannelKeys> {
        ChannelKeys::new(algorithm, &self.server_enc_key, &self.client_enc_key)
    }

    /// Get client MAC key
    pub fn client_mac_key(&self) -> &[u8; 32] {
        &self.client_mac_key
    }

    /// Get server MAC key
    pub fn server_mac_key(&self) -> &[u8; 32] {
        &self.server_mac_key
    }
}

/// User authentication parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserParams {
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: [u8; 32], // PBKDF2-HMAC-SHA256(password, salt)
    pub salt: [u8; 16],
    pub iterations: u32,
}

impl UserParams {
    /// Generate new user parameters from password
    pub fn generate(username: &str, password: &[u8]) -> Result<Self> {
        use crate::hkdf::derive_user_params_key;

        let mut salt = [0u8; 16];
        secure_random(&mut salt)?;

        let password_hash = derive_user_params_key(password, &salt)?
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidParameter("Invalid hash length".into()))?;

        Ok(Self {
            username: username.to_string(),
            password_hash,
            salt,
            iterations: 100_000,
        })
    }

    /// Verify a password against stored parameters
    pub fn verify_password(&self, password: &[u8]) -> Result<bool> {
        use crate::hkdf::derive_user_params_key;

        let key_material = derive_user_params_key(password, &self.salt)?;
        let computed = key_material.as_bytes();
        let computed_arr: [u8; 32] = computed.try_into()
            .map_err(|_| CryptoError::InvalidParameter("Invalid hash length".into()))?;

        Ok(self.password_hash == computed_arr)
    }

    /// Change password
    pub fn change_password(&mut self, new_password: &[u8]) -> Result<()> {
        use crate::hkdf::derive_user_params_key;

        let mut salt = [0u8; 16];
        secure_random(&mut salt)?;

        let key_material = derive_user_params_key(new_password, &salt)?;
        let new_hash = key_material.as_bytes();
        self.password_hash = new_hash.try_into()
            .map_err(|_| CryptoError::InvalidParameter("Invalid hash length".into()))?;
        self.salt = salt;

        Ok(())
    }
}

/// Network/peer identity keys (long-term)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKeys {
    /// Long-term signing key (ECDSA P-256) - stored as PKCS#8 DER
    pub signing_key_der: Vec<u8>,
    /// Certificate chain (PEM encoded)
    pub certificate_chain: Vec<String>,
}

impl IdentityKeys {
    /// Generate new identity keys
    pub fn generate() -> Result<Self> {
        let signing_key = crate::signature::SignatureKeyPair::generate()?;
        Ok(Self {
            signing_key_der: signing_key.to_pkcs8_der()?,
            certificate_chain: Vec::new(),
        })
    }

    /// Get the signing key pair
    pub fn signing_key(&self) -> Result<crate::signature::SignatureKeyPair> {
        crate::signature::SignatureKeyPair::from_pkcs8_der(&self.signing_key_der)
    }

    /// Get the public verifying key
    pub fn verifying_key(&self) -> Result<crate::signature::VerifyingKey> {
        self.signing_key().map(|k| k.verifying_key())
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<crate::signature::Signature> {
        self.signing_key()?.sign(data)
    }

    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &crate::signature::Signature) -> Result<bool> {
        self.verifying_key()?.verify(data, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_keys_creation() {
        let enc_key = [0xAA; 32];
        let dec_key = [0xBB; 32];

        let mut keys = ChannelKeys::new(AeadAlgorithm::Aes256Gcm, &enc_key, &dec_key).unwrap();

        assert_eq!(keys.algorithm, AeadAlgorithm::Aes256Gcm);
        assert_eq!(keys.enc_nonce.len(), 12);
        assert_eq!(keys.dec_nonce.len(), 12);
    }

    #[test]
    fn test_channel_keys_bidirectional() {
        // Simulate two parties communicating with synchronized nonces
        let key = [0xAA; 32];

        // Party A's keys (encrypts to B, decrypts from B)
        let mut a_keys = ChannelKeys::new(AeadAlgorithm::ChaCha20Poly1305, &key, &key).unwrap();
        
        // Party B's keys (encrypts to A, decrypts from A)
        // Sync B's dec_nonce with A's enc_nonce for this test
        let mut b_keys = ChannelKeys::new(AeadAlgorithm::ChaCha20Poly1305, &key, &key).unwrap();
        b_keys.set_dec_nonce(*a_keys.enc_nonce());

        let aad = b"channel-aad";
        let plaintext = b"Test message from A to B";

        // A encrypts message to B
        let mut buf = plaintext.to_vec();
        a_keys.encrypt(aad, &mut buf).unwrap();
        assert_ne!(buf, plaintext);
        assert_eq!(buf.len(), plaintext.len() + 16);

        // B decrypts message from A (using synced nonce)
        let len = b_keys.decrypt(aad, &mut buf).unwrap();
        buf.truncate(len);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn test_channel_keys_separate_bidirectional() {
        let key = [0xAA; 32];

        // Party A's keys
        let mut a_keys = ChannelKeys::new(AeadAlgorithm::Aes256Gcm, &key, &key).unwrap();
        
        // Party B's keys - sync dec_nonce with A's enc_nonce
        let mut b_keys = ChannelKeys::new(AeadAlgorithm::Aes256Gcm, &key, &key).unwrap();
        b_keys.set_dec_nonce(*a_keys.enc_nonce());

        let aad = b"channel-aad";
        let plaintext = b"Test message from A to B";

        // A encrypts
        let ciphertext = a_keys.encrypt_separate(aad, plaintext).unwrap();
        
        // B decrypts
        let decrypted = b_keys.decrypt_separate(aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_session_keys() {
        let master = [0x11; 32];
        let c_enc = [0x22; 32];
        let s_enc = [0x33; 32];
        let c_mac = [0x44; 32];
        let s_mac = [0x55; 32];

        let session = SessionKeys::new(master, c_enc, s_enc, c_mac, s_mac);

        let client_chan = session.client_channel_keys(AeadAlgorithm::Aes256Gcm).unwrap();
        let server_chan = session.server_channel_keys(AeadAlgorithm::Aes256Gcm).unwrap();

        // Client's enc key should be server's dec key
        assert_eq!(client_chan.enc_key.key_bytes(), server_chan.dec_key.key_bytes());
        assert_eq!(client_chan.dec_key.key_bytes(), server_chan.enc_key.key_bytes());
    }

    #[test]
    fn test_user_params_generate_verify() {
        let params = UserParams::generate("testuser", b"password123").unwrap();

        assert_eq!(params.username, "testuser");
        assert_eq!(params.salt.len(), 16);
        assert_eq!(params.iterations, 100_000);

        // Verify correct password
        assert!(params.verify_password(b"password123").unwrap());

        // Verify wrong password fails
        assert!(!params.verify_password(b"wrongpassword").unwrap());
    }

    #[test]
    fn test_user_params_change_password() {
        let mut params = UserParams::generate("testuser", b"oldpassword").unwrap();
        let old_hash = params.password_hash;

        params.change_password(b"newpassword").unwrap();

        assert_ne!(params.password_hash, old_hash);
        assert!(!params.verify_password(b"oldpassword").unwrap());
        assert!(params.verify_password(b"newpassword").unwrap());
    }

    #[test]
    fn test_identity_keys() {
        let identity = IdentityKeys::generate().unwrap();

        let msg = b"test message";
        let sig = identity.sign(msg).unwrap();
        assert!(identity.verify(msg, &sig).unwrap());

        // Tampered message should fail
        let tampered = b"tampered message";
        assert!(!identity.verify(tampered, &sig).unwrap());
    }
}