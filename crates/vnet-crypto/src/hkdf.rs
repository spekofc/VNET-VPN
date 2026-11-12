//! HKDF (HMAC-based Key Derivation Function) implementation
//!
//! Provides HKDF-Extract and HKDF-Expand as per RFC 5869, using HMAC-SHA256.

use crate::error::{CryptoError, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF output key material
pub struct KeyMaterial {
    material: Vec<u8>,
}

impl Zeroize for KeyMaterial {
    fn zeroize(&mut self) {
        self.material.zeroize();
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl KeyMaterial {
    /// Create new key material from bytes
    pub fn new(material: Vec<u8>) -> Self {
        Self { material }
    }

    /// Get the key material as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.material
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.material.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.material.is_empty()
    }

    /// Split into two equal parts
    pub fn split_half(&self) -> Result<(KeyMaterial, KeyMaterial)> {
        if self.material.len() % 2 != 0 {
            return Err(CryptoError::InvalidParameter("Key material length must be even".into()));
        }
        let half = self.material.len() / 2;
        Ok((
            KeyMaterial::new(self.material[..half].to_vec()),
            KeyMaterial::new(self.material[half..].to_vec()),
        ))
    }

    /// Take first `n` bytes
    pub fn take_first(&self, n: usize) -> Result<KeyMaterial> {
        if n > self.material.len() {
            return Err(CryptoError::BufferTooSmall { need: n, have: self.material.len() });
        }
        Ok(KeyMaterial::new(self.material[..n].to_vec()))
    }

    /// Take last `n` bytes
    pub fn take_last(&self, n: usize) -> Result<KeyMaterial> {
        if n > self.material.len() {
            return Err(CryptoError::BufferTooSmall { need: n, have: self.material.len() });
        }
        Ok(KeyMaterial::new(self.material[self.material.len() - n..].to_vec()))
    }
}

impl AsRef<[u8]> for KeyMaterial {
    fn as_ref(&self) -> &[u8] {
        &self.material
    }
}

/// HKDF-Extract: derive a pseudorandom key (PRK) from input key material and salt
///
/// PRK = HMAC-SHA256(salt, IKM)
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> KeyMaterial {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut prk = [0u8; 32];
    hkdf.expand(b"", &mut prk).expect("HKDF expand failed");
    KeyMaterial::new(prk.to_vec())
}

/// HKDF-Expand: derive output key material from PRK and info
///
/// OKM = HKDF-Expand(PRK, info, L)
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<KeyMaterial> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|e| CryptoError::HkdfFailed(format!("Invalid PRK length: {}", e)))?;
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .map_err(|e| CryptoError::HkdfFailed(e.to_string()))?;
    Ok(KeyMaterial::new(okm))
}

/// Combined HKDF: Extract then Expand
///
/// Returns KeyMaterial of specified length
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<KeyMaterial> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(prk.as_bytes(), info, length)
}

/// Derive session keys from ECDH shared secret
///
/// This implements the VNET session key derivation:
/// - master_secret = HKDF(salt=zero, IKM=shared_secret, info="vnet-master-secret", 32)
/// - enc_keys = HKDF(salt=zero, PRK=master_secret, info="vnet-enc-keys", 64) -> split into client/server
/// - mac_keys = HKDF(salt=zero, PRK=master_secret, info="vnet-mac-keys", 64) -> split into client/server
///
/// Returns (client_enc_key, server_enc_key, client_mac_key, server_mac_key)
pub fn derive_session_keys(shared_secret: &[u8]) -> Result<(KeyMaterial, KeyMaterial, KeyMaterial, KeyMaterial)> {
    // Step 1: Derive master secret from shared secret
    let master_secret = hkdf_extract(&[0u8; 32], shared_secret);
    let master_secret = hkdf_expand(
        master_secret.as_bytes(),
        super::KEY_DERIVATION_LABEL_MASTER,
        super::MASTER_SECRET_SIZE,
    )?;

    // Step 2: Derive encryption keys (64 bytes -> 32 + 32)
    let enc_keys = hkdf_expand(
        master_secret.as_bytes(),
        super::KEY_DERIVATION_LABEL_ENC,
        super::CHANNEL_KEY_SIZE * 2,
    )?;
    let (client_enc_key, server_enc_key) = enc_keys.split_half()?;

    // Step 3: Derive MAC keys (64 bytes -> 32 + 32)
    let mac_keys = hkdf_expand(
        master_secret.as_bytes(),
        super::KEY_DERIVATION_LABEL_MAC,
        super::MAC_KEY_SIZE * 2,
    )?;
    let (client_mac_key, server_mac_key) = mac_keys.split_half()?;

    Ok((client_enc_key, server_enc_key, client_mac_key, server_mac_key))
}

/// Derive handshake confirmation keys
///
/// client_confirm = HKDF(master_secret, "vnet-handshake-client", 32)
/// server_confirm = HKDF(master_secret, "vnet-handshake-server", 32)
pub fn derive_handshake_keys(master_secret: &[u8]) -> Result<(KeyMaterial, KeyMaterial)> {
    let client_confirm = hkdf_expand(
        master_secret,
        super::HANDSHAKE_LABEL_CLIENT,
        32,
    )?;
    let server_confirm = hkdf_expand(
        master_secret,
        super::HANDSHAKE_LABEL_SERVER,
        32,
    )?;
    Ok((client_confirm, server_confirm))
}

/// Derive keys for a specific purpose with custom info
pub fn derive_keys(
    master_secret: &[u8],
    info: &[u8],
    length: usize,
) -> Result<KeyMaterial> {
    hkdf_expand(master_secret, info, length)
}

/// Manual PBKDF2-HMAC-SHA256 implementation to avoid digest version conflicts
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let hlen = 32; // SHA-256 output length
    let dk_len = output.len();
    let l = (dk_len + hlen - 1) / hlen; // number of blocks

    for block_idx in 1..=l {
        let mut mac = Hmac::<Sha256>::new_from_slice(password).expect("HMAC key creation failed");
        mac.update(salt);
        mac.update(&(block_idx as u32).to_be_bytes());
        let mut u = mac.finalize().into_bytes();

        let mut t = u;

        for _ in 1..iterations {
            let mut mac = Hmac::<Sha256>::new_from_slice(password).expect("HMAC key creation failed");
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
                *t_byte ^= u_byte;
            }
        }

        let start = (block_idx - 1) * hlen;
        let end = std::cmp::min(start + hlen, dk_len);
        output[start..end].copy_from_slice(&t[..end - start]);
    }
}

/// Derive user parameters key (for password-based auth) using PBKDF2-HMAC-SHA256
pub fn derive_user_params_key(password: &[u8], salt: &[u8]) -> Result<KeyMaterial> {
    let mut result = [0u8; 32];
    pbkdf2_hmac_sha256(password, salt, 100_000, &mut result);
    Ok(KeyMaterial::new(result.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract() {
        let salt = b"salt";
        let ikm = b"input key material";
        let prk = hkdf_extract(salt, ikm);
        assert_eq!(prk.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = [0x42; 32];
        let info = b"info";
        let okm = hkdf_expand(&prk, info, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn test_hkdf_combined() {
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"info";
        let okm = hkdf(salt, ikm, info, 48).unwrap();
        assert_eq!(okm.len(), 48);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let salt = b"salt";
        let ikm = b"ikm";
        let info = b"info";

        let okm1 = hkdf(salt, ikm, info, 32).unwrap();
        let okm2 = hkdf(salt, ikm, info, 32).unwrap();
        assert_eq!(okm1.as_bytes(), okm2.as_bytes());
    }

    #[test]
    fn test_hkdf_different_info() {
        let salt = b"salt";
        let ikm = b"ikm";

        let okm1 = hkdf(salt, ikm, b"info1", 32).unwrap();
        let okm2 = hkdf(salt, ikm, b"info2", 32).unwrap();
        assert_ne!(okm1.as_bytes(), okm2.as_bytes());
    }

    #[test]
    fn test_derive_session_keys() {
        let shared_secret = [0xAB; 32];
        let (client_enc, server_enc, client_mac, server_mac) = derive_session_keys(&shared_secret).unwrap();

        assert_eq!(client_enc.len(), 32);
        assert_eq!(server_enc.len(), 32);
        assert_eq!(client_mac.len(), 32);
        assert_eq!(server_mac.len(), 32);

        // All should be different
        assert_ne!(client_enc.as_bytes(), server_enc.as_bytes());
        assert_ne!(client_enc.as_bytes(), client_mac.as_bytes());
        assert_ne!(client_enc.as_bytes(), server_mac.as_bytes());
        assert_ne!(server_enc.as_bytes(), client_mac.as_bytes());
        assert_ne!(server_enc.as_bytes(), server_mac.as_bytes());
        assert_ne!(client_mac.as_bytes(), server_mac.as_bytes());
    }

    #[test]
    fn test_derive_session_keys_deterministic() {
        let shared_secret = [0xCD; 32];
        let (c1, s1, cm1, sm1) = derive_session_keys(&shared_secret).unwrap();
        let (c2, s2, cm2, sm2) = derive_session_keys(&shared_secret).unwrap();

        assert_eq!(c1.as_bytes(), c2.as_bytes());
        assert_eq!(s1.as_bytes(), s2.as_bytes());
        assert_eq!(cm1.as_bytes(), cm2.as_bytes());
        assert_eq!(sm1.as_bytes(), sm2.as_bytes());
    }

    #[test]
    fn test_derive_handshake_keys() {
        let master_secret = [0xEF; 32];
        let (client_confirm, server_confirm) = derive_handshake_keys(&master_secret).unwrap();

        assert_eq!(client_confirm.len(), 32);
        assert_eq!(server_confirm.len(), 32);
        assert_ne!(client_confirm.as_bytes(), server_confirm.as_bytes());
    }

    #[test]
    fn test_key_material_split() {
        let km = KeyMaterial::new(vec![1, 2, 3, 4]);
        let (first, second) = km.split_half().unwrap();
        assert_eq!(first.as_bytes(), &[1, 2]);
        assert_eq!(second.as_bytes(), &[3, 4]);
    }

    #[test]
    fn test_key_material_take() {
        let km = KeyMaterial::new(vec![1, 2, 3, 4, 5, 6]);
        let first = km.take_first(3).unwrap();
        assert_eq!(first.as_bytes(), &[1, 2, 3]);

        let last = km.take_last(3).unwrap();
        assert_eq!(last.as_bytes(), &[4, 5, 6]);
    }

    #[test]
    fn test_derive_user_params_key() {
        let password = b"my_password";
        let salt = b"salt1234";
        let key1 = derive_user_params_key(password, salt).unwrap();
        let key2 = derive_user_params_key(password, salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.len(), 32);

        // Different salt should produce different key
        let key3 = derive_user_params_key(password, b"different_salt").unwrap();
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }
}