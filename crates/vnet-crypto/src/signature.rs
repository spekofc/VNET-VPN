//! Digital signatures using ECDSA P-256

use crate::error::{CryptoError, Result};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature as P256Signature, SigningKey, VerifyingKey as P256VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// ECDSA P-256 signature (DER encoded)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Create from DER-encoded bytes
    pub fn from_der(der: &[u8]) -> Result<Self> {
        P256Signature::from_der(der)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        Ok(Self(der.to_vec()))
    }

    /// Create from raw (r || s) bytes (64 bytes)
    pub fn from_raw(raw: &[u8]) -> Result<Self> {
        if raw.len() != 64 {
            return Err(CryptoError::InvalidSignature("Raw signature must be 64 bytes".into()));
        }
        let sig = P256Signature::from_slice(raw)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        Ok(Self(sig.to_der().as_bytes().to_vec()))
    }

    /// Get DER-encoded bytes
    pub fn to_der(&self) -> &[u8] {
        &self.0
    }

    /// Get raw (r || s) bytes (64 bytes)
    pub fn to_raw(&self) -> Result<[u8; 64]> {
        let sig = P256Signature::from_der(&self.0)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        let raw = sig.to_bytes();
        Ok(raw.into())
    }

    /// Get length of DER encoding
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// ECDSA P-256 signing key pair
pub struct SignatureKeyPair {
    signing_key: SigningKey,
    verifying_key: P256VerifyingKey,
}

impl SignatureKeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Create from PKCS#8 DER-encoded private key
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Create from PKCS#8 PEM-encoded private key
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Create from raw private key bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize { expected: 32, actual: bytes.len() });
        }
        let signing_key = SigningKey::from_bytes(bytes.into())
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self { signing_key, verifying_key })
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.verifying_key)
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<Signature> {
        let sig: P256Signature = self.signing_key.sign(data);
        Ok(Signature(sig.to_der().as_bytes().to_vec()))
    }

    /// Sign data with raw output
    pub fn sign_raw(&self, data: &[u8]) -> Result<[u8; 64]> {
        let sig: P256Signature = self.signing_key.sign(data);
        Ok(sig.to_bytes().into())
    }

    /// Export private key as PKCS#8 DER
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.signing_key
            .to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| CryptoError::SerializationFailed(e.to_string()))
    }

    /// Export private key as PKCS#8 PEM
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.signing_key
            .to_pkcs8_pem(Default::default())
            .map(|pem| pem.to_string())
            .map_err(|e| CryptoError::SerializationFailed(e.to_string()))
    }

    /// Get raw private key bytes
    pub fn private_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }
}

/// ECDSA P-256 verifying key (public key)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyingKey(#[serde(with = "verifying_key_serde")] P256VerifyingKey);

mod verifying_key_serde {
    use p256::ecdsa::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_sec1_bytes();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl VerifyingKey {
    /// Create from compressed public key bytes (33 bytes)
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(CryptoError::InvalidKeySize { expected: 33, actual: bytes.len() });
        }
        let key = P256VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Ok(Self(key))
    }

    /// Create from uncompressed public key bytes (65 bytes)
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(CryptoError::InvalidKeySize { expected: 65, actual: bytes.len() });
        }
        let key = P256VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Ok(Self(key))
    }

    /// Create from SEC1 DER-encoded public key
    pub fn from_sec1_der(der: &[u8]) -> Result<Self> {
        let key = P256VerifyingKey::from_sec1_bytes(der)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Ok(Self(key))
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

    /// Verify a signature
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<bool> {
        let sig = P256Signature::from_der(&signature.0)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        Ok(self.0.verify(data, &sig).is_ok())
    }

    /// Verify a raw signature
    pub fn verify_raw(&self, data: &[u8], signature: &[u8; 64]) -> Result<bool> {
        let sig = P256Signature::from_slice(signature)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        Ok(self.0.verify(data, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_generation() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let verifying = keypair.verifying_key();

        let data = b"Test message for signing";
        let sig = keypair.sign(data).unwrap();

        assert!(verifying.verify(data, &sig).unwrap());
    }

    #[test]
    fn test_signature_raw() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let verifying = keypair.verifying_key();

        let data = b"Test message";
        let raw_sig = keypair.sign_raw(data).unwrap();
        assert_eq!(raw_sig.len(), 64);

        assert!(verifying.verify_raw(data, &raw_sig).unwrap());
    }

    #[test]
    fn test_signature_verification_fails() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let verifying = keypair.verifying_key();

        let data = b"Original message";
        let sig = keypair.sign(data).unwrap();

        // Wrong message should fail
        assert!(!verifying.verify(b"Wrong message", &sig).unwrap());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = SignatureKeyPair::generate().unwrap();

        // Test PKCS#8 DER
        let der = keypair.to_pkcs8_der().unwrap();
        let restored = SignatureKeyPair::from_pkcs8_der(&der).unwrap();
        assert_eq!(keypair.private_bytes(), restored.private_bytes());

        // Test PKCS#8 PEM
        let pem = keypair.to_pkcs8_pem().unwrap();
        let restored = SignatureKeyPair::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(keypair.private_bytes(), restored.private_bytes());

        // Test raw bytes
        let bytes = keypair.private_bytes();
        let restored = SignatureKeyPair::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.private_bytes(), restored.private_bytes());
    }

    #[test]
    fn test_verifying_key_serialization() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let verifying = keypair.verifying_key();

        // Compressed
        let compressed = verifying.to_compressed_bytes();
        let restored = VerifyingKey::from_compressed_bytes(&compressed).unwrap();
        assert_eq!(verifying, restored);

        // Uncompressed
        let uncompressed = verifying.to_uncompressed_bytes();
        let restored = VerifyingKey::from_uncompressed_bytes(&uncompressed).unwrap();
        assert_eq!(verifying, restored);

        // SEC1 DER
        let der = verifying.to_sec1_der();
        let restored = VerifyingKey::from_sec1_der(&der).unwrap();
        assert_eq!(verifying, restored);
    }

    #[test]
    fn test_signature_from_der() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let sig = keypair.sign(b"test").unwrap();

        let restored = Signature::from_der(sig.to_der()).unwrap();
        assert_eq!(sig, restored);
    }

    #[test]
    fn test_signature_from_raw() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let raw_sig = keypair.sign_raw(b"test").unwrap();

        let sig = Signature::from_raw(&raw_sig).unwrap();
        let restored_raw = sig.to_raw().unwrap();
        assert_eq!(raw_sig, restored_raw);
    }

    #[test]
    fn test_signature_tamper() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let verifying = keypair.verifying_key();

        let data = b"test message";
        let mut sig = keypair.sign(data).unwrap();

        // Tamper with signature
        sig.0[0] ^= 0xFF;

        // Tampered signature should fail verification (either parse error or invalid signature)
        let result = verifying.verify(data, &sig);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_signature_wrong_key() {
        let keypair1 = SignatureKeyPair::generate().unwrap();
        let keypair2 = SignatureKeyPair::generate().unwrap();

        let data = b"test message";
        let sig = keypair1.sign(data).unwrap();

        assert!(!keypair2.verifying_key().verify(data, &sig).unwrap());
    }
}