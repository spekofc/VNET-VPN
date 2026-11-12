//! Secure random number generation
//!
//! Uses `getrandom` which provides OS-backed CSPRNG on all platforms.

use crate::error::{CryptoError, Result};
use getrandom::getrandom;

/// Fill buffer with cryptographically secure random bytes
pub fn secure_random(buf: &mut [u8]) -> Result<()> {
    getrandom(buf).map_err(|e| CryptoError::RandomFailed(e.to_string()))
}

/// Generate a random 32-byte array
pub fn random_32() -> Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    secure_random(&mut buf)?;
    Ok(buf)
}

/// Generate a random 16-byte array
pub fn random_16() -> Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    secure_random(&mut buf)?;
    Ok(buf)
}

/// Generate a random 12-byte array (for nonces)
pub fn random_12() -> Result<[u8; 12]> {
    let mut buf = [0u8; 12];
    secure_random(&mut buf)?;
    Ok(buf)
}

/// Generate random bytes of arbitrary length
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    secure_random(&mut buf)?;
    Ok(buf)
}

/// Generate a random u64
pub fn random_u64() -> Result<u64> {
    let mut buf = [0u8; 8];
    secure_random(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Generate a random u32
pub fn random_u32() -> Result<u32> {
    let mut buf = [0u8; 4];
    secure_random(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random() {
        let mut buf = [0u8; 32];
        secure_random(&mut buf).unwrap();
        // Should not be all zeros
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_random_32() {
        let r1 = random_32().unwrap();
        let r2 = random_32().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_16() {
        let r1 = random_16().unwrap();
        let r2 = random_16().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_12() {
        let r1 = random_12().unwrap();
        let r2 = random_12().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_bytes() {
        let r1 = random_bytes(64).unwrap();
        let r2 = random_bytes(64).unwrap();
        assert_eq!(r1.len(), 64);
        assert_eq!(r2.len(), 64);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_u64() {
        let r1 = random_u64().unwrap();
        let r2 = random_u64().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_u32() {
        let r1 = random_u32().unwrap();
        let r2 = random_u32().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_distribution() {
        // Basic test that random values are distributed
        let mut zeros = 0;
        let mut ones = 0;
        for _ in 0..1000 {
            let b = random_bytes(1).unwrap()[0];
            if b == 0 {
                zeros += 1;
            }
            if b == 255 {
                ones += 1;
            }
        }
        // Should have some zeros and some 255s (not exact but should happen)
        // This is a very basic sanity check
        assert!(zeros < 1000); // Not all zeros
    }
}