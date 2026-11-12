//! Protocol constants

/// Protocol magic bytes: "RDVP" (0x52445650)
pub const MAGIC: u32 = 0x52445650;

/// Protocol version
pub const VERSION: u8 = 2;

/// Maximum frame payload size (64 KiB - header)
pub const MAX_PAYLOAD_SIZE: usize = 65536 - 32;

/// Frame header size in bytes
pub const HEADER_SIZE: usize = 32;

/// Default MTU for TUN interface
pub const DEFAULT_MTU: u16 = 1400;

/// Handshake timeout (milliseconds)
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// Keepalive interval (milliseconds)
pub const KEEPALIVE_INTERVAL_MS: u64 = 30_000;

/// Replay window size (sequence numbers)
pub const REPLAY_WINDOW: u64 = 64;

/// Maximum frame size including header
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_PAYLOAD_SIZE;

/// Channel key size (256 bits)
pub const CHANNEL_KEY_SIZE: usize = 32;

/// MAC key size (256 bits)
pub const MAC_KEY_SIZE: usize = 32;

/// Nonce size for AEAD (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Tag size for AEAD (128 bits)
pub const TAG_SIZE: usize = 16;

/// ECDH public key compressed size (33 bytes)
pub const ECDH_PUBLIC_KEY_COMPRESSED: usize = 33;

/// ECDH public key uncompressed size (65 bytes)
pub const ECDH_PUBLIC_KEY_UNCOMPRESSED: usize = 65;

/// ECDH shared secret size (32 bytes)
pub const ECDH_SHARED_SECRET_SIZE: usize = 32;

/// Master secret size (32 bytes)
pub const MASTER_SECRET_SIZE: usize = 32;

/// Session ID size (16 bytes)
pub const SESSION_ID_SIZE: usize = 16;

/// Cookie size for DTLS-style cookie exchange (32 bytes)
pub const COOKIE_SIZE: usize = 32;