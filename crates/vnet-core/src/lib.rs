//! vnet-core — Core session management and peer mesh

#![warn(missing_docs, clippy::all)]

pub mod session;
pub mod peer;
pub mod mesh;
pub mod rekey;
pub mod p2p;
#[cfg(windows)]
pub mod tun_win;

pub use session::{
    default_stun_servers, Session, SessionConfig, SessionEvent, SessionState,
};
pub use peer::{Peer, PeerConfig};
pub use mesh::{Mesh, MeshConfig};
pub use rekey::{RekeyManager, RekeyConfig};

/// Core result type
pub type CoreResult<T> = std::result::Result<T, CoreError>;

/// Core errors
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("Session error: {0}")]
    Session(String),
    #[error("Peer error: {0}")]
    Peer(String),
    #[error("Mesh error: {0}")]
    Mesh(String),
    #[error("Rekey error: {0}")]
    Rekey(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] vnet_crypto::error::CryptoError),
    #[error("Proto error: {0}")]
    Proto(#[from] vnet_proto::codec::CodecError),
    #[error("Handshake error: {0}")]
    Handshake(#[from] vnet_proto::handshake::HandshakeError),
    #[error("NAT error: {0}")]
    Nat(#[from] vnet_nat::NatError),
    #[error("TUN error: {0}")]
    Tun(#[from] vnet_tun::TunError),
}