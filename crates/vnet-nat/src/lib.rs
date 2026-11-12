//! vnet-nat — NAT traversal (STUN, ICE, UDP hole-punching)
//!
//! Implements RFC 5389 (STUN), RFC 8445 (ICE), and UDP hole-punching.

#![warn(missing_docs, clippy::all)]

pub mod stun;
pub mod ice;
pub mod hole_punch;
pub mod endpoint;

pub use endpoint::{Endpoint, Transport};
pub use ice::{IceAgent, IceCandidate, IceState};
pub use stun::{StunClient, StunMessage, StunError, StunMessageBuilder};

/// NAT traversal result
pub type NatResult<T> = Result<T, NatError>;

/// NAT traversal errors
#[derive(Debug, thiserror::Error)]
pub enum NatError {
    #[error("STUN error: {0}")]
    Stun(#[from] stun::StunError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("ICE error: {0}")]
    Ice(String),
    #[error("Hole punch failed: {0}")]
    HolePunch(String),
    #[error("Invalid endpoint: {0}")]
    InvalidEndpoint(String),
}