//! Peer management stub

use crate::{CoreError, CoreResult};

/// Peer configuration
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub id: String,
    pub address: String,
    pub public_key: Vec<u8>,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            address: String::new(),
            public_key: Vec::new(),
        }
    }
}

/// Peer representation
pub struct Peer {
    config: PeerConfig,
}

impl Peer {
    pub fn new(config: PeerConfig) -> Self {
        Self { config }
    }

    pub fn id(&self) -> &str {
        &self.config.id
    }

    pub fn address(&self) -> &str {
        &self.config.address
    }

    pub fn public_key(&self) -> &[u8] {
        &self.config.public_key
    }
}