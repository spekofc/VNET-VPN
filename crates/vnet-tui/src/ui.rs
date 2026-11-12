//! TUI UI

use crate::app::{TuiError, TuiResult};

/// TUI UI components stub
pub struct Ui {
    // Stub implementation
}

impl Ui {
    pub fn new() -> Self {
        Self {}
    }

    pub fn draw(&self) -> TuiResult<()> {
        Ok(())
    }

    pub fn render_status(&self, _status: &str) -> TuiResult<()> {
        Ok(())
    }

    pub fn render_peers(&self, _peers: &[PeerInfo]) -> TuiResult<()> {
        Ok(())
    }
}

/// Peer info for UI display
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub name: String,
    pub status: String,
    pub address: String,
}

impl PeerInfo {
    pub fn new(name: String, status: String, address: String) -> Self {
        Self { name, status, address }
    }
}