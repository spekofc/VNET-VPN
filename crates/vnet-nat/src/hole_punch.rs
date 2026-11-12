//! UDP hole punching implementation

use crate::{NatError, NatResult};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Hole punch configuration
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// Number of punch attempts
    pub attempts: usize,
    /// Interval between attempts
    pub interval: Duration,
    /// Timeout for each attempt
    pub timeout: Duration,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            attempts: 10,
            interval: Duration::from_millis(100),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Hole puncher for establishing direct UDP connectivity
pub struct HolePuncher {
    socket: UdpSocket,
    config: HolePunchConfig,
    remote_addr: SocketAddr,
}

impl HolePuncher {
    /// Create a new hole puncher
    pub async fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> NatResult<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        Ok(Self {
            socket,
            config: HolePunchConfig::default(),
            remote_addr,
        })
    }

    /// Create with custom config
    pub async fn with_config(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: HolePunchConfig,
    ) -> NatResult<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        Ok(Self {
            socket,
            config,
            remote_addr,
        })
    }

    /// Perform hole punching
    pub async fn punch(&self) -> NatResult<()> {
        for _attempt in 0..self.config.attempts {
            // Send punch packet
            self.socket.send_to(b"VNET_PUNCH", self.remote_addr).await?;
            
            // Wait for response
            let mut buf = [0u8; 1024];
            match timeout(Duration::from_millis(500), self.socket.recv(&mut buf)).await {
                Ok(Ok(_)) => {
                    return Ok(());
                }
                Err(_) => {
                    // Timeout, continue
                }
                Ok(Err(e)) => {
                    return Err(crate::NatError::HolePunch(e.to_string()));
                }
            }
            
            // Wait before next attempt
            tokio::time::sleep(self.config.interval).await;
        }
        
        Err(crate::NatError::HolePunch("Hole punch timed out".into()))
    }

    /// Punch with both sides coordinated (both sides send simultaneously)
    pub async fn punch_coordinated(&self, peer_ready: tokio::sync::oneshot::Receiver<()>) -> NatResult<()> {
        // Wait for peer to be ready
        let _ = peer_ready.await;
        
        // Send rapid-fire packets
        for _ in 0..20 {
            self.socket.send_to(b"VNET_PUNCH_COORD", self.remote_addr).await?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        // Listen for response
        let mut buf = [0u8; 1024];
        match timeout(Duration::from_secs(2), self.socket.recv(&mut buf)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(crate::NatError::HolePunch(e.to_string())),
            Err(_) => Err(crate::NatError::HolePunch("Coordinated punch timed out".into())),
        }
    }
}