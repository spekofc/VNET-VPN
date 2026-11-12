//! vnet-tun — Cross-platform TUN device abstraction

#![warn(missing_docs, clippy::all)]

mod device;
mod platform;

pub use device::{TunDevice, TunReader, TunWriter};

/// TUN errors
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("Device creation failed: {0}")]
    CreationFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Platform not supported")]
    PlatformNotSupported,
    #[error("Permission denied: need CAP_NET_ADMIN or Administrator")]
    PermissionDenied,
}

/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: Option<String>,
    pub mtu: u16,
    pub address: Option<std::net::IpAddr>,
    pub netmask: Option<std::net::IpAddr>,
    pub up: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            mtu: 1400,
            address: None,
            netmask: None,
            up: true,
        }
    }
}

/// TUN builder
pub struct TunBuilder {
    config: TunConfig,
}

impl TunBuilder {
    pub fn new() -> Self {
        Self { config: TunConfig::default() }
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.config.name = Some(name.into());
        self
    }

    pub fn mtu(mut self, mtu: u16) -> Self {
        self.config.mtu = mtu;
        self
    }

    pub fn address(mut self, addr: std::net::IpAddr) -> Self {
        self.config.address = Some(addr);
        self
    }

    pub fn netmask(mut self, mask: std::net::IpAddr) -> Self {
        self.config.netmask = Some(mask);
        self
    }

    pub fn up(mut self, up: bool) -> Self {
        self.config.up = up;
        self
    }

    pub async fn build(self) -> Result<Box<dyn TunDevice>, TunError> {
        device::create_device(self.config).await
    }
}