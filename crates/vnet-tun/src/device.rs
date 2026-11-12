//! TUN device abstraction

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// TUN device trait
#[async_trait]
pub trait TunDevice: Send + Sync {
    /// Get the device name
    fn name(&self) -> &str;

    /// Get the MTU
    fn mtu(&self) -> u16;

    /// Split into reader and writer
    fn split(self: Box<Self>) -> (Box<dyn TunReader>, Box<dyn TunWriter>);

    /// Get the device file descriptor (Unix) or handle (Windows)
    #[cfg(unix)]
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd;

    #[cfg(windows)]
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle;
}

/// TUN reader trait
pub trait TunReader: AsyncRead + Send + Sync + Unpin {
    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), std::io::Error>;
}

/// TUN writer trait
pub trait TunWriter: AsyncWrite + Send + Sync + Unpin {
    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), std::io::Error>;
}

/// Create a TUN device based on the platform
pub async fn create_device(config: crate::TunConfig) -> Result<Box<dyn TunDevice>, crate::TunError> {
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows::create_wintun_device(config).await
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        crate::platform::unix::create_tun_device(config).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd")))]
    {
        Err(crate::TunError::PlatformNotSupported)
    }
}