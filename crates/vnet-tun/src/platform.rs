//! Platform-specific TUN implementations

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub use unix::create_tun_device;