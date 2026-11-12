//! Unix TUN device implementation using /dev/net/tun

#[cfg(unix)]
use crate::{TunConfig, TunError, TunDevice, TunReader, TunWriter};
#[cfg(unix)]
use async_trait::async_trait;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::task::{Context, Poll};
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::mem;
#[cfg(unix)]
use libc::{c_int, c_short, IFNAMSIZ, IFF_TUN, IFF_NO_PI, TUNSETIFF, ioctl, ifreq};

// ifreq structure for TUNSETIFF ioctl
#[cfg(unix)]
#[repr(C)]
struct IfReq {
    ifr_name: [c_short; IFNAMSIZ as usize],
    ifr_ifru: IfReqIfru,
}

#[cfg(unix)]
#[repr(C)]
union IfReqIfru {
    ifru_flags: c_short,
    ifru_addr: [c_short; 16],
}

/// Unix TUN device using /dev/net/tun
#[cfg(unix)]
pub struct UnixTunDevice {
    fd: AsyncFd<File>,
    name: String,
    mtu: u16,
}

#[cfg(unix)]
impl UnixTunDevice {
    pub async fn new(config: TunConfig) -> Result<Self, TunError> {
        // Open /dev/net/tun
        let file = File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| TunError::CreationFailed(format!("Failed to open /dev/net/tun: {}", e)))?;

        let fd = file.as_raw_fd();

        // Set up the TUN interface using ioctl
        let name = config.name.clone().unwrap_or_else(|| "tun0".to_string());
        let mut ifr = create_ifreq(&name);

        // IFF_TUN | IFF_NO_PI
        let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as c_short;
        unsafe { ifr.ifr_ifru.ifru_flags = flags };

        // Perform ioctl to create the interface
        unsafe {
            let ret = ioctl(fd, libc::TUNSETIFF, &mut ifr as *mut _);
            if ret < 0 {
                return Err(TunError::CreationFailed(
                    format!("ioctl(TUNSETIFF) failed: {}", io::Error::last_os_error())
                ));
            }
        }

        // Extract the actual interface name from the ifreq
        let name = extract_ifname(&ifr);

        // Set MTU if specified
        if config.mtu > 0 {
            set_interface_mtu(&name, config.mtu)?;
        }

        // Set IP address if specified
        if let Some(addr) = config.address {
            set_interface_address(&name, addr, config.netmask)?;
        }

        // Bring interface up if requested
        if config.up {
            set_interface_up(&name)?;
        }

        let async_fd = AsyncFd::new(file)
            .map_err(|e| TunError::CreationFailed(e.to_string()))?;

        Ok(Self {
            fd: async_fd,
            name,
            mtu: config.mtu.max(1),
        })
    }
}

#[cfg(unix)]
fn create_ifreq(name: &str) -> ifreq {
    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let name_bytes = name.as_bytes();
    let len = name_bytes.len().min(libc::IFNAMSIZ as usize - 1);
    for (i, &b) in name_bytes.iter().enumerate().take(len) {
        ifr.ifr_name[i] = b as i8;
    }
    ifr
}

#[cfg(unix)]
fn extract_ifname(ifr: &ifreq) -> String {
    let name_bytes = &ifr.ifr_name;
    let len = name_bytes.iter().position(|&c| c == 0).unwrap_or(libc::IFNAMSIZ as usize);
    let bytes: Vec<u8> = name_bytes.iter().take(len).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(unix)]
fn set_interface_mtu(name: &str, mtu: u16) -> Result<(), std::io::Error> {
    use std::process::Command;
    Command::new("ip")
        .args(["link", "set", "dev", name, "mtu", &mtu.to_string()])
        .status()
        .map(|_| ())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

#[cfg(unix)]
fn set_interface_address(name: &str, addr: std::net::IpAddr, netmask: Option<std::net::IpAddr>) -> Result<(), std::io::Error> {
    use std::process::Command;
    let addr_str = match addr {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => ip.to_string(),
    };
    let prefix = match (addr, netmask) {
        (std::net::IpAddr::V4(_), Some(std::net::IpAddr::V4(mask))) => {
            let mask_bytes = mask.octets();
            let prefix = mask_bytes.iter().map(|b| b.count_ones()).sum::<u32>();
            format!("/{}", prefix)
        }
        (std::net::IpAddr::V6(_), Some(std::net::IpAddr::V6(mask))) => {
            let mask_bytes = mask.octets();
            let prefix = mask_bytes.iter().map(|b| b.count_ones()).sum::<u32>();
            format!("/{}", prefix)
        }
        _ => "/32".to_string(),
    };
    Command::new("ip")
        .args(["addr", "add", &format!("{}{}", addr_str, prefix), "dev", name])
        .status()
        .map(|_| ())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

#[cfg(unix)]
fn set_interface_up(name: &str) -> Result<(), std::io::Error> {
    use std::process::Command;
    Command::new("ip")
        .args(["link", "set", "dev", name, "up"])
        .status()
        .map(|_| ())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

#[cfg(unix)]
#[async_trait]
impl TunDevice for UnixTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn split(self: Box<Self>) -> (Box<dyn TunReader>, Box<dyn TunWriter>) {
        let (reader, writer) = self.fd.split();
        (Box::new(UnixTunReader(reader)), Box::new(UnixTunWriter(writer)))
    }

    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    #[cfg(windows)]
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        unimplemented!("UnixTunDevice on Windows")
    }
}

#[cfg(unix)]
struct UnixTunReader {
    reader: tokio::io::unix::AsyncFdRead<'static, File>,
}

#[cfg(unix)]
impl TunReader for UnixTunReader {
    fn set_nonblocking(&mut self, _nonblocking: bool) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(unix)]
impl AsyncRead for UnixTunReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

#[cfg(unix)]
struct UnixTunWriter {
    writer: tokio::io::unix::AsyncFdWrite<'static, File>,
}

#[cfg(unix)]
impl TunWriter for UnixTunWriter {
    fn set_nonblocking(&mut self, _nonblocking: bool) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(unix)]
impl AsyncWrite for UnixTunWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(unix)]
pub async fn create_tun_device(config: TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    UnixTunDevice::new(config).await.map(|d| Box::new(d) as Box<dyn TunDevice>)
}