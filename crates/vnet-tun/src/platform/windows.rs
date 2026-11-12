//! Windows TUN device implementation using Wintun

#[cfg(windows)]
use crate::{TunConfig, TunError, TunDevice, TunReader, TunWriter};
#[cfg(windows)]
use async_trait::async_trait;
#[cfg(windows)]
use std::os::windows::io::RawHandle;
#[cfg(windows)]
use std::pin::Pin;
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::task::{Context, Poll};
#[cfg(windows)]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(windows)]
use wintun::{Adapter, Session};
#[cfg(windows)]
use std::io;

/// Windows TUN device using Wintun
#[cfg(windows)]
pub struct WindowsTunDevice {
    _wintun: wintun::Wintun,
    _adapter: Arc<Adapter>, // Kept to maintain Arc lifetime
    session: Arc<Session>,
    name: String,
    mtu: u16,
}

#[cfg(windows)]
impl WindowsTunDevice {
    pub async fn new(config: TunConfig) -> Result<Self, TunError> {
        let name = config.name.clone().unwrap_or_else(|| "vnet".to_string());

        // Load Wintun DLL (must be in PATH or same directory as executable)
        let wintun = unsafe { wintun::load() }
            .map_err(|e| TunError::CreationFailed(format!("Failed to load wintun.dll: {}", e)))?;

        // Create Wintun adapter
        let adapter = Adapter::create(&wintun, &name, "vnet TUN Adapter", None)
            .map_err(|e| TunError::CreationFailed(e.to_string()))?;

        // Set MTU
        let mtu = config.mtu.max(1);
        adapter.set_mtu(mtu as usize)
            .map_err(|e| TunError::CreationFailed(e.to_string()))?;

        // Create session with buffer size
        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| TunError::CreationFailed(e.to_string()))?);

        // Get actual adapter name
        let name = adapter.get_name()
            .map_err(|e| TunError::CreationFailed(e.to_string()))?;

        Ok(Self {
            _wintun: wintun,
            _adapter: adapter,
            session,
            name,
            mtu: config.mtu.max(1),
        })
    }
}

#[cfg(windows)]
#[async_trait]
impl TunDevice for WindowsTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn split(self: Box<Self>) -> (Box<dyn TunReader>, Box<dyn TunWriter>) {
        let session = self.session.clone();
        (Box::new(WindowsTunReader::new(session.clone())), Box::new(WindowsTunWriter::new(session)))
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        unimplemented!("WindowsTunDevice on Unix")
    }

    #[cfg(windows)]
    fn as_raw_handle(&self) -> RawHandle {
        // Wintun adapter doesn't expose a raw handle; return null as placeholder
        std::ptr::null_mut()
    }
}

#[cfg(windows)]
struct WindowsTunReader {
    session: Arc<Session>,
}

#[cfg(windows)]
impl WindowsTunReader {
    fn new(session: Arc<Session>) -> Self {
        Self { session }
    }
}

#[cfg(windows)]
impl TunReader for WindowsTunReader {
    fn set_nonblocking(&mut self, _nonblocking: bool) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(windows)]
impl AsyncRead for WindowsTunReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Use try_receive for non-blocking read
        match self.session.try_receive() {
            Ok(Some(packet)) => {
                let data = packet.bytes();
                if data.len() <= buf.remaining() {
                    buf.put_slice(data);
                    Poll::Ready(Ok(()))
                } else {
                    // Packet too large for buffer
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "Packet too large")))
                }
            }
            Ok(None) => {
                // No packet available, register waker and return pending
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
        }
    }
}

#[cfg(windows)]
struct WindowsTunWriter {
    session: Arc<Session>,
}

#[cfg(windows)]
impl WindowsTunWriter {
    fn new(session: Arc<Session>) -> Self {
        Self { session }
    }
}

#[cfg(windows)]
impl TunWriter for WindowsTunWriter {
    fn set_nonblocking(&mut self, _nonblocking: bool) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(windows)]
impl AsyncWrite for WindowsTunWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Allocate a send packet
        match self.session.allocate_send_packet(buf.len() as u16) {
            Ok(mut packet) => {
                packet.bytes_mut().copy_from_slice(buf);
                self.session.send_packet(packet);
                Poll::Ready(Ok(buf.len()))
            }
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(windows)]
pub async fn create_wintun_device(config: TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    WindowsTunDevice::new(config).await.map(|d| Box::new(d) as Box<dyn TunDevice>)
}