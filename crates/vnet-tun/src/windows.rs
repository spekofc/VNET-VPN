//! Windows TUN device implementation using Wintun

use crate::device::{TunDevice, TunReader, TunWriter, TunConfig, TunError};
use async_trait::async_trait;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wintun::{Adapter, Session};
use std::sync::Arc;
use std::sync::Mutex;

/// Windows TUN device using Wintun
pub struct WintunDevice {
    adapter: Adapter,
    session: Arc<Mutex<Session>>,
    name: String,
    mtu: u16,
}

impl WintunDevice {
    pub async fn new(config: super::super::TunConfig) -> Result<Self, super::super::TunError> {
        // Create Wintun adapter
        let name = config.name.clone().unwrap_or_else(|| "vnet-tun".to_string());
        let adapter = Adapter::create(&name, "VNET TUN Adapter", None)
            .map_err(|e| super::super::TunError::CreationFailed(e.to_string()))?;

        // Set MTU
        let mtu = config.mtu.max(1);
        adapter.set_mtu(mtu as u32)
            .map_err(|e| super::super::TunError::CreationFailed(e.to_string()))?;

        // Create session
        let session = Arc::new(Mutex::new(Session::new(&adapter, config.mtu as usize)
            .map_err(|e| super::super::TunError::CreationFailed(e.to_string()))?));

        // Get actual adapter name
        let name = adapter.name()
            .map_err(|e| super::super::TunError::CreationFailed(e.to_string()))?;

        Ok(Self {
            adapter,
            session,
            name,
            mtu: config.mtu.max(1),
        })
    }
}

#[async_trait::async_trait]
impl super::TunDevice for WintunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn split(self: Box<Self>) -> (Box<dyn super::TunReader>, Box<dyn super::TunWriter>) {
        let session = self.session.clone();
        (Box::new(WintunReader(session.clone())), Box::new(WintunWriter(session)))
    }

    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.adapter.handle().as_raw_handle()
    }
}

struct WintunReader {
    session: Arc<Mutex<wintun::Session>>,
}

impl super::TunReader for WintunReader {
    fn set_nonblocking(&mut self, _nonblocking: bool) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl AsyncRead for WintunReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut session = match self.session.try_lock() {
            Ok(s) => s,
            Err(_) => return Poll::Pending,
        };

        let mut buf = vec![0u8; self.remaining()];
        match session.read_packet(&mut buf) {
            Ok(size) => {
                buf.put_slice(&buf[..size]);
                Poll::Ready(Ok(()))
            }
            Err(wintun::Error::Empty) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
        }
    }
}

struct WintunWriter {
    session: Arc<Mutex<wintun::Session>>,
}

impl super::TunWriter for WintunWriter {
    fn set_nonblocking(&mut self, _nonblocking: bool) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl AsyncWrite for WintunWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut session = match self.session.try_lock() {
            Ok(s) => s,
            Err(_) => return Poll::Pending,
        };

        match session.write_packet(buf) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(wintun::Error::Full) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub async fn create_wintun_device(config: super::TunConfig) -> Result<Box<dyn super::TunDevice>, super::super::TunError> {
    WintunDevice::new(config).await.map(|d| Box::new(d) as Box<dyn super::TunDevice>)
}