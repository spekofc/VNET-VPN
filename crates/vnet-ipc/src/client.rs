//! IPC client with JSON-RPC 2.0 over Unix sockets (Linux/macOS) and named pipes (Windows)

use crate::{IpcError, IpcResult, ClientConfig};
use crate::transport::{AsyncJsonRpcClient, AsyncTransport};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(not(windows))]
use crate::transport::UnixSocketTransport;
#[cfg(windows)]
use crate::transport::NamedPipeTransport;
use tracing::info;

#[cfg(not(windows))]
use tokio::net::UnixStream;

/// IPC client with actual transport support
pub struct IpcClient {
    config: ClientConfig,
    #[cfg(not(windows))]
    transport: Arc<Mutex<Option<UnixSocketTransport>>>,
    #[cfg(windows)]
    transport: Arc<Mutex<Option<NamedPipeTransport<tokio::net::windows::named_pipe::NamedPipeClient>>>>,
}

impl IpcClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { 
            config, 
            #[cfg(not(windows))]
            transport: Arc::new(Mutex::new(None)),
            #[cfg(windows)]
            transport: Arc::new(Mutex::new(None)) 
        }
    }

    pub async fn connect(&mut self) -> IpcResult<()> {
        #[cfg(not(windows))]
        {
            self.connect_unix().await
        }
        #[cfg(windows)]
        {
            self.connect_named_pipe().await
        }
    }

    #[cfg(not(windows))]
    async fn connect_unix(&mut self) -> IpcResult<()> {
        let socket_path = self.config.unix_socket.as_deref()
            .unwrap_or("/tmp/vnet.sock");
        
        let transport = UnixSocketTransport::connect(socket_path).await
            .map_err(|e| IpcError::Client(format!("Failed to connect to Unix socket: {}", e)))?;
        
        *self.transport.lock().await = Some(transport);
        info!("IPC client connected to Unix socket: {}", socket_path);
        Ok(())
    }

    #[cfg(windows)]
    async fn connect_named_pipe(&mut self) -> IpcResult<()> {
        let pipe_path = self.config.named_pipe.as_deref()
            .unwrap_or(r"\\.\pipe\vnet");
        
        let transport = crate::transport::connect_named_pipe(pipe_path).await
            .map_err(|e| IpcError::Client(format!("Failed to connect to named pipe: {}", e)))?;
        
        *self.transport.lock().await = Some(transport);
        info!("IPC client connected to named pipe: {}", pipe_path);
        Ok(())
    }

    pub async fn disconnect(&mut self) -> IpcResult<()> {
        #[cfg(not(windows))]
        {
            if let Some(mut transport) = self.transport.lock().await.take() {
                transport.close().await?;
            }
        }
        #[cfg(windows)]
        {
            if let Some(mut transport) = self.transport.lock().await.take() {
                transport.close().await?;
            }
        }
        Ok(())
    }

    pub async fn call(&self, method: &str, params: serde_json::Value) -> IpcResult<serde_json::Value> {
        #[cfg(not(windows))]
        {
            let mut transport_guard = self.transport.lock().await;
            if let Some(mut transport) = transport_guard.take() {
                let mut client = AsyncJsonRpcClient::new(transport);
                let result = client.call(method, params).await;
                // Put transport back
                *transport_guard = Some(client.into_transport());
                result
            } else {
                Err(IpcError::Client("Not connected".to_string()))
            }
        }
        #[cfg(windows)]
        {
            let mut transport_guard = self.transport.lock().await;
            if let Some(mut transport) = transport_guard.take() {
                let mut client = AsyncJsonRpcClient::new(transport);
                let result = client.call(method, params).await;
                // Put transport back
                *transport_guard = Some(client.into_transport());
                result
            } else {
                Err(IpcError::Client("Not connected".to_string()))
            }
        }
    }
}