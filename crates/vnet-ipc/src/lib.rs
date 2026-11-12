//! vnet-ipc — Local control plane IPC

#![warn(missing_docs, clippy::all)]

pub mod server;
pub mod client;
pub mod methods;
pub mod transport;

pub use server::IpcServer;
pub use client::IpcClient;
pub use methods::{MethodRegistry, MethodError};
pub use transport::{AsyncJsonRpcServer, AsyncJsonRpcClient, JsonRpcRequest, JsonRpcResponse};

#[cfg(not(windows))]
pub use transport::{UnixSocketTransport, UnixSocketListener};

#[cfg(windows)]
pub use transport::{NamedPipeTransport, NamedPipeListener};

/// IPC result type
pub type IpcResult<T> = std::result::Result<T, IpcError>;

/// IPC errors
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("Server error: {0}")]
    Server(String),
    #[error("Client error: {0}")]
    Client(String),
    #[error("Method error: {0}")]
    Method(#[from] methods::MethodError),
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    #[error("JSON-RPC error: {0}")]
    JsonRpc(String),
    #[error("Core error: {0}")]
    Core(#[from] vnet_core::CoreError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// IPC server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub unix_socket: Option<String>,
    pub named_pipe: Option<String>,
    pub http_endpoint: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            unix_socket: Some("/tmp/vnet.sock".into()),
            named_pipe: Some(r"\\.\pipe\vnet".into()),
            http_endpoint: None,
        }
    }
}

/// IPC client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub unix_socket: Option<String>,
    pub named_pipe: Option<String>,
    pub http_endpoint: Option<String>,
    pub timeout: std::time::Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            unix_socket: Some("/tmp/vnet.sock".into()),
            named_pipe: Some(r"\\.\pipe\vnet".into()),
            http_endpoint: None,
            timeout: std::time::Duration::from_secs(5),
        }
    }
}