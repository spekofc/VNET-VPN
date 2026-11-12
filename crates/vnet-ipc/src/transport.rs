//! vnet-ipc transport layer — JSON-RPC 2.0 over Unix sockets

use crate::{IpcError, IpcResult};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

#[cfg(not(windows))]
use tokio::net::{UnixListener, UnixStream};

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Async transport trait for async I/O (Unix sockets)
#[async_trait::async_trait]
pub trait AsyncTransport: Send + Sync {
    async fn send(&mut self, data: &[u8]) -> IpcResult<()>;
    async fn receive(&mut self) -> IpcResult<Option<Vec<u8>>>;
    async fn close(&mut self) -> IpcResult<()>;
}

#[cfg(not(windows))]
/// Unix socket transport (Linux/macOS) - async
pub struct UnixSocketTransport {
    stream: UnixStream,
    reader: TokioBufReader<UnixStream>,
}

#[cfg(not(windows))]
impl UnixSocketTransport {
    pub async fn connect(path: &str) -> IpcResult<Self> {
        let stream = UnixStream::connect(path).await.map_err(|e| IpcError::Io(e))?;
        let reader = TokioBufReader::new(stream);
        Ok(Self { stream, reader })
    }

    pub async fn listen(path: &str) -> IpcResult<UnixSocketListener> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).map_err(|e| IpcError::Io(e))?;
        Ok(UnixSocketListener { listener })
    }
}

#[cfg(not(windows))]
#[async_trait::async_trait]
impl AsyncTransport for UnixSocketTransport {
    async fn send(&mut self, data: &[u8]) -> IpcResult<()> {
        self.stream.write_all(data).await.map_err(|e| IpcError::Io(e))?;
        Ok(())
    }

    async fn receive(&mut self) -> IpcResult<Option<Vec<u8>>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line).await {
            Ok(0) => Ok(None),
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return self.receive().await;
                }
                Ok(Some(trimmed.as_bytes().to_vec()))
            }
            Err(e) => Err(IpcError::Io(e)),
        }
    }

    async fn close(&mut self) -> IpcResult<()> {
        self.stream.shutdown().await.map_err(|e| IpcError::Io(e))?;
        Ok(())
    }
}

#[cfg(not(windows))]
/// Unix socket listener (Linux/macOS)
pub struct UnixSocketListener {
    listener: UnixListener,
}

#[cfg(not(windows))]
impl UnixSocketListener {
    pub async fn accept(&self) -> IpcResult<UnixSocketTransport> {
        let (stream, _) = self.listener.accept().await.map_err(|e| IpcError::Io(e))?;
        let reader = TokioBufReader::new(stream);
        Ok(UnixSocketTransport { stream, reader })
    }
}

#[cfg(windows)]
/// Windows named pipe transport (generic over client/server)
pub struct NamedPipeTransport<S> {
    reader: TokioBufReader<tokio::io::ReadHalf<S>>,
    writer: tokio::io::WriteHalf<S>,
}

#[cfg(windows)]
impl<S> NamedPipeTransport<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    pub fn new(pipe: S) -> Self {
        let (reader, writer) = tokio::io::split(pipe);
        let reader = TokioBufReader::new(reader);
        Self { reader, writer }
    }
}

#[cfg(windows)]
pub async fn connect_named_pipe(path: &str) -> IpcResult<NamedPipeTransport<tokio::net::windows::named_pipe::NamedPipeClient>> {
    let pipe = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(path)
        .map_err(|e| IpcError::Io(e))?;
    Ok(NamedPipeTransport::new(pipe))
}

#[cfg(windows)]
pub fn listen_named_pipe(path: &str) -> IpcResult<NamedPipeListener> {
    let listener = NamedPipeListener { path: path.to_string() };
    Ok(listener)
}

#[cfg(windows)]
#[async_trait::async_trait]
impl<S> AsyncTransport for NamedPipeTransport<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    async fn send(&mut self, data: &[u8]) -> IpcResult<()> {
        self.writer.write_all(data).await.map_err(|e| IpcError::Io(e))?;
        Ok(())
    }

    async fn receive(&mut self) -> IpcResult<Option<Vec<u8>>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line).await {
            Ok(0) => Ok(None),
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return self.receive().await;
                }
                Ok(Some(trimmed.as_bytes().to_vec()))
            }
            Err(e) => Err(IpcError::Io(e)),
        }
    }

    async fn close(&mut self) -> IpcResult<()> {
        self.writer.shutdown().await.map_err(|e| IpcError::Io(e))?;
        Ok(())
    }
}

#[cfg(windows)]
/// Windows named pipe listener
pub struct NamedPipeListener {
    path: String,
}

#[cfg(windows)]
impl NamedPipeListener {
    pub async fn accept(&self) -> IpcResult<NamedPipeTransport<tokio::net::windows::named_pipe::NamedPipeServer>> {
        let server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&self.path)
            .map_err(|e| IpcError::Io(e))?;
        
        server.connect().await.map_err(|e| IpcError::Io(e))?;
        
        Ok(NamedPipeTransport::new(server))
    }
}

/// Async JSON-RPC server
pub struct AsyncJsonRpcServer<T: AsyncTransport> {
    transport: T,
    registry: crate::methods::MethodRegistry,
}

impl<T: AsyncTransport> AsyncJsonRpcServer<T> {
    pub fn new(transport: T, registry: crate::methods::MethodRegistry) -> Self {
        Self { transport, registry }
    }

    pub async fn run(&mut self) -> IpcResult<()> {
        loop {
            match self.transport.receive().await {
                Ok(Some(data)) => {
                    let request: JsonRpcRequest = serde_json::from_slice(&data)
                        .map_err(|e| IpcError::JsonRpc(e.to_string()))?;
                    
                    let response = self.handle_request(request).await;
                    let response_data = serde_json::to_vec(&response)
                        .map_err(|e| IpcError::JsonRpc(e.to_string()))?;
                    
                    self.transport.send(&response_data).await?;
                    self.transport.send(b"\n").await?;
                }
                Ok(None) => break,
                Err(e) => {
                    eprintln!("Transport error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();
        
        if request.jsonrpc != "2.0" {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: "Invalid JSON-RPC version".to_string(),
                    data: None,
                }),
                id,
            };
        }

        let result = self.registry.call(&request.method, request.params.unwrap_or(serde_json::Value::Null)).await;

        match result {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(result),
                error: None,
                id,
            },
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32603,
                    message: e.to_string(),
                    data: None,
                }),
                id,
            },
        }
    }
}

/// Async JSON-RPC client - takes ownership of transport
pub struct AsyncJsonRpcClient<T: AsyncTransport> {
    pub transport: T,
    next_id: u64,
}

impl<T: AsyncTransport> AsyncJsonRpcClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, next_id: 1 }
    }
    
    pub fn into_transport(self) -> T {
        self.transport
    }

    pub async fn call(&mut self, method: &str, params: serde_json::Value) -> IpcResult<serde_json::Value> {
        let id = serde_json::Value::Number(self.next_id.into());
        self.next_id += 1;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: Some(params),
            id: Some(id.clone()),
        };

        let request_data = serde_json::to_vec(&request)
            .map_err(|e| IpcError::JsonRpc(e.to_string()))?;
        
        self.transport.send(&request_data).await?;
        self.transport.send(b"\n").await?;

        let response_data = self.transport.receive().await?
            .ok_or_else(|| IpcError::JsonRpc("Connection closed".to_string()))?;
        
        let response: JsonRpcResponse = serde_json::from_slice(&response_data)
            .map_err(|e| IpcError::JsonRpc(e.to_string()))?;

        if let Some(error) = response.error {
            return Err(IpcError::JsonRpc(format!("RPC error {}: {}", error.code, error.message)));
        }

        if response.id != Some(id) {
            return Err(IpcError::JsonRpc("Response ID mismatch".to_string()));
        }

        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }
}