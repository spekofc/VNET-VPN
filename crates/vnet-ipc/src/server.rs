//! IPC server with JSON-RPC 2.0 over Unix sockets (Linux/macOS) and named pipes (Windows)

use crate::{IpcError, IpcResult, ServerConfig};
use crate::methods::MethodRegistry;
use crate::transport::AsyncJsonRpcServer;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::info;

#[cfg(not(windows))]
use crate::transport::{UnixSocketListener, UnixSocketTransport};

#[cfg(not(windows))]
use tokio::net::UnixListener;

/// IPC server with actual transport support
pub struct IpcServer {
    config: ServerConfig,
    registry: Arc<MethodRegistry>,
    handle: Option<JoinHandle<()>>,
}

impl IpcServer {
    pub fn new(config: ServerConfig, registry: MethodRegistry) -> Self {
        Self {
            config,
            registry: Arc::new(registry),
            handle: None,
        }
    }

    pub async fn start(&mut self) -> IpcResult<()> {
        #[cfg(not(windows))]
        {
            self.start_unix().await
        }
        #[cfg(windows)]
        {
            self.start_named_pipe().await
        }
    }

    #[cfg(not(windows))]
    async fn start_unix(&mut self) -> IpcResult<()> {
        let socket_path = self.config.unix_socket.as_deref()
            .unwrap_or("/tmp/vnet.sock");
        
        // Remove existing socket
        let _ = std::fs::remove_file(socket_path);
        
        let listener = UnixListener::bind(socket_path)
            .map_err(|e| IpcError::Server(format!("Failed to bind Unix socket: {}", e)))?;
        
        let registry = self.registry.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let registry = registry.clone();
                        let transport = UnixSocketTransport { 
                            stream,
                            reader: TokioBufReader::new(stream.try_clone().await.unwrap()),
                        };
                        let mut server = AsyncJsonRpcServer::new(transport, (*registry).clone());
                        tokio::spawn(async move {
                            if let Err(e) = server.run().await {
                                eprintln!("JSON-RPC server error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Failed to accept connection: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        self.handle = Some(handle);
        info!("IPC server started on Unix socket: {}", socket_path);
        Ok(())
    }

    #[cfg(windows)]
    async fn start_named_pipe(&mut self) -> IpcResult<()> {
        let pipe_path = self.config.named_pipe.as_deref()
            .unwrap_or(r"\\.\pipe\vnet")
            .to_string();
        let display_path = pipe_path.clone();

        let registry = self.registry.clone();

        // First pipe instance: fail fast if another process already owns the name
        let first_server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_path)
            .map_err(|e| IpcError::Server(format!("pipe already in use: {}", e)))?;

        let handle = tokio::spawn(async move {
            // Pending server instance waiting for a client
            let mut next: Option<tokio::net::windows::named_pipe::NamedPipeServer> = Some(first_server);
            loop {
                let server = match next.take() {
                    Some(s) => s,
                    None => {
                        // Create the next instance, tolerating transient pipe busy
                        let mut created = None;
                        for _ in 0..5 {
                            match tokio::net::windows::named_pipe::ServerOptions::new().create(&pipe_path) {
                                Ok(s) => {
                                    created = Some(s);
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("Failed to create named pipe instance: {}", e);
                                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                }
                            }
                        }
                        match created {
                            Some(s) => s,
                            None => {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                continue;
                            }
                        }
                    }
                };

                match server.connect().await {
                    Ok(()) => {
                        let registry = registry.clone();
                        // Serve this connection on its own task
                        let transport = crate::transport::NamedPipeTransport::new(server);
                        let mut jrpc = AsyncJsonRpcServer::new(transport, (*registry).clone());
                        tokio::spawn(async move {
                            if let Err(e) = jrpc.run().await {
                                eprintln!("JSON-RPC server error: {}", e);
                            }
                        });
                        // Immediately prepare the next instance so other clients can connect
                        next = tokio::net::windows::named_pipe::ServerOptions::new()
                            .create(&pipe_path)
                            .ok();
                    }
                    Err(e) => {
                        eprintln!("Failed to connect named pipe: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });

        self.handle = Some(handle);
        info!("IPC server started on named pipe: {}", display_path);
        Ok(())
    }

    pub async fn stop(&mut self) -> IpcResult<()> {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        Ok(())
    }
}