//! IPC method registry with vnet-core integration

use crate::{IpcError, IpcResult};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use vnet_core::{CoreError, CoreResult, Session, SessionConfig, SessionState, SessionEvent};
use vnet_proto::message::PeerInfo;
use tokio::sync::mpsc;

/// Method errors
#[derive(Debug, thiserror::Error)]
pub enum MethodError {
    #[error("Method not found: {0}")]
    NotFound(String),
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
}

/// Method handler type - async function
type MethodHandler = Arc<dyn Fn(Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResult<Value>> + Send>> + Send + Sync>;

/// Session handle for IPC
pub struct SessionHandle {
    session: Arc<tokio::sync::Mutex<Option<Session>>>,
    event_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<SessionEvent>>>>,
}

impl SessionHandle {
    pub fn new() -> Self {
        Self {
            session: Arc::new(tokio::sync::Mutex::new(None)),
            event_rx: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub async fn create_session(&self, config: SessionConfig) -> CoreResult<()> {
        let (session, event_rx) = Session::new(config).await?;
        *self.session.lock().await = Some(session);
        *self.event_rx.lock().await = Some(event_rx);
        Ok(())
    }

    pub async fn initialize(&self) -> CoreResult<()> {
        if let Some(session) = self.session.lock().await.as_mut() {
            session.initialize().await
        } else {
            Err(CoreError::Session("No session created".into()))
        }
    }

    pub async fn connect(&self) -> CoreResult<()> {
        if let Some(session) = self.session.lock().await.as_mut() {
            session.connect().await
        } else {
            Err(CoreError::Session("No session created".into()))
        }
    }

    pub async fn disconnect(&self) -> CoreResult<()> {
        if let Some(session) = self.session.lock().await.as_mut() {
            session.disconnect().await
        } else {
            Err(CoreError::Session("No session created".into()))
        }
    }

    pub async fn add_peer(&self, peer_id: String, virtual_ip: std::net::Ipv4Addr) -> CoreResult<()> {
        if let Some(session) = self.session.lock().await.as_mut() {
            session.add_peer(peer_id, virtual_ip).await
        } else {
            Err(CoreError::Session("No session created".into()))
        }
    }

    pub async fn remove_peer(&self, peer_id: &str) -> CoreResult<()> {
        if let Some(session) = self.session.lock().await.as_mut() {
            session.remove_peer(peer_id).await
        } else {
            Err(CoreError::Session("No session created".into()))
        }
    }

    pub async fn get_state(&self) -> SessionState {
        if let Some(session) = self.session.lock().await.as_ref() {
            session.state()
        } else {
            SessionState::Disconnected
        }
    }

    pub async fn get_peer_ids(&self) -> Vec<String> {
        if let Some(session) = self.session.lock().await.as_ref() {
            session.get_peer_ids().await
        } else {
            Vec::new()
        }
    }

    pub async fn get_peer_info(&self, peer_id: &str) -> Option<vnet_proto::message::PeerInfo> {
        if let Some(session) = self.session.lock().await.as_ref() {
            session.get_peer(peer_id).await
        } else {
            None
        }
    }

    pub async fn initiate_handshake(&self, peer_id: &str, remote_addr: std::net::SocketAddr) -> CoreResult<()> {
        if let Some(session) = self.session.lock().await.as_mut() {
            session.initiate_handshake(peer_id, remote_addr).await
        } else {
            Err(CoreError::Session("No session created".into()))
        }
    }
}

/// Method registry with vnet-core integration
#[derive(Clone)]
pub struct MethodRegistry {
    methods: HashMap<String, MethodHandler>,
    session_handle: Arc<SessionHandle>,
}

impl MethodRegistry {
    pub fn new() -> Self {
        let session_handle = Arc::new(SessionHandle::new());
        let mut registry = Self {
            methods: HashMap::new(),
            session_handle,
        };
        registry.register_core_methods();
        registry
    }

    fn register_core_methods(&mut self) {
        let handle = self.session_handle.clone();

        // Create session
        self.register("session.create", {
            let handle = handle.clone();
            move |params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("default").to_string();
                    let password = params.get("password").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let virtual_ip = params.get("virtual_ip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| "10.0.0.1".parse().unwrap());
                    let stun_servers = params.get("stun_servers").and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().and_then(|s| s.parse().ok())).collect())
                        .unwrap_or_else(vnet_core::default_stun_servers);

                    let config = SessionConfig {
                        name,
                        password,
                        virtual_ip,
                        stun_servers,
                        enable_relay: false,
                        mtu: 1400,
                    };

                    let result = handle.create_session(config).await;
                    match result {
                        Ok(_) => Ok(json!({"success": true})),
                        Err(e) => Err(IpcError::Core(e)),
                    }
                })
            }
        });

        // Initialize session
        self.register("session.initialize", {
            let handle = handle.clone();
            move |_params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let result = handle.initialize().await;
                    match result {
                        Ok(_) => Ok(json!({"success": true})),
                        Err(e) => Err(IpcError::Core(e)),
                    }
                })
            }
        });

        // Connect session
        self.register("session.connect", {
            let handle = handle.clone();
            move |_params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let result = handle.connect().await;
                    match result {
                        Ok(_) => Ok(json!({"success": true})),
                        Err(e) => Err(IpcError::Core(e)),
                    }
                })
            }
        });

        // Disconnect session
        self.register("session.disconnect", {
            let handle = handle.clone();
            move |_params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let result = handle.disconnect().await;
                    match result {
                        Ok(_) => Ok(json!({"success": true})),
                        Err(e) => Err(IpcError::Core(e)),
                    }
                })
            }
        });

        // Get session state
        self.register("session.state", {
            let handle = handle.clone();
            move |_params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let state = handle.get_state().await;
                    Ok(json!({"state": format!("{:?}", state)}))
                })
            }
        });

        // Add peer
        self.register("peer.add", {
            let handle = handle.clone();
            move |params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or_else(|| IpcError::InvalidParams("peer_id required".into()))?;
                    let virtual_ip = params.get("virtual_ip").and_then(|v| v.as_str())
                        .ok_or_else(|| IpcError::InvalidParams("virtual_ip required".into()))?
                        .parse().map_err(|_| IpcError::InvalidParams("invalid virtual_ip".into()))?;
                    
                    let result = handle.add_peer(peer_id.to_string(), virtual_ip).await;
                    match result {
                        Ok(_) => Ok(json!({"success": true})),
                        Err(e) => Err(IpcError::Core(e)),
                    }
                })
            }
        });

        // Remove peer
        self.register("peer.remove", {
            let handle = handle.clone();
            move |params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or_else(|| IpcError::InvalidParams("peer_id required".into()))?;
                    
                    let result = handle.remove_peer(peer_id).await;
                    match result {
                        Ok(_) => Ok(json!({"success": true})),
                        Err(e) => Err(IpcError::Core(e)),
                    }
                })
            }
        });

        // List peers
        self.register("peer.list", {
            let handle = handle.clone();
            move |_params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let peers = handle.get_peer_ids().await;
                    let mut peer_list = Vec::new();
                    for peer_id in peers {
                        if let Some(info) = handle.get_peer_info(&peer_id).await {
                            peer_list.push(json!({
                                "peer_id": peer_id,
                                "virtual_ip": info.virtual_ip.to_string(),
                                "state": format!("{:?}", info.state),
                                "endpoint": info.endpoint.map(|e| format!("{}:{}", e.0, e.1)),
                            }));
                        }
                    }
                    Ok(json!({"peers": peer_list}))
                })
            }
        });

        // Initiate handshake with peer
        self.register("peer.handshake", {
            let handle = handle.clone();
            move |params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or_else(|| IpcError::InvalidParams("peer_id required".into()))?;
                    let remote_addr = params.get("remote_addr").and_then(|v| v.as_str())
                        .ok_or_else(|| IpcError::InvalidParams("remote_addr required".into()))?
                        .parse().map_err(|_| IpcError::InvalidParams("invalid remote_addr".into()))?;
                    
                    let result = handle.initiate_handshake(peer_id, remote_addr).await;
                    match result {
                        Ok(_) => Ok(json!({"success": true})),
                        Err(e) => Err(IpcError::Core(e)),
                    }
                })
            }
        });

        // Get peer info
        self.register("peer.info", {
            let handle = handle.clone();
            move |params| {
                let handle = handle.clone();
                Box::pin(async move {
                    let peer_id = params.get("peer_id").and_then(|v| v.as_str())
                        .ok_or_else(|| IpcError::InvalidParams("peer_id required".into()))?;
                    
                    if let Some(info) = handle.get_peer_info(peer_id).await {
                        Ok(json!({
                            "peer_id": peer_id,
                            "virtual_ip": info.virtual_ip.to_string(),
                            "state": format!("{:?}", info.state),
                            "endpoint": info.endpoint.map(|e| format!("{}:{}", e.0, e.1)),
                            "last_seen": info.last_seen,
                        }))
                    } else {
                        Err(IpcError::Core(CoreError::Peer("Peer not found".into())))
                    }
                })
            }
        });
    }

    pub fn register(&mut self, name: &str, handler: impl Fn(Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = IpcResult<Value>> + Send>> + Send + Sync + 'static) {
        self.methods.insert(name.to_string(), Arc::new(handler));
    }

    pub async fn call(&self, method: &str, params: Value) -> IpcResult<Value> {
        if let Some(handler) = self.methods.get(method) {
            handler(params).await
        } else {
            Err(crate::IpcError::Method(crate::methods::MethodError::NotFound(
                format!("Method not found: {}", method)
            )))
        }
    }
}

impl Default for MethodRegistry {
    fn default() -> Self {
        Self::new()
    }
}