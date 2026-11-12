//! Session management with real handshake and encrypted channels

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use hex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{info, warn, error, debug};

use vnet_crypto::{
    aead::AeadAlgorithm,
    keys::{ChannelKeys, IdentityKeys},
    rand::secure_random,
    ecdh::EcdhKeyPair,
};
use vnet_proto::{
    codec::{Decode, Encode, FrameCodec},
    constants::*,
    frame::{Frame, FrameHeader, FrameType, FrameFlags},
    handshake::{HandshakeContext, HandshakeError, HandshakeMessage, HandshakeState},
    message::{ControlMessage, ControlMessageType, DataMessage, Message, PeerInfo, PeerState, RouteEntry, RouteFlags},
};
use vnet_nat::{
    endpoint::Endpoint,
    ice::{IceAgent, IceCandidate, IceState},
    stun::StunClient,
    NatError,
};
use vnet_tun::{TunConfig, TunDevice, TunError, TunBuilder, TunReader, TunWriter};

use crate::{CoreError, CoreResult};

/// Session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Disconnected,
    Connecting,
    Handshaking,
    NatTraversal,
    Connected,
    Disconnecting,
    Failed(String),
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub name: String,
    pub password: Option<String>,
    pub virtual_ip: Ipv4Addr,
    pub stun_servers: Vec<SocketAddr>,
    pub enable_relay: bool,
    pub mtu: u16,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            password: None,
            virtual_ip: Ipv4Addr::new(10, 0, 0, 1),
            stun_servers: default_stun_servers(),
            enable_relay: false,
            mtu: 1400,
        }
    }
}

/// Resolve os servidores STUN padrão (hostname → SocketAddr).
///
/// `"stun.l.google.com:19302".parse::<SocketAddr>()` FALHA porque o texto é um
/// hostname, não um IP literal — por isso a resolução via `ToSocketAddrs`.
/// Se o DNS não responder, cai para uma lista de IPs públicos conhecidos.
/// (O `parse` dos literais abaixo é infalível: IPv4 numérico válido.)
pub fn default_stun_servers() -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;

    let hosts = ["stun.l.google.com", "stun1.l.google.com"];
    let mut out: Vec<SocketAddr> = Vec::new();
    for host in hosts {
        if let Ok(addrs) = (host, 19302u16).to_socket_addrs() {
            for addr in addrs {
                if !out.iter().any(|a| a.ip() == addr.ip()) {
                    out.push(addr);
                }
            }
        }
    }

    if out.is_empty() {
        out.push("74.125.250.129:19302".parse().unwrap());
        out.push("74.125.200.127:19302".parse().unwrap());
    }
    out
}

/// Per-peer handshake state
struct PeerHandshake {
    context: HandshakeContext,
    remote_addr: SocketAddr,
}

/// Encrypted channel for peer communication
pub struct EncryptedChannel {
    codec: FrameCodec,
    remote_addr: SocketAddr,
    sequence: u64,
    socket: Arc<UdpSocket>,
}

impl EncryptedChannel {
    pub fn new(
        algorithm: AeadAlgorithm,
        enc_key: &[u8],
        dec_key: &[u8],
        remote_addr: SocketAddr,
        socket: Arc<UdpSocket>,
    ) -> CoreResult<Self> {
        let enc_keys = ChannelKeys::new(algorithm, enc_key, dec_key)
            .map_err(|e| CoreError::Crypto(e))?;
        let dec_keys = ChannelKeys::new(algorithm, dec_key, enc_key)
            .map_err(|e| CoreError::Crypto(e))?;

        let codec = FrameCodec::new(enc_keys, dec_keys);

        Ok(Self {
            codec,
            remote_addr,
            sequence: 0,
            socket,
        })
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn set_sequence(&mut self, seq: u64) {
        self.sequence = seq;
    }

    /// Encrypt and send a frame
    pub async fn send_frame(&mut self, frame: &Frame) -> CoreResult<()> {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf)
            .map_err(|e| CoreError::Proto(e))?;

        self.socket.send_to(&buf, self.remote_addr).await
            .map_err(|e| CoreError::Session(e.to_string()))?;

        self.sequence += 1;
        Ok(())
    }

    /// Send a message (encrypts and frames it)
    pub async fn send_message(&mut self, msg: Message) -> CoreResult<()> {
        let frame = self.codec.encode_message(msg)
            .map_err(|e| CoreError::Proto(e))?;
        self.send_frame(&frame).await
    }

    /// Receive and decrypt a frame
    pub async fn recv_frame(&mut self, buf: &mut [u8]) -> CoreResult<Frame> {
        let (len, addr) = self.socket.recv_from(buf).await
            .map_err(|e| CoreError::Session(e.to_string()))?;

        if addr != self.remote_addr {
            return Err(CoreError::Session("Packet from unexpected address".into()));
        }

        let mut bytes = Bytes::copy_from_slice(&buf[..len]);
        let frame = Frame::decode(&mut bytes)
            .map_err(|e| CoreError::Proto(e))?;

        Ok(frame)
    }

    /// Receive and decrypt a message
    pub async fn recv_message(&mut self, buf: &mut [u8]) -> CoreResult<Message> {
        let frame = self.recv_frame(buf).await?;
        let msg = self.codec.decode_message(frame)
            .map_err(|e| CoreError::Proto(e))?;
        Ok(msg)
    }
}

/// Active peer connection
pub struct PeerConnection {
    pub peer_id: String,
    pub virtual_ip: Ipv4Addr,
    pub channel: Option<EncryptedChannel>,
    pub endpoint: Option<Endpoint>,
    pub ice_agent: Option<IceAgent>,
    pub state: PeerState,
    pub last_activity: Instant,
    pub remote_session_id: [u8; SESSION_ID_SIZE],
    pub handshake: Option<PeerHandshake>,
}

impl PeerConnection {
    pub fn new(peer_id: String, virtual_ip: Ipv4Addr, remote_session_id: [u8; SESSION_ID_SIZE]) -> Self {
        Self {
            peer_id,
            virtual_ip,
            channel: None,
            endpoint: None,
            ice_agent: None,
            state: PeerState::Handshaking,
            last_activity: Instant::now(),
            remote_session_id,
            handshake: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, PeerState::Connected)
    }

    pub fn set_handshake(&mut self, context: HandshakeContext, remote_addr: SocketAddr) {
        self.handshake = Some(PeerHandshake { context, remote_addr });
    }

    pub fn take_handshake(&mut self) -> Option<PeerHandshake> {
        self.handshake.take()
    }
}

/// Session events
#[derive(Debug, Clone)]
pub enum SessionEvent {
    PeerConnected(String, Ipv4Addr),
    PeerDisconnected(String),
    PeerError(String, String),
    StateChanged(SessionState),
    HandshakeComplete(String),
    RouteUpdate(Vec<RouteEntry>),
}

/// Main session manager
pub struct Session {
    config: SessionConfig,
    state: Arc<RwLock<SessionState>>,
    local_session_id: [u8; SESSION_ID_SIZE],
    local_identity: IdentityKeys,
    peers: Arc<RwLock<HashMap<String, PeerConnection>>>,
    tun_device: Option<Box<dyn TunDevice>>,
    tun_reader: Option<Box<dyn TunReader>>,
    tun_writer: Arc<Mutex<Option<Box<dyn TunWriter>>>>,
    udp_socket: Option<Arc<UdpSocket>>,
    nat_client: Option<StunClient>,
    ice_agent: Option<IceAgent>,
    event_tx: mpsc::Sender<SessionEvent>,
    event_rx: Arc<Mutex<mpsc::Receiver<SessionEvent>>>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Session {
    pub async fn new(config: SessionConfig) -> CoreResult<(Self, mpsc::Receiver<SessionEvent>)> {
        let local_session_id = {
            let mut id = [0u8; SESSION_ID_SIZE];
            secure_random(&mut id).map_err(|e| CoreError::Crypto(e))?;
            id
        };

        let local_identity = IdentityKeys::generate()
            .map_err(|e| CoreError::Crypto(e))?;

        let (event_tx, event_rx) = mpsc::channel(100);

        let session = Self {
            config,
            state: Arc::new(RwLock::new(SessionState::Disconnected)),
            local_session_id,
            local_identity,
            peers: Arc::new(RwLock::new(HashMap::new())),
            tun_device: None,
            tun_reader: None,
            tun_writer: Arc::new(Mutex::new(None)),
            udp_socket: None,
            nat_client: None,
            ice_agent: None,
            event_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            tasks: Arc::new(Mutex::new(Vec::new())),
        };

        Ok((session, mpsc::channel(100).1))
    }

    pub async fn initialize(&mut self) -> CoreResult<()> {
        // Initialize TUN device
        self.init_tun().await?;

        // Initialize UDP socket
        self.init_udp().await?;

        // Initialize NAT traversal
        self.init_nat().await?;

        Ok(())
    }

    async fn init_tun(&mut self) -> CoreResult<()> {
        let device = TunBuilder::new()
            .name(format!("vnet-{}", &self.config.name))
            .mtu(self.config.mtu)
            .address(IpAddr::V4(self.config.virtual_ip))
            .netmask(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)))
            .up(true)
            .build()
            .await;

        match device {
            Ok(device) => {
                let (tun_rx, tun_tx) = device.split();
                self.tun_reader = Some(tun_rx);
                *self.tun_writer.lock().await = Some(tun_tx);
            }
            Err(e) => {
                // Sem privilégios de admin o driver TUN não abre. A sessão
                // continua em modo userspace (controle/keepalive/STUN), só
                // não há roteamento de pacotes IP pela interface virtual.
                warn!(
                    "TUN indisponível ({e}); seguindo em modo userspace. \
                     Para rotear tráfego, execute o app como administrador."
                );
            }
        }
        Ok(())
    }

    async fn init_udp(&mut self) -> CoreResult<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| CoreError::Session(e.to_string()))?;

        let local_addr = socket.local_addr()
            .map_err(|e| CoreError::Session(e.to_string()))?;

        info!("UDP socket bound to {}", local_addr);

        self.udp_socket = Some(Arc::new(socket));
        Ok(())
    }

    async fn init_nat(&mut self) -> CoreResult<()> {
        if let Some(ref socket) = self.udp_socket {
            let bind_addr = socket.local_addr().unwrap();
            
            // Gather host candidates (local interfaces)
            let mut ice_agent = IceAgent::new(true);
            
            // Add local host candidate
            let host_candidate = IceCandidate {
                foundation: "1".to_string(),
                component_id: 1,
                transport: "udp".to_string(),
                priority: 2130706431, // (1 << 24) | (1 << 8) | 255 - highest priority for host
                address: bind_addr.ip(),
                port: bind_addr.port(),
                candidate_type: vnet_nat::ice::CandidateType::Host,
                related_address: None,
                related_port: None,
                tcp_type: None,
            };
            ice_agent.add_local_candidate(host_candidate);
            
            // STUN discovery for server reflexive candidate
            if let Some(stun_server) = self.config.stun_servers.first() {
                match StunClient::new(*stun_server, Some(bind_addr)).await {
                    Ok(stun_client) => {
                        if let Ok(Ok(endpoint)) =
                            timeout(Duration::from_secs(5), stun_client.binding_request()).await
                        {
                            info!("Discovered public endpoint: {}", endpoint);

                            // Add server reflexive candidate
                            let srflx_candidate = IceCandidate {
                                foundation: "2".to_string(),
                                component_id: 1,
                                transport: "udp".to_string(),
                                priority: 1694498815, // (1 << 24) | (1 << 8) | 100 - lower than host
                                address: endpoint.ip(),
                                port: endpoint.port(),
                                candidate_type: vnet_nat::ice::CandidateType::ServerReflexive,
                                related_address: Some(bind_addr.ip()),
                                related_port: Some(bind_addr.port()),
                                tcp_type: None,
                            };
                            ice_agent.add_local_candidate(srflx_candidate);
                        } else {
                            warn!("STUN discovery failed or timed out");
                        }

                        self.nat_client = Some(stun_client);
                    }
                    Err(e) => {
                        // Sem STUN não há candidato srflx, mas host candidates
                        // ainda permitem conexão em LAN. Não aborta a sessão.
                        warn!("STUN indisponível ({e}); seguindo só com host candidates");
                    }
                }
            }

            self.ice_agent = Some(ice_agent);
        }
        Ok(())
    }

    pub async fn connect(&mut self) -> CoreResult<()> {
        *self.state.write().await = SessionState::Connecting;
        self.emit_event(SessionEvent::StateChanged(SessionState::Connecting));

        // Start TUN read loop
        self.start_tun_loop().await?;

        // Start UDP receive loop
        self.start_udp_loop().await?;

        // Start keepalive
        self.start_keepalive().await?;

        // Start ICE candidate gathering
        self.start_ice_loop().await?;

        *self.state.write().await = SessionState::Connected;
        self.emit_event(SessionEvent::StateChanged(SessionState::Connected));

        info!("Session initialized successfully");
        Ok(())
    }

    /// Initiate handshake to a specific peer
    pub async fn initiate_handshake(&mut self, peer_id: &str, remote_addr: SocketAddr) -> CoreResult<()> {
        let mut peers = self.peers.write().await;
        let peer = peers.get_mut(peer_id).ok_or_else(|| CoreError::Session("Peer not found".into()))?;

        if peer.channel.is_some() {
            return Ok(()); // Already connected
        }

        let static_key = self.local_identity.signing_key().ok();
        let mut handshake = HandshakeContext::new_client(self.local_session_id, static_key);

        // Get local ICE candidates
        let ice_candidates = if let Some(ref ice_agent) = self.ice_agent {
            ice_agent.local_candidates().to_vec()
        } else {
            Vec::new()
        };

        // Build and send ClientHello with ICE candidates
        let client_hello = handshake.build_client_hello_with_candidates(ice_candidates)?;
        
        let frame = handshake_message_to_frame(&client_hello, self.local_session_id, 0)?;
        if let Some(socket) = &self.udp_socket {
            let mut buf = BytesMut::new();
            frame.encode(&mut buf).map_err(|e| CoreError::Proto(e))?;
            socket.send_to(&buf, remote_addr).await
                .map_err(|e| CoreError::Session(e.to_string()))?;
        }

        // Store handshake state
        peer.set_handshake(handshake, remote_addr);
        peer.endpoint = Some(Endpoint::udp(remote_addr));
        peer.state = PeerState::Handshaking;

        info!("Initiated handshake with {} at {}", peer_id, remote_addr);
        Ok(())
    }

    async fn start_tun_loop(&mut self) -> CoreResult<()> {
        // Em modo userspace (TUN indisponível, ex. sem admin) não existe leitor
        // para bombear — a sessão segue viva só com controle/keepalive/STUN.
        let Some(tun_rx) = self.tun_reader.take() else {
            warn!("TUN loop ignorado: nenhum leitor TUN (modo userspace)");
            return Ok(());
        };

        let peers = self.peers.clone();
        let local_session_id = self.local_session_id;
        let udp_socket = self.udp_socket.clone();

        let tun_rx_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut rx = tun_rx;
            loop {
                let n = match rx.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                };

                if n == 0 {
                    break;
                }

                if let Some(frame) = parse_ethernet_frame(&buf[..n]) {
                    if let Some((peer_id, _dst_ip)) = route_frame(&frame, &peers).await {
                        if let Some(mut peer) = peers.write().await.get_mut(&peer_id) {
                            if let Some(channel) = peer.channel.as_mut() {
                                let mut out_frame = data_frame(local_session_id, channel.sequence(), &buf[..n]);
                                if let Err(e) = channel.send_frame(&out_frame).await {
                                    error!("Failed to send frame to {}: {}", peer_id, e);
                                } else {
                                    peer.last_activity = Instant::now();
                                }
                            }
                        }
                    }
                }
            }
        });

        self.tasks.lock().await.push(tun_rx_task);
        Ok(())
    }

    async fn start_udp_loop(&mut self) -> CoreResult<()> {
        let Some(socket) = self.udp_socket.clone() else {
            warn!("UDP loop ignorado: socket não inicializado");
            return Ok(());
        };
        let peers = self.peers.clone();
        let local_session_id = self.local_session_id;
        let event_tx = self.event_tx.clone();
        let tun_writer = self.tun_writer.clone();
        let udp_socket = self.udp_socket.clone();

        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let tun_writer = tun_writer.clone();
                let udp_socket = udp_socket.clone();
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let frame_result = Frame::decode(&mut Bytes::copy_from_slice(&buf[..len]));
                        match frame_result {
                            Ok(frame) => {
                                if let Err(e) = handle_incoming_frame(
                                    frame, addr, &peers, &local_session_id, &event_tx, tun_writer, udp_socket
                                ).await {
                                    warn!("Frame handling error: {}", e);
                                }
                            }
                            Err(e) => {
                                debug!("Failed to decode frame from {}: {}", addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });

        self.tasks.lock().await.push(udp_task);
        Ok(())
    }

    async fn start_keepalive(&mut self) -> CoreResult<()> {
        let peers = self.peers.clone();
        let local_session_id = self.local_session_id;
        let event_tx = self.event_tx.clone();

        let keepalive_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(KEEPALIVE_INTERVAL_MS));
            loop {
                interval.tick().await;

                let mut peers_guard = peers.write().await;
                for (peer_id, peer) in peers_guard.iter_mut() {
                    if peer.is_connected() {
                        if let Some(channel) = peer.channel.as_mut() {
                            let frame = make_control_frame(local_session_id, channel.sequence(), ControlMessage::Ping { timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() });
                            if let Err(e) = channel.send_frame(&frame).await {
                                warn!("Keepalive failed for {}: {}", peer_id, e);
                                peer.state = PeerState::Disconnected;
                                let _ = event_tx.send(SessionEvent::PeerDisconnected(peer_id.clone())).await;
                            } else {
                                peer.last_activity = Instant::now();
                            }
                        }
                    }
                }
            }
        });

        self.tasks.lock().await.push(keepalive_task);
        Ok(())
    }

    async fn start_ice_loop(&mut self) -> CoreResult<()> {
        let mut ice_agent = self.ice_agent.take();
        let peers = self.peers.clone();
        let socket = self.udp_socket.clone();

        if let Some(mut ice) = ice_agent.take() {
            let ice_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;

                    // Process ICE state changes
                    let _ = ice.start_connectivity_checks().await;

                    // Check for new candidates and send to peers
                    if let Some(_socket) = &socket {
                        // In a real implementation, we'd send candidates via signaling
                        // For now, just process ICE state
                    }
                }
            });
            self.tasks.lock().await.push(ice_task);
        }

        self.ice_agent = ice_agent;
        Ok(())
    }

    pub async fn disconnect(&mut self) -> CoreResult<()> {
        *self.state.write().await = SessionState::Disconnecting;
        self.emit_event(SessionEvent::StateChanged(SessionState::Disconnecting));

        let mut peers = self.peers.write().await;
        for (_peer_id, peer) in peers.iter_mut() {
            if let Some(channel) = peer.channel.as_mut() {
                let frame = make_control_frame(self.local_session_id, channel.sequence(), ControlMessage::Close { reason: "Session closing".into() });
                let _ = channel.send_frame(&frame).await;
            }
        }

        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        *self.state.write().await = SessionState::Disconnected;
        self.emit_event(SessionEvent::StateChanged(SessionState::Disconnected));

        Ok(())
    }

    pub fn state(&self) -> SessionState {
        futures::executor::block_on(async {
            self.state.read().await.clone()
        })
    }

    pub async fn add_peer(&mut self, peer_id: String, virtual_ip: Ipv4Addr) -> CoreResult<()> {
        let mut peers = self.peers.write().await;
        if !peers.contains_key(&peer_id) {
            let remote_session_id = [0u8; SESSION_ID_SIZE];
            let mut peer = PeerConnection::new(peer_id.clone(), virtual_ip, remote_session_id);
            peer.state = PeerState::Handshaking;
            peers.insert(peer_id.clone(), peer);
            info!("Added peer: {} ({})", peer_id, virtual_ip);
        }
        Ok(())
    }

    pub async fn remove_peer(&mut self, peer_id: &str) -> CoreResult<()> {
        let mut peers = self.peers.write().await;
        if peers.remove(peer_id).is_some() {
            info!("Removed peer: {}", peer_id);
            self.emit_event(SessionEvent::PeerDisconnected(peer_id.to_string()));
        }
        Ok(())
    }

    pub async fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(peer_id).map(|p| PeerInfo {
            session_id: p.remote_session_id,
            static_public: vec![],
            virtual_ip: IpAddr::V4(p.virtual_ip),
            endpoint: p.endpoint.as_ref().map(|e| (e.addr.ip(), e.addr.port())),
            aead_algorithms: 0x03,
            last_seen: p.last_activity.elapsed().as_secs(),
            state: p.state,
            mtu: self.config.mtu,
        })
    }

    pub async fn get_peer_ids(&self) -> Vec<String> {
        let peers = self.peers.read().await;
        peers.keys().cloned().collect()
    }

    fn emit_event(&self, event: SessionEvent) {
        let _ = self.event_tx.try_send(event);
    }

    pub async fn next_event(&self) -> Option<SessionEvent> {
        self.event_rx.lock().await.recv().await
    }
}

/// Convert handshake message to frame
fn handshake_message_to_frame(msg: &HandshakeMessage, session_id: [u8; SESSION_ID_SIZE], sequence: u64) -> CoreResult<Frame> {
    let payload = msg.encode().map_err(|e| CoreError::Proto(e))?;
    let mut frame = Frame::new(
        FrameHeader {
            magic: MAGIC,
            version: VERSION,
            flags: FrameFlags::NONE,
            frame_type: msg.frame_type(),
            sequence,
            session_id,
            payload_len: payload.len() as u16,
            reserved: [0; 6],
        },
        payload,
        [0u8; TAG_SIZE],
    );
    Ok(frame)
}

/// Create a data frame
fn data_frame(session_id: [u8; SESSION_ID_SIZE], sequence: u64, payload: &[u8]) -> Frame {
    Frame::new(
        FrameHeader {
            magic: MAGIC,
            version: VERSION,
            flags: FrameFlags::NONE,
            frame_type: FrameType::Data,
            sequence,
            session_id,
            payload_len: payload.len() as u16,
            reserved: [0; 6],
        },
        Bytes::copy_from_slice(payload),
        [0u8; TAG_SIZE],
    )
}

/// Create a control frame
fn make_control_frame(session_id: [u8; SESSION_ID_SIZE], sequence: u64, msg: ControlMessage) -> Frame {
    let payload = msg.encode().unwrap();
    Frame::new(
        FrameHeader {
            magic: MAGIC,
            version: VERSION,
            flags: FrameFlags::NONE,
            frame_type: FrameType::Control,
            sequence,
            session_id,
            payload_len: payload.len() as u16,
            reserved: [0; 6],
        },
        payload,
        [0u8; TAG_SIZE],
    )
}

/// Parse Ethernet frame to extract IP addresses
fn parse_ethernet_frame(data: &[u8]) -> Option<ParsedFrame> {
    if data.len() < 14 {
        return None;
    }

    let _dst_mac = &data[0..6];
    let _src_mac = &data[6..12];
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0800 => Some(ParsedFrame::Ipv4 { payload: &data[14..] }),
        0x86DD => Some(ParsedFrame::Ipv6 { payload: &data[14..] }),
        0x0806 => Some(ParsedFrame::Arp { payload: &data[14..] }),
        _ => None,
    }
}

enum ParsedFrame<'a> {
    Ipv4 { payload: &'a [u8] },
    Ipv6 { payload: &'a [u8] },
    Arp { payload: &'a [u8] },
}

/// Route frame to appropriate peer based on destination IP
async fn route_frame(
    frame: &ParsedFrame<'_>,
    peers: &Arc<RwLock<HashMap<String, PeerConnection>>>,
) -> Option<(String, Ipv4Addr)> {
    let dst_ip = match frame {
        ParsedFrame::Ipv4 { payload } => {
            if payload.len() < 20 {
                return None;
            }
            let dst_octets = &payload[16..20];
            Ipv4Addr::new(dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3])
        }
        _ => return None,
    };

    let peers_guard = peers.read().await;
    for (peer_id, peer) in peers_guard.iter() {
        if peer.virtual_ip == dst_ip && peer.is_connected() {
            return Some((peer_id.clone(), dst_ip));
        }
    }
    None
}

/// Handle incoming UDP frame
async fn handle_incoming_frame(
    frame: Frame,
    src_addr: SocketAddr,
    peers: &Arc<RwLock<HashMap<String, PeerConnection>>>,
    local_session_id: &[u8; SESSION_ID_SIZE],
    event_tx: &mpsc::Sender<SessionEvent>,
    tun_writer: Arc<Mutex<Option<Box<dyn TunWriter>>>>,
    udp_socket: Option<Arc<UdpSocket>>,
) -> CoreResult<()> {
    // Check session ID
    if frame.header.session_id != *local_session_id {
        return Ok(()); // Not for us
    }

    // Handle handshake frames
    if frame.header.frame_type.is_handshake() {
        return handle_handshake_frame(frame, src_addr, peers, local_session_id, event_tx, udp_socket).await;
    }

    // Find peer by source address or session ID
    let mut peers_guard = peers.write().await;
    let peer_entry = peers_guard.iter_mut().find(|(_, p)| {
        p.endpoint.as_ref().map(|e| e.addr) == Some(src_addr)
            || p.remote_session_id == frame.header.session_id
    });

    let Some((peer_id, peer)) = peer_entry else {
        debug!("No peer found for frame from {}", src_addr);
        return Ok(());
    };

    // Update endpoint if not set
    if peer.endpoint.is_none() {
        peer.endpoint = Some(Endpoint::udp(src_addr));
    }

    // Handle control messages
    if frame.header.frame_type == FrameType::Control {
        if let Ok(msg) = ControlMessage::decode(&mut frame.payload.clone()) {
            match msg {
                ControlMessage::Ping { timestamp } => {
                    if let Some(channel) = peer.channel.as_mut() {
                        let ack = make_control_frame(*local_session_id, channel.sequence(), ControlMessage::Pong { timestamp });
                        let _ = channel.send_frame(&ack).await;
                    }
                }
                ControlMessage::Pong { timestamp: _ } => {
                    peer.last_activity = Instant::now();
                }
                ControlMessage::Close { reason: _ } => {
                    peer.state = PeerState::Disconnected;
                }
                _ => {}
            }
        }
    }

    // Handle data frames - decrypt and forward to TUN
    if frame.header.frame_type == FrameType::Data {
        if let Some(channel) = peer.channel.as_mut() {
            // Use FrameCodec to decrypt
            let decrypted_frame = channel.codec.decrypt(frame)
                .map_err(|e| CoreError::Proto(e))?;
            
            // Forward to TUN
            if let Ok(mut writer_guard) = tun_writer.try_lock() {
                if let Some(writer) = writer_guard.as_mut() {
                    writer.write_all(&decrypted_frame.payload).await
                        .map_err(|e| CoreError::Tun(TunError::Io(e)))?;
                    debug!("Forwarded {} bytes to TUN for peer {}", decrypted_frame.payload.len(), peer_id);
                }
            }
        }
    }

    Ok(())
}

/// Handle handshake frames
async fn handle_handshake_frame(
    frame: Frame,
    src_addr: SocketAddr,
    peers: &Arc<RwLock<HashMap<String, PeerConnection>>>,
    local_session_id: &[u8; SESSION_ID_SIZE],
    event_tx: &mpsc::Sender<SessionEvent>,
    udp_socket: Option<Arc<UdpSocket>>,
) -> CoreResult<()> {
    // Decode handshake message
    let msg = HandshakeMessage::decode(&mut frame.payload.clone())
        .map_err(|e| CoreError::Proto(e))?;

    let mut peers_guard = peers.write().await;
    
    // Find or create peer for this address
    let peer_id = format!("{}:{}", src_addr.ip(), src_addr.port());
    let peer = peers_guard.entry(peer_id.clone()).or_insert_with(|| {
        PeerConnection::new(peer_id.clone(), Ipv4Addr::UNSPECIFIED, frame.header.session_id)
    });

    // Update endpoint
    peer.endpoint = Some(Endpoint::udp(src_addr));
    peer.remote_session_id = frame.header.session_id;

    match msg {
        HandshakeMessage::ServerHello { ecdh_public, aead_algorithm, session_id, version, nonce, cookie, ice_candidates: _ } => {
            debug!("Received ServerHello from {}", src_addr);
            
            // Process ServerHello using stored handshake context
            if let Some(mut handshake) = peer.take_handshake() {
                // Process through state machine
                let server_hello_msg = HandshakeMessage::ServerHello {
                    ecdh_public: ecdh_public.clone(),
                    aead_algorithm,
                    session_id: session_id.clone(),
                    version,
                    nonce,
                    cookie: cookie.clone(),
                    ice_candidates: Vec::new(),
                };
                
                match handshake.context.process_message(server_hello_msg) {
                    Ok(Some(client_auth)) => {
                        // Send ClientAuth
                        let auth_frame = handshake_message_to_frame(&client_auth, *local_session_id, handshake.context.next_sequence())?;
                        // Need to send via UDP socket - will be handled by session
                        // Store for sending
                        debug!("Built ClientAuth, need to send to {}", src_addr);
                        
                        // Store updated handshake
                        peer.set_handshake(handshake.context, src_addr);
                        peer.state = PeerState::Handshaking;
                    }
                    Ok(None) => {
                        peer.set_handshake(handshake.context, src_addr);
                    }
                    Err(e) => {
                        error!("Handshake error processing ServerHello: {}", e);
                        peer.state = PeerState::Disconnected;
                    }
                }
            } else {
                debug!("No handshake context for ServerHello from {}", src_addr);
            }
        }
        HandshakeMessage::Confirm { confirm_tag } => {
            debug!("Received Confirm from {}", src_addr);
            
            // Process Confirm using stored handshake context
            if let Some(mut handshake) = peer.take_handshake() {
                let confirm_msg = HandshakeMessage::Confirm { confirm_tag: confirm_tag.clone() };
                
                match handshake.context.process_message(confirm_msg) {
                    Ok(_) => {
                        // Handshake complete - derive keys and create encrypted channel
                        if let Some(keys) = handshake.context.session_keys() {
                            let algorithm = handshake.context.aead_algorithm();
                            let (enc_key, dec_key) = if handshake.context.state().is_client() {
                                (keys.client_enc_key, keys.server_enc_key)
                            } else {
                                (keys.server_enc_key, keys.client_enc_key)
                            };
                            
                            // Convert proto AeadAlgorithm to crypto AeadAlgorithm
                            let crypto_algorithm = match algorithm {
                                vnet_proto::frame::AeadAlgorithm::Aes256Gcm => vnet_crypto::aead::AeadAlgorithm::Aes256Gcm,
                                vnet_proto::frame::AeadAlgorithm::ChaCha20Poly1305 => vnet_crypto::aead::AeadAlgorithm::ChaCha20Poly1305,
                            };
                            
                            debug!("Handshake complete with {}, creating encrypted channel", src_addr);
                            
                            // Create encrypted channel with derived keys
                            if let Some(socket) = &udp_socket {
                                let channel = EncryptedChannel::new(crypto_algorithm, &enc_key, &dec_key, src_addr, socket.clone())?;
                                peer.channel = Some(channel);
                            }
                            
                            // Now we can modify peer state
                            peer.state = PeerState::Connected;
                            
                            // Emit events
                            let _ = event_tx.send(SessionEvent::HandshakeComplete(hex::encode(*local_session_id))).await;
                            let _ = event_tx.send(SessionEvent::PeerConnected(peer_id.clone(), peer.virtual_ip)).await;
                        }
                    }
                    Err(e) => {
                        error!("Handshake error processing Confirm: {}", e);
                        peer.state = PeerState::Disconnected;
                    }
                }
            } else {
                debug!("No handshake context for Confirm from {}", src_addr);
            }
        }
        HandshakeMessage::Error { code, message } => {
            error!("Handshake error from {}: {} - {}", src_addr, code, message);
            peer.state = PeerState::Disconnected;
        }
        _ => {
            debug!("Unexpected handshake message {:?} from {}", msg.frame_type(), src_addr);
        }
    }

    Ok(())
}

/// FrameType extension for handshake check
trait FrameTypeExt {
    fn is_handshake(&self) -> bool;
}

impl FrameTypeExt for FrameType {
    fn is_handshake(&self) -> bool {
        matches!(self, FrameType::Handshake | FrameType::HandshakeResponse | FrameType::HandshakeConfirm)
    }
}