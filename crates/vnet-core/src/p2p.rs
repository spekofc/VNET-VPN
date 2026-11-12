//! VNET mesh core (v3): rede sem dono, definida por nome + senha.
//!
//! Modelo:
//!   * a rede **é** o par `nome + senha` — não existe servidor nem "dono";
//!   * cada PC tem um id persistente (`%LOCALAPPDATA%\vnet\node_id`) e deriva
//!     dele o próprio IP virtual `10.144.0.X`, então o IP não muda entre sessões;
//!   * quem já conhece um membro (código `IP:PORTA`) troca HELLO e recebe a
//!     lista dos outros membros por gossip, conectando-se direto a eles;
//!   * todo membro pode gerar código de convite (UPnP/STUN best-effort);
//!   * pacotes cujo destino não é um vizinho direto são repassados (relay),
//!     com deduplicação por `(origem, seq)` — a malha fecha mesmo sem todos os
//!     pares se alcançarem.
//!
//! A sala é identificada por `SHA-256("vnet-room-hash" || nome || 0 || senha)`.
//! Quem não souber a senha não deriva a chave nem acerta o *room hash*, então
//! nem handshake nem dados atravessam.

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

const MAGIC: &[u8; 4] = b"VNP2";
const T_HELLO: u8 = 1;
const T_DATA: u8 = 3;
const T_PING: u8 = 4;
const T_PONG: u8 = 5;
const T_BYE: u8 = 6;
const T_PEERS: u8 = 7;

const HELLO_EVERY: Duration = Duration::from_millis(400);
const HELLO_TIMEOUT: Duration = Duration::from_secs(20);
const PEER_TIMEOUT: Duration = Duration::from_secs(20);
const PING_EVERY: Duration = Duration::from_secs(3);
const GOSSIP_EVERY: Duration = Duration::from_secs(2);
/// Varredura de LAN: enquanto sozinho, procura a mesma rede na rede local.
const LAN_SWEEP_EVERY: Duration = Duration::from_secs(3);
/// Intervalo mínimo entre tentativas de HELLO a um membro aprendido por gossip.
const RETRY_EVERY: Duration = Duration::from_secs(8);
const TICK: Duration = Duration::from_millis(250);
const SEEN_CAP: usize = 8192;

/// Faixa da rede virtual: `10.144.0.0/24`.
///
/// Fora de `26.0.0.0/8`, `25.0.0.0/8` (outras VPNs de malha),
/// `100.64.0.0/10` (CGNAT) e das faixas domésticas comuns.
pub const VIRTUAL_PREFIX: Ipv4Addr = Ipv4Addr::new(10, 144, 0, 0);
/// Broadcast da faixa virtual.
pub const VIRTUAL_BROADCAST: Ipv4Addr = Ipv4Addr::new(10, 144, 0, 255);
const VNET_OCTETS: [u8; 3] = [10, 144, 0];
const VNET_PORT_RANGE: std::ops::RangeInclusive<u16> = 7000..=7100;

// ---------------------------------------------------------------------------
// Tipos públicos
// ---------------------------------------------------------------------------

/// Como a sessão começa.
///
/// `Host` abre a rede sem seed (fica em `Waiting` até alguém entrar);
/// `Join` começa sabendo o endpoint de um membro. Depois do primeiro HELLO os
/// dois lados são idênticos — não existe papel de servidor.
#[derive(Clone, Debug)]
pub enum Role {
    /// Abre a rede sem nenhum contato inicial.
    Host,
    /// Entra sabendo o `IP:PORTA` de um membro.
    Join { host: SocketAddr },
}

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub room: String,
    pub password: String,
    pub role: Role,
    pub mtu: u16,
    /// Id fixo do nó (testes). `None` = id persistente da máquina.
    pub node_id: Option<[u8; 8]>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct PeerInfo {
    pub id: String,
    pub ip: String,
    pub endpoint: String,
    pub rtt_ms: Option<u16>,
    /// Sempre `false` na malha (mantido por compatibilidade do JSON).
    pub is_host: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Snapshot {
    /// Disconnected | Connecting | Waiting | Connected | Failed
    pub state: String,
    pub virtual_ip: Option<String>,
    /// Código para convidar (qualquer membro gera o seu).
    pub code: Option<String>,
    /// Endpoint público visto pelo STUN (pode não estar acessível sem UPnP).
    pub public_endpoint: Option<String>,
    /// Endpoint na rede local (funciona sem roteador).
    pub local_endpoint: Option<String>,
    /// UPnP mapeou a porta no roteador?
    pub mapped: bool,
    /// Adaptador virtual (Wintun) ativo? Sem ele o jogo não vê a rede.
    pub tun_ready: bool,
    pub peers: Vec<PeerInfo>,
    pub error: Option<String>,
    /// Nome da rede atual.
    pub room: Option<String>,
    /// `mesh` — não há host.
    pub role: String,
}

#[derive(Clone, Debug)]
pub enum Event {
    Snapshot(Snapshot),
    Log(String),
}

#[derive(Debug)]
enum Cmd {
    Ping(String),
    Inject(Vec<u8>),
    Disconnect,
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

fn room_key(room: &str, password: &str) -> ([u8; 32], [u8; 16]) {
    let mut h = Sha256::new();
    h.update(b"vnet-room-ikm");
    h.update(room.as_bytes());
    h.update([0u8]);
    h.update(password.as_bytes());
    let ikm = h.finalize();

    let mut rh = Sha256::new();
    rh.update(b"vnet-room-hash");
    rh.update(room.as_bytes());
    rh.update([0u8]);
    rh.update(password.as_bytes());
    let rh_full = rh.finalize();

    let mut room_hash = [0u8; 16];
    room_hash.copy_from_slice(&rh_full[..16]);

    let hk = Hkdf::<Sha256>::new(Some(&room_hash), &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"vnet-p2p-data-v2", &mut key)
        .expect("hkdf 32 bytes");
    (key, room_hash)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Id persistente da máquina — define o IP virtual e sobrevive a reinícios.
fn node_id() -> [u8; 8] {
    if let Ok(text) = std::env::var("VNET_NODE_ID") {
        if let Some(id) = parse_peer_id(text.trim()) {
            return id;
        }
    }
    let Some(path) = node_id_path() else {
        return random_bytes();
    };
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Some(id) = parse_peer_id(text.trim()) {
            return id;
        }
    }
    let id: [u8; 8] = random_bytes();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&path, hex8(id));
    id
}

fn node_id_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    let mut p = PathBuf::from(base);
    p.push("vnet");
    Some(p.join("node_id"))
}

/// IP virtual determinístico a partir do id: `10.144.0.2` .. `10.144.0.254`.
pub fn derive_ip(id: [u8; 8]) -> Ipv4Addr {
    let mut h = Sha256::new();
    h.update(b"vnet-node-ip");
    h.update(id);
    let d = h.finalize();
    let n = 2 + (u16::from_be_bytes([d[0], d[1]]) % 253) as u8;
    Ipv4Addr::new(VNET_OCTETS[0], VNET_OCTETS[1], VNET_OCTETS[2], n)
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

fn frame(typ: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload.len());
    v.extend_from_slice(MAGIC);
    v.push(typ);
    v.extend_from_slice(payload);
    v
}

fn unframe(buf: &[u8]) -> Option<(u8, &[u8])> {
    if buf.len() < 5 || &buf[..4] != MAGIC {
        return None;
    }
    Some((buf[4], &buf[5..]))
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

pub struct Tunnel {
    cmd_tx: UnboundedSender<Cmd>,
    evt_rx: tokio::sync::Mutex<UnboundedReceiver<Event>>,
    snap: Arc<Mutex<Snapshot>>,
    capture: Arc<Mutex<Option<UnboundedSender<Vec<u8>>>>>,
}

impl Tunnel {
    pub fn start(cfg: P2pConfig) -> Result<Tunnel> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();
        let snap = Arc::new(Mutex::new(Snapshot {
            state: "Connecting".into(),
            role: "mesh".into(),
            ..Default::default()
        }));

        let snap_task = snap.clone();
        let capture = Arc::new(Mutex::new(None));
        let capture_task = capture.clone();
        tokio::spawn(async move {
            if let Err(e) = Core::run(cfg, cmd_rx, evt_tx.clone(), snap_task.clone(), capture_task).await {
                let mut s = snap_task.lock().unwrap();
                s.state = "Failed".into();
                s.error = Some(format!("{e:#}"));
                let snapshot = s.clone();
                drop(s);
                let _ = evt_tx.send(Event::Snapshot(snapshot));
            }
        });

        Ok(Tunnel {
            cmd_tx,
            evt_rx: tokio::sync::Mutex::new(evt_rx),
            snap,
            capture,
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snap.lock().unwrap().clone()
    }

    pub async fn next_event(&self) -> Option<Event> {
        self.evt_rx.lock().await.recv().await
    }

    pub fn ping(&self, peer_id: &str) {
        let _ = self.cmd_tx.send(Cmd::Ping(peer_id.to_string()));
    }

    /// Injeta um pacote IP como se tivesse vindo da interface TUN.
    /// Usado em testes e em diagnósticos sem adaptador.
    pub fn inject_packet(&self, packet: Vec<u8>) {
        let _ = self.cmd_tx.send(Cmd::Inject(packet));
    }

    /// Recebe os pacotes IP decifrados em vez de entregá-los ao TUN.
    /// Serve para verificar o caminho de dados sem privilégios de administrador.
    pub fn capture_decrypted(&self, tx: UnboundedSender<Vec<u8>>) {
        *self.capture.lock().unwrap() = Some(tx);
    }

    pub fn disconnect(&self) {
        let _ = self.cmd_tx.send(Cmd::Disconnect);
    }
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

enum Ev {
    Udp(Vec<u8>, SocketAddr),
    Tun(Vec<u8>),
    Tick,
    Cmd(Cmd),
    /// Resultado do mapeamento UPnP (roda em paralelo ao loop).
    Mapped(bool),
}

struct Peer {
    id: [u8; 8],
    ip: Ipv4Addr,
    addr: SocketAddr,
    last_seen: Instant,
    rtt_ms: Option<u16>,
    ping_at: Option<Instant>,
}

struct Core {
    cfg: P2pConfig,
    sock: Arc<UdpSocket>,
    key: [u8; 32],
    room_hash: [u8; 16],
    my_id: [u8; 8],
    my_ip: Ipv4Addr,
    /// IP da interface principal (Wi-Fi/cabo) — usado para filtrar peers.
    local_ip: Option<Ipv4Addr>,
    /// Endpoint conhecido de um membro (só quem entra tem).
    seed: Option<SocketAddr>,
    code: Option<String>,
    public_ep: Option<String>,
    local_ep: Option<String>,
    mapped: bool,
    failed: bool,
    peers: HashMap<[u8; 8], Peer>,
    /// Última tentativa de HELLO a um membro aprendido por gossip.
    hello_tried: HashMap<[u8; 8], Instant>,
    /// Dedup de relay: (origem, seq) já vistos.
    seen: VecDeque<([u8; 8], u64)>,
    seen_set: HashSet<([u8; 8], u64)>,
    tun: Option<Arc<super::tun_win::TunHandle>>,
    seq: u64,
    snap: Arc<Mutex<Snapshot>>,
    evt_tx: UnboundedSender<Event>,
    ev: UnboundedSender<Ev>,
    capture: Arc<Mutex<Option<UnboundedSender<Vec<u8>>>>>,
}

impl Core {
    async fn run(
        cfg: P2pConfig,
        mut cmd_rx: UnboundedReceiver<Cmd>,
        evt_tx: UnboundedSender<Event>,
        snap: Arc<Mutex<Snapshot>>,
        capture: Arc<Mutex<Option<UnboundedSender<Vec<u8>>>>>,
    ) -> Result<()> {
        let seed = match &cfg.role {
            Role::Join { host } => Some(*host),
            Role::Host => None,
        };

        // ---- socket: todo mundo tenta a mesma faixa, para o código ser estável
        let mut sock = None;
        for port in VNET_PORT_RANGE {
            if let Ok(std_sock) = std::net::UdpSocket::bind(("0.0.0.0", port)) {
                // Necessário para a varredura de LAN (HELLO em broadcast).
                let _ = std_sock.set_broadcast(true);
                let _ = std_sock.set_nonblocking(true);
                if let Ok(s) = UdpSocket::from_std(std_sock) {
                    sock = Some(s);
                    break;
                }
            }
        }
        let sock = match sock {
            Some(s) => s,
            None => {
                let std_sock = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
                let _ = std_sock.set_broadcast(true);
                let _ = std_sock.set_nonblocking(true);
                UdpSocket::from_std(std_sock)?
            }
        };
        let sock = Arc::new(sock);
        let local_port = sock.local_addr()?.port();

        // Libera as portas do túnel (best-effort; só funciona elevado).
        super::tun_win::ensure_firewall_rules();

        let (key, room_hash) = room_key(&cfg.room, &cfg.password);
        let my_id = cfg.node_id.unwrap_or_else(node_id);
        let my_ip = derive_ip(my_id);

        // Avisa a UI já (sem esperar UPnP/STUN) que a malha está subindo.
        {
            let mut s = snap.lock().unwrap();
            s.state = "Connecting".into();
            s.virtual_ip = Some(my_ip.to_string());
            s.room = Some(cfg.room.clone());
            s.role = "mesh".into();
            let copy = s.clone();
            drop(s);
            let _ = evt_tx.send(Event::Snapshot(copy));
        }

        // STUN antes de soltar o loop de recepção (dividem o mesmo socket).
        // Tempo curto: serve só para mostrar o código público na UI.
        let public: Option<SocketAddr> = if std::env::var_os("VNET_SKIP_STUN").is_some() {
            None
        } else {
            match tokio::time::timeout(
                Duration::from_millis(5000),
                stun::public_endpoint(&sock),
            )
            .await
            {
                Ok(ep) => ep,
                Err(_) => None,
            }
        };

        // Uma única leitura da interface principal: serve para o código local,
        // para o filtro de transporte e para a varredura de LAN.
        let local_ip = local_ipv4();
        let local_ep = {
            let ip = local_ip.unwrap_or(Ipv4Addr::LOCALHOST);
            format!("{ip}:{local_port}")
        };
        let public_ep = public.map(|ep| format!("{}:{}", ep.ip(), local_port));

        // canal interno do loop (UDP, TUN, tick, comandos)
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Ev>();

        let mut core = Core {
            cfg,
            sock: sock.clone(),
            key,
            room_hash,
            my_id,
            my_ip,
            local_ip,
            seed,
            code: None,
            public_ep,
            local_ep: Some(local_ep),
            mapped: false,
            failed: false,
            peers: HashMap::new(),
            hello_tried: HashMap::new(),
            seen: VecDeque::new(),
            seen_set: HashSet::new(),
            tun: None,
            seq: 1,
            snap: snap.clone(),
            evt_tx: evt_tx.clone(),
            ev: ev_tx.clone(),
            capture,
        };
        core.refresh_code();
        core.try_bring_up_tun().await;

        // ---- tasks de I/O ---------------------------------------------------
        {
            let sock = sock.clone();
            let ev_tx = ev_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    match sock.recv_from(&mut buf).await {
                        Ok((n, from)) => {
                            if ev_tx.send(Ev::Udp(buf[..n].to_vec(), from)).is_err() {
                                break;
                            }
                        }
                        Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                    }
                }
            });
        }

        {
            let ev_tx = ev_tx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(TICK).await;
                    if ev_tx.send(Ev::Tick).is_err() {
                        break;
                    }
                }
            });
        }

        {
            let ev_tx = ev_tx.clone();
            tokio::spawn(async move {
                while let Some(cmd) = cmd_rx.recv().await {
                    if ev_tx.send(Ev::Cmd(cmd)).is_err() {
                        break;
                    }
                }
            });
        }

        // UPnP em paralelo: pode levar segundos e não bloqueia o handshake.
        if std::env::var_os("VNET_SKIP_UPNP").is_none() {
            let ev_tx = ev_tx.clone();
            tokio::spawn(async move {
                let mapped = match local_ipv4() {
                    Some(local) => upnp::map_port(local_port, local, local_port).await,
                    None => false,
                };
                let _ = ev_tx.send(Ev::Mapped(mapped));
            });
        }

        // ---- estado inicial -------------------------------------------------
        {
            let mut s = snap.lock().unwrap();
            s.state = if core.seed.is_some() { "Connecting".into() } else { "Waiting".into() };
            s.code = core.code.clone();
            s.mapped = core.mapped;
            s.virtual_ip = Some(my_ip.to_string());
            s.peers.clear();
            let copy = s.clone();
            drop(s);
            let _ = evt_tx.send(Event::Snapshot(copy));
        }

        let hello_deadline = Instant::now() + HELLO_TIMEOUT;
        let mut last_hello = Instant::now() - Duration::from_secs(2);
        let mut last_ping = Instant::now();
        let mut last_gossip = Instant::now();
        let mut last_sweep = Instant::now() - LAN_SWEEP_EVERY;
        let mut last_snap = Instant::now();

        // ---- loop -----------------------------------------------------------
        while let Some(ev) = ev_rx.recv().await {
            match ev {
                Ev::Udp(buf, from) => {
                    core.on_udp(&buf, from).await;
                }
                Ev::Tun(pkt) => {
                    core.on_tun(&pkt).await;
                }
                Ev::Mapped(m) => {
                    core.mapped = m;
                    if m {
                        core.refresh_code();
                    }
                    let _ = core.evt_tx.send(Event::Log(format!(
                        "UPnP: porta UDP {local_port} {}",
                        if m { "mapeada no roteador" } else { "sem mapeamento (encaminhe no roteador)" }
                    )));
                    core.publish().await;
                }
                Ev::Tick => {
                    let now = Instant::now();

                    // Ainda sozinho com um seed: insiste no HELLO.
                    if let Some(dst) = core.seed {
                        if core.peers.is_empty() && now.duration_since(last_hello) >= HELLO_EVERY {
                            last_hello = now;
                            core.send_hello_to(dst).await;
                        }
                    }

                    // Sozinho: procura a mesma rede na LAN (sem código).
                    if core.peers.is_empty() && now.duration_since(last_sweep) >= LAN_SWEEP_EVERY {
                        last_sweep = now;
                        core.lan_sweep().await;
                    }

                    // Seed inalcançável: falha explícita depois do prazo.
                    if core.seed.is_some() && core.peers.is_empty() && now >= hello_deadline
                        && !core.failed
                    {
                        core.failed = true;
                        core.set_failed(
                            "não foi possível alcançar o outro PC — confira o código, a senha e a porta UDP",
                        );
                        break;
                    }

                    // keepalive + RTT
                    if now.duration_since(last_ping) >= PING_EVERY {
                        last_ping = now;
                        core.ping_peers(now).await;
                    }

                    // gossip: espalha quem eu conheço
                    if now.duration_since(last_gossip) >= GOSSIP_EVERY && !core.peers.is_empty() {
                        last_gossip = now;
                        core.send_peer_list(None).await;
                    }

                    // expira peers mudos
                    let stale: Vec<[u8; 8]> = core
                        .peers
                        .iter()
                        .filter(|(_, p)| now.duration_since(p.last_seen) > PEER_TIMEOUT)
                        .map(|(id, _)| *id)
                        .collect();
                    for id in stale {
                        core.peers.remove(&id);
                        core.publish().await;
                    }

                    if now.duration_since(last_snap) >= Duration::from_secs(1) {
                        last_snap = now;
                        core.publish().await;
                    }
                }
                Ev::Cmd(Cmd::Ping(id)) => {
                    core.send_ping_by_id(&id).await;
                }
                Ev::Cmd(Cmd::Inject(pkt)) => {
                    core.on_tun(&pkt).await;
                }
                Ev::Cmd(Cmd::Disconnect) => {
                    core.send_bye().await;
                    if let Some(t) = &core.tun {
                        t.stop();
                    }
                    let c = {
                        let mut s = snap.lock().unwrap();
                        s.state = "Disconnected".into();
                        s.peers.clear();
                        s.virtual_ip = None;
                        s.code = None;
                        s.room = None;
                        s.clone()
                    };
                    let _ = evt_tx.send(Event::Snapshot(c));
                    upnp::unmap_port(local_port).await;
                    break;
                }
            }
        }

        Ok(())
    }

    fn set_failed(&self, msg: &str) {
        let mut s = self.snap.lock().unwrap();
        s.state = "Failed".into();
        s.error = Some(msg.to_string());
        let copy = s.clone();
        drop(s);
        let _ = self.evt_tx.send(Event::Snapshot(copy));
    }

    fn refresh_code(&mut self) {
        self.code = Some(match (self.mapped, &self.public_ep) {
            (true, Some(pubep)) => pubep.clone(),
            _ => self
                .local_ep
                .clone()
                .unwrap_or_else(|| "0.0.0.0:0".to_string()),
        });
    }

    // -- envio --------------------------------------------------------------

    async fn send_frame(&self, dst: SocketAddr, typ: u8, payload: &[u8]) {
        let _ = self.sock.send_to(&frame(typ, payload), dst).await;
    }

    async fn send_hello_to(&self, dst: SocketAddr) {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&self.room_hash);
        p.extend_from_slice(&self.my_id);
        p.extend_from_slice(&self.my_ip.octets());
        self.send_frame(dst, T_HELLO, &p).await;
    }

    /// Procura a mesma rede (nome + senha) na LAN, sem código nenhum.
    /// Só roda enquanto o nó está sozinho — depois disso o gossip basta.
    async fn lan_sweep(&self) {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&self.room_hash);
        p.extend_from_slice(&self.my_id);
        p.extend_from_slice(&self.my_ip.octets());
        let blob = frame(T_HELLO, &p);

        let mut targets = vec![Ipv4Addr::BROADCAST];
        if let Some(local) = self.local_ip {
            let o = local.octets();
            let directed = Ipv4Addr::new(o[0], o[1], o[2], 255);
            if directed != local && !targets.contains(&directed) {
                targets.push(directed);
            }
        }

        for ip in targets {
            for port in VNET_PORT_RANGE {
                let _ = self
                    .sock
                    .send_to(&blob, SocketAddr::from((ip, port)))
                    .await;
            }
        }
    }

    async fn send_bye(&self) {
        for p in self.peers.values() {
            let mut payload = Vec::with_capacity(24);
            payload.extend_from_slice(&self.room_hash);
            payload.extend_from_slice(&self.my_id);
            self.send_frame(p.addr, T_BYE, &payload).await;
        }
    }

    async fn ping_peers(&mut self, now: Instant) {
        let stamp = now_ms();
        for p in self.peers.values_mut() {
            let mut payload = Vec::with_capacity(32);
            payload.extend_from_slice(&self.room_hash);
            payload.extend_from_slice(&self.my_id);
            payload.extend_from_slice(&stamp.to_be_bytes());
            let pkt = frame(T_PING, &payload);
            let _ = self.sock.send_to(&pkt, p.addr).await;
            p.ping_at = Some(now);
        }
    }

    async fn send_ping_by_id(&mut self, id: &str) {
        let Some(pid) = parse_peer_id(id) else { return };
        let Some(p) = self.peers.get(&pid) else { return };
        let addr = p.addr;
        let mut payload = Vec::with_capacity(32);
        payload.extend_from_slice(&self.room_hash);
        payload.extend_from_slice(&self.my_id);
        payload.extend_from_slice(&now_ms().to_be_bytes());
        let _ = self.sock.send_to(&frame(T_PING, &payload), addr).await;
        if let Some(p) = self.peers.get_mut(&pid) {
            p.ping_at = Some(Instant::now());
        }
    }

    /// Lista de membros (id + IP virtual + endpoint observado).
    /// `only = Some(addr)` manda só para aquele endereço.
    async fn send_peer_list(&self, only: Option<SocketAddr>) {
        let mut p = Vec::with_capacity(16 + self.peers.len() * 18);
        p.extend_from_slice(&self.room_hash);
        for peer in self.peers.values() {
            p.extend_from_slice(&peer.id);
            p.extend_from_slice(&peer.ip.octets());
            match peer.addr {
                SocketAddr::V4(v4) => {
                    p.extend_from_slice(&v4.ip().octets());
                    p.extend_from_slice(&v4.port().to_be_bytes());
                }
                SocketAddr::V6(_) => {
                    p.extend_from_slice(&[0, 0, 0, 0]);
                    p.extend_from_slice(&0u16.to_be_bytes());
                }
            }
        }
        let blob = frame(T_PEERS, &p);
        match only {
            Some(addr) => {
                let _ = self.sock.send_to(&blob, addr).await;
            }
            None => {
                for peer in self.peers.values() {
                    let _ = self.sock.send_to(&blob, peer.addr).await;
                }
            }
        }
    }

    /// Envia o mesmo blob cifrado para todos os peers (ou só um).
    async fn blast(&self, blob: &[u8], only: Option<[u8; 8]>) {
        match only {
            Some(id) => {
                if let Some(p) = self.peers.get(&id) {
                    let _ = self.sock.send_to(blob, p.addr).await;
                }
            }
            None => {
                for p in self.peers.values() {
                    let _ = self.sock.send_to(blob, p.addr).await;
                }
            }
        }
    }

    // -- recepção -----------------------------------------------------------

    async fn on_udp(&mut self, buf: &[u8], from: SocketAddr) {
        let Some((typ, p)) = unframe(buf) else { return };

        // Todo pacote carrega (ou é validado por) o room hash.
        if p.len() < 16 || p[..16] != self.room_hash {
            return;
        }

        // Pacotes com origem na própria faixa virtual vêm do adaptador TUN
        // (ou de outra VPN na mesma faixa) — não são endpoint de transporte.
        if let SocketAddr::V4(v4) = from {
            if !plausible_transport(*v4.ip(), self.local_ip) {
                return;
            }
        }

        match typ {
            T_HELLO => {
                if p.len() < 28 {
                    return;
                }
                let mut id = [0u8; 8];
                id.copy_from_slice(&p[16..24]);
                if id == self.my_id {
                    return;
                }
                let claimed = Ipv4Addr::new(p[24], p[25], p[26], p[27]);
                let ip = if in_virtual_range(claimed) {
                    claimed
                } else {
                    derive_ip(id)
                };

                let is_new = !self.peers.contains_key(&id);
                let existing = self.peers.get(&id).map(|peer| peer.addr);
                match self.peers.get_mut(&id) {
                    Some(peer) => {
                        peer.addr = from;
                        peer.last_seen = Instant::now();
                        peer.ip = ip;
                    }
                    None => {
                        self.peers.insert(
                            id,
                            Peer {
                                id,
                                ip,
                                addr: from,
                                last_seen: Instant::now(),
                                rtt_ms: None,
                                ping_at: None,
                            },
                        );
                    }
                }

                // Responde só quando o remetente é novo (ou mudou de porta):
                // responder sempre viraria ping-pong de HELLO.
                if is_new || existing != Some(from) {
                    self.send_hello_to(from).await;
                    self.try_bring_up_tun().await;
                    self.send_peer_list(Some(from)).await;
                    self.send_peer_list(None).await;
                    self.publish().await;
                }
            }
            T_PEERS => {
                // entrada: id(8) + ip(4) + endpoint ip(4) + porta(2)
                let mut i = 16;
                let mut learned: Vec<([u8; 8], SocketAddr)> = Vec::new();
                while i + 18 <= p.len() {
                    let mut id = [0u8; 8];
                    id.copy_from_slice(&p[i..i + 8]);
                    // p[i+8..i+12] = IP virtual anunciado (informativo)
                    let ep = Ipv4Addr::new(p[i + 12], p[i + 13], p[i + 14], p[i + 15]);
                    let port = u16::from_be_bytes([p[i + 16], p[i + 17]]);
                    i += 18;

                    if id == self.my_id || self.peers.contains_key(&id) || port == 0 {
                        continue;
                    }
                    // Não liga para endereços que não existem — nem para
                    // endereços que outra VPN da máquina anunciou.
                    if port == 0 || !plausible_transport(ep, self.local_ip) {
                        continue;
                    }
                    learned.push((id, SocketAddr::new(IpAddr::V4(ep), port)));
                }

                let now = Instant::now();
                for (id, addr) in learned {
                    let due = self
                        .hello_tried
                        .get(&id)
                        .map(|t| now.duration_since(*t) >= RETRY_EVERY)
                        .unwrap_or(true);
                    if !due {
                        continue;
                    }
                    self.hello_tried.insert(id, now);
                    self.send_hello_to(addr).await;
                }
            }
            T_DATA => {
                if p.len() < 16 + 8 + 8 + 12 + 16 {
                    return;
                }
                let mut origin = [0u8; 8];
                origin.copy_from_slice(&p[16..24]);
                let mut seqb = [0u8; 8];
                seqb.copy_from_slice(&p[24..32]);
                let seq = u64::from_be_bytes(seqb);
                let nonce_bytes = &p[32..44];
                let ct = &p[44..];

                if origin == self.my_id {
                    return;
                }

                // Quem mandou (direto) — usado para não devolver o relay.
                let sender = self
                    .peers
                    .values()
                    .find(|peer| peer.addr == from)
                    .map(|peer| peer.id);

                // Dedup do relay: (origem, seq) só atravessa uma vez.
                if !self.mark_seen(origin, seq) {
                    return;
                }
                if let Some(peer) = self.peers.get_mut(&origin) {
                    peer.last_seen = Instant::now();
                }

                let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
                let plain = match cipher.decrypt(
                    Nonce::from_slice(nonce_bytes),
                    Payload {
                        msg: ct,
                        aad: &self.room_hash,
                    },
                ) {
                    Ok(v) => v,
                    Err(_) => return, // senha errada ou adulterado
                };

                let dst = ipv4_dst(&plain).unwrap_or(Ipv4Addr::UNSPECIFIED);
                let is_mine = dst == self.my_ip
                    || dst == Ipv4Addr::UNSPECIFIED
                    || is_broadcast(dst);
                if is_mine {
                    self.deliver(&plain);
                }

                // Encaminha o blob original (não recifra) para quem ainda
                // não recebeu: destino direto, broadcast ou desconhecido.
                if is_mine && !is_broadcast(dst) {
                    return;
                }
                let target = if is_broadcast(dst) || dst == Ipv4Addr::UNSPECIFIED {
                    None
                } else {
                    self.peers
                        .values()
                        .find(|peer| peer.ip == dst)
                        .map(|peer| peer.id)
                };
                match target {
                    Some(id) if Some(id) != sender => {
                        self.blast(buf, Some(id)).await;
                    }
                    Some(_) => {}
                    None => {
                        for (id, peer) in self.peers.iter() {
                            if Some(*id) == sender {
                                continue;
                            }
                            let _ = self.sock.send_to(buf, peer.addr).await;
                        }
                    }
                }
            }
            T_PING => {
                if p.len() < 32 {
                    return;
                }
                let mut id = [0u8; 8];
                id.copy_from_slice(&p[16..24]);
                if id != self.my_id {
                    self.touch(id, from);
                }
                let mut payload = Vec::with_capacity(32);
                payload.extend_from_slice(&self.room_hash);
                payload.extend_from_slice(&self.my_id);
                payload.extend_from_slice(&p[24..32]); // devolve o carimbo original
                self.send_frame(from, T_PONG, &payload).await;
            }
            T_PONG => {
                if p.len() < 32 {
                    return;
                }
                let mut id = [0u8; 8];
                id.copy_from_slice(&p[16..24]);
                if id == self.my_id {
                    return;
                }
                let stamp = u64::from_be_bytes(p[24..32].try_into().unwrap_or([0; 8]));
                if self.touch(id, from) {
                    if let Some(peer) = self.peers.get_mut(&id) {
                        let rtt = now_ms().saturating_sub(stamp).min(u16::MAX as u64) as u16;
                        peer.rtt_ms = Some(rtt);
                    }
                }
            }
            T_BYE => {
                if p.len() >= 24 {
                    let mut id = [0u8; 8];
                    id.copy_from_slice(&p[16..24]);
                    if self.peers.remove(&id).is_some() {
                        self.publish().await;
                    }
                }
            }
            _ => {}
        }
    }

    /// Atualiza presença; devolve `true` se o membro já era conhecido.
    fn touch(&mut self, id: [u8; 8], from: SocketAddr) -> bool {
        match self.peers.get_mut(&id) {
            Some(peer) => {
                peer.addr = from;
                peer.last_seen = Instant::now();
                true
            }
            None => false,
        }
    }

    fn mark_seen(&mut self, origin: [u8; 8], seq: u64) -> bool {
        if !self.seen_set.insert((origin, seq)) {
            return false;
        }
        self.seen.push_back((origin, seq));
        while self.seen.len() > SEEN_CAP {
            if let Some(old) = self.seen.pop_front() {
                self.seen_set.remove(&old);
            }
        }
        true
    }

    fn deliver(&self, plain: &[u8]) {
        if let Some(t) = &self.tun {
            t.send(plain);
            return;
        }
        if let Some(tx) = self.capture.lock().unwrap().as_ref() {
            let _ = tx.send(plain.to_vec());
        }
    }

    async fn publish(&self) {
        let peers: Vec<PeerInfo> = self
            .peers
            .values()
            .map(|p| PeerInfo {
                id: hex8(p.id),
                ip: p.ip.to_string(),
                endpoint: p.addr.to_string(),
                rtt_ms: p.rtt_ms,
                is_host: false,
            })
            .collect();

        let mut s = self.snap.lock().unwrap();
        s.peers = peers;
        s.virtual_ip = Some(self.my_ip.to_string());
        s.code = self.code.clone();
        s.public_endpoint = self.public_ep.clone();
        s.local_endpoint = self.local_ep.clone();
        s.mapped = self.mapped;
        s.room = Some(self.cfg.room.clone());
        s.tun_ready = self.tun.is_some();
        s.role = "mesh".into();
        if !self.failed {
            s.state = if !self.peers.is_empty() {
                "Connected".into()
            } else if self.seed.is_some() {
                "Connecting".into()
            } else {
                "Waiting".into()
            };
        }
        let copy = s.clone();
        drop(s);
        let _ = self.evt_tx.send(Event::Snapshot(copy));
    }

    async fn try_bring_up_tun(&mut self) {
        if self.tun.is_some() {
            return;
        }
        let ip = self.my_ip;
        let mtu = self.cfg.mtu;
        match tokio::task::spawn_blocking(move || super::tun_win::TunHandle::create(ip, mtu)).await {
            Ok(Ok(handle)) => {
                let handle = Arc::new(handle);
                let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                handle.spawn_reader(tx);
                self.tun = Some(handle);

                // bombeia pacotes do TUN para o loop principal
                let ev = self.ev.clone();
                tokio::spawn(async move {
                    while let Some(pkt) = rx.recv().await {
                        if ev.send(Ev::Tun(pkt)).is_err() {
                            break;
                        }
                    }
                });
                let _ = self.evt_tx.send(Event::Log(format!(
                    "interface {} ativa em {}",
                    super::tun_win::ADAPTER_NAME,
                    ip
                )));
            }
            Ok(Err(e)) => {
                let _ = self.evt_tx.send(Event::Log(format!(
                    "TUN indisponível ({e}) — sem repasse de pacotes IP. \
                     Execute como administrador."
                )));
            }
            Err(e) => {
                let _ = self.evt_tx.send(Event::Log(format!("TUN join error: {e}")));
            }
        }
    }

    async fn on_tun(&mut self, pkt: &[u8]) {
        if self.peers.is_empty() {
            return;
        }
        let dst = match ipv4_dst(pkt) {
            Some(d) => d,
            None => return,
        };
        if dst == self.my_ip {
            return;
        }

        let nonce: [u8; 12] = random_bytes();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ct = match cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: pkt,
                aad: &self.room_hash,
            },
        ) {
            Ok(v) => v,
            Err(_) => return,
        };

        self.seq = self.seq.wrapping_add(1);
        let mut payload = Vec::with_capacity(16 + 8 + 8 + 12 + ct.len());
        payload.extend_from_slice(&self.room_hash);
        payload.extend_from_slice(&self.my_id);
        payload.extend_from_slice(&self.seq.to_be_bytes());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ct);

        let blob = frame(T_DATA, &payload);

        let target = self
            .peers
            .values()
            .find(|p| p.ip == dst)
            .map(|p| p.id);

        if is_broadcast(dst) || dst == Ipv4Addr::UNSPECIFIED {
            // Descoberta LAN (Minecraft 224.0.2.60) vai para todo mundo.
            self.blast(&blob, None).await;
        } else if let Some(id) = target {
            self.blast(&blob, Some(id)).await;
        } else {
            // Destino desconhecido: espalha, quem conhecer entrega.
            self.blast(&blob, None).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

fn in_virtual_range(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[..3] == VNET_OCTETS && o[3] >= 1 && o[3] <= 254
}

/// O endereço de origem pode ser usado como transporte até o membro?
///
/// Máquinas com várias interfaces (outra VPN de malha, VirtualBox, WSL)
/// fazem o broadcast de descoberta sair por todas elas — e o eco chega com o
/// endereço da *outra* VPN, que não leva a lugar nenhum. Só aceitamos loopback,
/// link-local, o mesmo /16 da interface principal ou endereço público.
fn plausible_transport(ip: Ipv4Addr, local: Option<Ipv4Addr>) -> bool {
    if ip.is_loopback() || ip.is_link_local() {
        return true;
    }
    if ip.is_unspecified() || ip.is_broadcast() || ip.octets()[0] >= 224 {
        return false;
    }
    let o = ip.octets();
    // Faixas de outras VPNs de malha (25/8, 26/8) e CGNAT (100.64/10).
    if o[0] == 25 || o[0] == 26 {
        return false;
    }
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        return false;
    }
    if ip.is_private() {
        // Sem saber a interface principal, aceitar é melhor que perder a LAN.
        return match local {
            Some(l) => l.octets()[..2] == o[..2],
            None => true,
        };
    }
    true
}

fn is_broadcast(ip: Ipv4Addr) -> bool {
    if ip == Ipv4Addr::BROADCAST || ip == VIRTUAL_BROADCAST {
        return true;
    }
    ip.octets()[0] >= 224
}

fn hex8(id: [u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_peer_id(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// IP local da rota padrão (sem enviar pacote de verdade).
pub fn local_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// STUN mínimo (Binding Request) — roda no próprio socket do túnel
// ---------------------------------------------------------------------------

pub mod stun {
    use super::*;

    pub async fn public_endpoint(sock: &UdpSocket) -> Option<SocketAddr> {
        let servers = ["stun.l.google.com:19302", "stun1.l.google.com:19302"];
        for s in servers {
            let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(s).await {
                Ok(it) => it.filter(|a| a.is_ipv4()).collect(),
                Err(_) => continue,
            };
            for server in addrs {
                // Três tentativas: um pacote perdido não pode deixar a UI sem
                // o código público (é por ele que o outro PC entra de longe).
                for _attempt in 0..3 {
                    let mut req = Vec::with_capacity(20);
                    req.extend_from_slice(&0x0001u16.to_be_bytes());
                    req.extend_from_slice(&0u16.to_be_bytes());
                    req.extend_from_slice(&0x2112A442u32.to_be_bytes());
                    let txid: [u8; 12] = random_bytes();
                    req.extend_from_slice(&txid);

                    if sock.send_to(&req, server).await.is_err() {
                        break;
                    }
                    let mut buf = [0u8; 512];
                    let deadline = tokio::time::Instant::now() + Duration::from_millis(700);
                    loop {
                        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                        if left.is_zero() {
                            break; // tempo esgotado: a próxima tentativa reenvia
                        }
                        match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
                            Ok(Ok((n, from))) if from == server => {
                                if let Some(ep) = parse_binding_response(&buf[..n], &txid) {
                                    return Some(ep);
                                }
                            }
                            // Pacote de outra origem: segue esperando a resposta.
                            Ok(Ok(_)) => continue,
                            // Socket quebrado: não adianta insistir neste servidor.
                            Ok(Err(_)) => break,
                            // Timeout da leitura: sai para reenviar.
                            Err(_) => break,
                        }
                    }
                }
            }
        }
        None
    }

    fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
        if buf.len() < 20 {
            return None;
        }
        if u16::from_be_bytes([buf[0], buf[1]]) != 0x0101 {
            return None;
        }
        if &buf[8..20] != txid {
            return None;
        }
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let mut i = 20;
        let end = (20 + len).min(buf.len());
        while i + 4 <= end {
            let atyp = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let alen = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            let vstart = i + 4;
            if vstart + alen > end {
                return None;
            }
            if atyp == 0x0020 && alen >= 8 {
                let family = buf[vstart + 1];
                let port = u16::from_be_bytes([buf[vstart + 2], buf[vstart + 3]]) ^ 0x2112;
                let ip = Ipv4Addr::new(
                    buf[vstart + 4] ^ 0x21,
                    buf[vstart + 5] ^ 0x12,
                    buf[vstart + 6] ^ 0xA4,
                    buf[vstart + 7] ^ 0x42,
                );
                if family == 0x01 {
                    return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
                }
            }
            i = vstart + alen + ((4 - alen % 4) % 4);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// UPnP IGD mínimo (SSDP + SOAP) — só TCP/HTTP cru, sem dependências
// ---------------------------------------------------------------------------

pub mod upnp {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const SSDP: &str = "239.255.255.250:1900";

    pub async fn map_port(internal_port: u16, local_ip: Ipv4Addr, external_port: u16) -> bool {
        let Some((host, path, service)) = discover().await else {
            return false;
        };
        let body = soap_add(&service, external_port, internal_port, local_ip);
        post_soap(&host, &path, &body, "AddPortMapping").await
    }

    pub async fn unmap_port(external_port: u16) {
        let Some((host, path, service)) = discover().await else {
            return;
        };
        let body = soap_del(&service, external_port);
        let _ = post_soap(&host, &path, &body, "DeletePortMapping").await;
    }

    async fn discover() -> Option<(String, String, String)> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let msg = concat!(
            "M-SEARCH * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "MAN: \"ssdp:discover\"\r\n",
            "MX: 2\r\n",
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
            "\r\n"
        );
        sock.send_to(msg.as_bytes(), SSDP).await.ok()?;

        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    let Some(loc) = header(&text, "location") else { continue };
                    if let Some((host, path)) = fetch_control_url(&loc).await {
                        let service = if path.contains("WANPPPConnection") {
                            "urn:schemas-upnp-org:service:WANPPPConnection:1".to_string()
                        } else {
                            "urn:schemas-upnp-org:service:WANIPConnection:1".to_string()
                        };
                        return Some((host, path, service));
                    }
                }
                _ => break,
            }
        }
        None
    }

    fn header(text: &str, name: &str) -> Option<String> {
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with(name) && lower.as_bytes().get(name.len()) == Some(&b':') {
                return Some(line[name.len() + 1..].trim().to_string());
            }
        }
        None
    }

    async fn fetch_control_url(loc: &str) -> Option<(String, String)> {
        let rest = loc.strip_prefix("http://")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        let body = http(authority, &request).await?;
        let lower = body.to_ascii_lowercase();
        let idx = lower
            .find("wanipconnection:1</servicetype>")
            .or_else(|| lower.find("wanpppconnection:1</servicetype>"))?;
        let tail = &body[idx..];
        let start = tail.find("<controlURL>")? + "<controlURL>".len();
        let end = tail.find("</controlURL>")?;
        let ctrl = tail[start..end].trim().to_string();
        let path = if ctrl.starts_with("http://") {
            ctrl.strip_prefix(&format!("http://{authority}"))
                .unwrap_or(&ctrl)
                .to_string()
        } else if ctrl.starts_with('/') {
            ctrl
        } else {
            format!("/{ctrl}")
        };
        Some((authority.to_string(), path))
    }

    async fn http(authority: &str, request: &str) -> Option<String> {
        let addr: SocketAddr = tokio::net::lookup_host(authority).await.ok()?.next()?;
        let mut stream = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(addr))
            .await
            .ok()?
            .ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut out)).await;
        Some(String::from_utf8_lossy(&out).to_string())
    }

    fn soap_envelope(action: &str, service: &str, inner: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?>\r\n\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><u:{action} xmlns:u=\"{service}\">{inner}</u:{action}></s:Body></s:Envelope>"
        )
    }

    fn soap_add(service: &str, ext: u16, int: u16, ip: Ipv4Addr) -> String {
        let inner = format!(
            "<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{ext}</NewExternalPort>\
<NewProtocol>UDP</NewProtocol>\
<NewInternalPort>{int}</NewInternalPort>\
<NewInternalClient>{ip}</NewInternalClient>\
<NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>VNET</NewPortMappingDescription>\
<NewLeaseDuration>7200</NewLeaseDuration>"
        );
        soap_envelope("AddPortMapping", service, &inner)
    }

    fn soap_del(service: &str, ext: u16) -> String {
        let inner = format!(
            "<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{ext}</NewExternalPort>\
<NewProtocol>UDP</NewProtocol>"
        );
        soap_envelope("DeletePortMapping", service, &inner)
    }

    async fn post_soap(authority: &str, path: &str, body: &str, action: &str) -> bool {
        let service = if action == "AddPortMapping" {
            "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"
        } else {
            "urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"
        };
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        match http(authority, &request).await {
            Some(resp) => resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200"),
            None => false,
        }
    }
}
