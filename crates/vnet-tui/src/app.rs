//! TUI app with ratatui terminal dashboard

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hex;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, Table,
        Tabs, Wrap,
    },
    Frame, Terminal,
};
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use serde_json;

use vnet_core::{CoreError, CoreResult, Session, SessionConfig, SessionEvent, SessionState};
use vnet_ipc::{IpcClient, ClientConfig, IpcError};
use vnet_proto::message::PeerInfo;

/// TUI application configuration
#[derive(Debug, Clone)]
pub struct TuiConfig {
    pub tick_rate: Duration,
    pub refresh_rate: Duration,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            tick_rate: Duration::from_millis(100),
            refresh_rate: Duration::from_secs(1),
        }
    }
}

/// TUI result type
pub type TuiResult<T> = std::result::Result<T, TuiError>;

/// TUI errors
#[derive(Debug, thiserror::Error)]
pub enum TuiError {
    #[error("Terminal error: {0}")]
    Terminal(#[from] io::Error),
    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),
    #[error("Core error: {0}")]
    Core(#[from] CoreError),
    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

/// Log entry for TUI
#[derive(Debug, Clone)]
struct LogEntry {
    timestamp: Instant,
    level: String,
    message: String,
}

/// Connection state for TUI
#[derive(Debug, Clone)]
struct ConnectionState {
    session_state: SessionState,
    peers: Vec<PeerInfo>,
    logs: Vec<LogEntry>,
    virtual_ip: String,
    uptime: Option<Instant>,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Main TUI application
pub struct App {
    config: TuiConfig,
    connection_state: ConnectionState,
    running: bool,
    tab_index: usize,
    peer_list_state: ListState,
    log_list_state: ListState,
    ipc_client: Option<IpcClient>,
    event_tx: mpsc::UnboundedSender<TuiEvent>,
    event_rx: mpsc::UnboundedReceiver<TuiEvent>,
    last_refresh: Instant,
}

#[derive(Debug)]
enum TuiEvent {
    RefreshState,
    AddLog(LogEntry),
    UpdatePeers(Vec<PeerInfo>),
    UpdateSessionState(SessionState),
    UpdateStats(u64, u64),
}

impl App {
    pub fn new(config: TuiConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        
        Self {
            config,
            connection_state: ConnectionState {
                session_state: SessionState::Disconnected,
                peers: Vec::new(),
                logs: Vec::new(),
                virtual_ip: "10.0.0.1".to_string(),
                uptime: None,
                rx_bytes: 0,
                tx_bytes: 0,
            },
            running: true,
            tab_index: 0,
            peer_list_state: ListState::default(),
            log_list_state: ListState::default(),
            ipc_client: None,
            event_tx,
            event_rx,
            last_refresh: Instant::now(),
        }
    }

    pub async fn run(&mut self) -> TuiResult<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Start background tasks
        self.start_background_tasks().await?;

        // Main loop
        while self.running {
            terminal.draw(|f| self.ui(f))?;

            // Handle events
            if event::poll(self.config.tick_rate)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.handle_key(key.code);
                    }
                }
            }

            // Handle internal events
            while let Ok(event) = self.event_rx.try_recv() {
                self.handle_event(event).await;
            }

            // Periodic refresh
            if self.last_refresh.elapsed() >= self.config.refresh_rate {
                self.request_refresh().await;
                self.last_refresh = Instant::now();
            }
        }

        // Cleanup terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        Ok(())
    }

    async fn start_background_tasks(&mut self) -> Result<()> {
        let event_tx = self.event_tx.clone();
        
        // Start IPC client
        let mut client = IpcClient::new(ClientConfig::default());
        client.connect().await?;
        self.ipc_client = Some(client);

        // Spawn refresh task
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                let _ = tx.send(TuiEvent::RefreshState);
            }
        });

        // Spawn log collection task
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                // In a real implementation, this would collect logs from the session
            }
        });

        // Initial state fetch
        self.request_refresh().await;

        Ok(())
    }

    async fn request_refresh(&self) {
        if let Some(client) = &self.ipc_client {
            let tx = self.event_tx.clone();
            
            // Get session state
            if let Ok(result) = client.call("session.state", serde_json::json!({})).await {
                if let Some(state_str) = result.get("state").and_then(|v| v.as_str()) {
                    let state = match state_str {
                        "Disconnected" => SessionState::Disconnected,
                        "Connecting" => SessionState::Connecting,
                        "Handshaking" => SessionState::Handshaking,
                        "NatTraversal" => SessionState::NatTraversal,
                        "Connected" => SessionState::Connected,
                        "Disconnecting" => SessionState::Disconnecting,
                        _ => SessionState::Failed(state_str.to_string()),
                    };
                    let _ = tx.send(TuiEvent::UpdateSessionState(state));
                }
            }

            // Get peers
            if let Ok(result) = client.call("peer.list", serde_json::json!({})).await {
                if let Some(peers_val) = result.get("peers").and_then(|v| v.as_array()) {
                    let mut peers = Vec::new();
                    for peer in peers_val {
                        if let Some(info) = self.parse_peer_info(peer) {
                            peers.push(info);
                        }
                    }
                    let _ = tx.send(TuiEvent::UpdatePeers(peers));
                }
            }
        }
    }

    fn parse_peer_info(&self, value: &serde_json::Value) -> Option<PeerInfo> {
        let peer_id = value.get("peer_id")?.as_str()?.to_string();
        let virtual_ip = value.get("virtual_ip")?.as_str()?.parse().ok()?;
        let state_str = value.get("state")?.as_str()?;
        let state = match state_str {
            "Handshaking" => vnet_proto::message::PeerState::Handshaking,
            "Connected" => vnet_proto::message::PeerState::Connected,
            "Disconnected" => vnet_proto::message::PeerState::Disconnected,
            "Reconnecting" => vnet_proto::message::PeerState::Reconnecting,
            "Blocked" => vnet_proto::message::PeerState::Blocked,
            _ => vnet_proto::message::PeerState::Disconnected,
        };
        
        let endpoint = value.get("endpoint").and_then(|v| v.as_str()).and_then(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 2 {
                let ip = parts[0].parse().ok()?;
                let port = parts[1].parse().ok()?;
                Some((ip, port))
            } else {
                None
            }
        });

        Some(PeerInfo {
            session_id: [0u8; vnet_proto::constants::SESSION_ID_SIZE],
            static_public: vec![],
            virtual_ip,
            endpoint,
            aead_algorithms: 0x03,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            state,
            mtu: 1400,
        })
    }

    async fn handle_event(&mut self, event: TuiEvent) {
        match event {
            TuiEvent::RefreshState => {
                self.request_refresh().await;
            }
            TuiEvent::AddLog(log) => {
                self.connection_state.logs.push(log);
                if self.connection_state.logs.len() > 1000 {
                    self.connection_state.logs.drain(0..500);
                }
            }
            TuiEvent::UpdatePeers(peers) => {
                self.connection_state.peers = peers;
            }
            TuiEvent::UpdateSessionState(state) => {
                self.connection_state.session_state = state.clone();
                if matches!(state, SessionState::Connected) && self.connection_state.uptime.is_none() {
                    self.connection_state.uptime = Some(Instant::now());
                } else if matches!(state, SessionState::Disconnected) {
                    self.connection_state.uptime = None;
                }
            }
            TuiEvent::UpdateStats(rx, tx) => {
                self.connection_state.rx_bytes = rx;
                self.connection_state.tx_bytes = tx;
            }
        }
    }

    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Tab => self.tab_index = (self.tab_index + 1) % 3,
            KeyCode::BackTab => self.tab_index = (self.tab_index + 2) % 3,
            KeyCode::Up => {
                if self.tab_index == 1 {
                    let i = self.peer_list_state.selected().unwrap_or(0);
                    if i > 0 {
                        self.peer_list_state.select(Some(i - 1));
                    }
                } else if self.tab_index == 2 {
                    let i = self.log_list_state.selected().unwrap_or(0);
                    if i > 0 {
                        self.log_list_state.select(Some(i - 1));
                    }
                }
            }
            KeyCode::Down => {
                if self.tab_index == 1 {
                    let i = self.peer_list_state.selected().unwrap_or(0);
                    if i + 1 < self.connection_state.peers.len() {
                        self.peer_list_state.select(Some(i + 1));
                    }
                } else if self.tab_index == 2 {
                    let i = self.log_list_state.selected().unwrap_or(0);
                    if i + 1 < self.connection_state.logs.len() {
                        self.log_list_state.select(Some(i + 1));
                    }
                }
            }
            KeyCode::Char('c') => {
                // Connect
                self.add_log("INFO", "Connecting to network...");
            }
            KeyCode::Char('d') => {
                // Disconnect
                self.add_log("INFO", "Disconnecting...");
            }
            _ => {}
        }
    }

    fn add_log(&mut self, level: &str, message: &str) {
        let entry = LogEntry {
            timestamp: Instant::now(),
            level: level.to_string(),
            message: message.to_string(),
        };
        self.connection_state.logs.push(entry);
    }

    fn ui(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),    // Header
                Constraint::Length(1),    // Tabs
                Constraint::Min(0),       // Content
                Constraint::Length(3),    // Footer
            ])
            .split(f.size());

        self.render_header(f, chunks[0]);
        self.render_tabs(f, chunks[1]);
        self.render_content(f, chunks[2]);
        self.render_footer(f, chunks[3]);
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let state_style = match self.connection_state.session_state {
            SessionState::Connected => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            SessionState::Connecting | SessionState::Handshaking | SessionState::NatTraversal => {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            }
            SessionState::Disconnecting => Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            SessionState::Failed(_) => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            _ => Style::default().fg(Color::Gray),
        };

        let state_text = format!("{:?}", self.connection_state.session_state);
        let uptime = if let Some(start) = self.connection_state.uptime {
            let elapsed = start.elapsed();
            format!("Uptime: {:02}:{:02}:{:02}", elapsed.as_secs() / 3600, (elapsed.as_secs() % 3600) / 60, elapsed.as_secs() % 60)
        } else {
            "Uptime: --:--:--".to_string()
        };

        let header = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("vnet ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("Cross-platform Virtual Private Network", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::raw("Status: "),
                Span::styled(state_text, state_style),
                Span::raw("  "),
                Span::raw(&uptime),
                Span::raw("  "),
                Span::raw("Peers: "),
                Span::styled(self.connection_state.peers.len().to_string(), Style::default().fg(Color::Cyan)),
                Span::raw("  "),
                Span::raw("Virtual IP: "),
                Span::styled(&self.connection_state.virtual_ip, Style::default().fg(Color::Yellow)),
            ]),
        ])
        .block(Block::default().borders(Borders::ALL).title(" vnet "));

        f.render_widget(header, area);
    }

    fn render_tabs(&self, f: &mut Frame, area: Rect) {
        let tabs = Tabs::new(vec!["Overview", "Peers", "Logs"])
            .block(Block::default().borders(Borders::ALL))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .select(self.tab_index);

        f.render_widget(tabs, area);
    }

    fn render_content(&mut self, f: &mut Frame, area: Rect) {
        match self.tab_index {
            0 => self.render_overview(f, area),
            1 => self.render_peers(f, area),
            2 => self.render_logs(f, area),
            _ => {}
        }
    }

    fn render_overview(&self, f: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left: Connection info
        let connected_peers = self.connection_state.peers.iter()
            .filter(|p| matches!(p.state, vnet_proto::message::PeerState::Connected))
            .count();

        let info_text = vec![
            Line::from(vec![Span::styled("Connection Statistics", Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan))]),
            Line::from(""),
            Line::from(vec![Span::raw("Virtual IP: "), Span::styled(&self.connection_state.virtual_ip, Style::default().fg(Color::Yellow))]),
            Line::from(vec![Span::raw("Total Peers: "), Span::styled(self.connection_state.peers.len().to_string(), Style::default().fg(Color::White))]),
            Line::from(vec![Span::raw("Connected: "), Span::styled(connected_peers.to_string(), Style::default().fg(Color::Green))]),
            Line::from(vec![Span::raw("RX Bytes: "), Span::styled(format_bytes(self.connection_state.rx_bytes), Style::default().fg(Color::Cyan))]),
            Line::from(vec![Span::raw("TX Bytes: "), Span::styled(format_bytes(self.connection_state.tx_bytes), Style::default().fg(Color::Magenta))]),
            Line::from(""),
            Line::from(vec![Span::styled("Network Info", Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan))]),
            Line::from(""),
            Line::from(vec![Span::raw("Protocol: "), Span::styled("vnet v2", Style::default().fg(Color::White))]),
            Line::from(vec![Span::raw("Crypto: "), Span::styled("ChaCha20-Poly1305 / AES-GCM", Style::default().fg(Color::White))]),
            Line::from(vec![Span::raw("NAT: "), Span::styled("STUN + ICE", Style::default().fg(Color::White))]),
        ];

        let info = Paragraph::new(info_text)
            .block(Block::default().borders(Borders::ALL).title(" Overview "))
            .wrap(Wrap { trim: true });

        f.render_widget(info, chunks[0]);

        // Right: Peer status table
        let rows: Vec<Row> = self.connection_state.peers.iter().map(|peer| {
            let state_style = match peer.state {
                vnet_proto::message::PeerState::Connected => Style::default().fg(Color::Green),
                vnet_proto::message::PeerState::Handshaking => Style::default().fg(Color::Yellow),
                vnet_proto::message::PeerState::Reconnecting => Style::default().fg(Color::Blue),
                _ => Style::default().fg(Color::Red),
            };

            Row::new(vec![
                Cell::from(hex::encode(peer.session_id)[..16].to_string()),
                Cell::from(peer.virtual_ip.to_string()),
                Cell::from(peer.endpoint.map(|e| format!("{}:{}", e.0, e.1)).unwrap_or_else(|| "pending".to_string())),
                Cell::from(format!("{:?}", peer.state)).style(state_style),
            ])
        }).collect();

        let table = Table::new(
            rows,
            [Constraint::Length(18), Constraint::Length(15), Constraint::Length(22), Constraint::Length(15)]
        )
        .header(Row::new(vec!["Peer ID", "Virtual IP", "Endpoint", "State"]).style(Style::default().add_modifier(Modifier::BOLD)))
        .block(Block::default().borders(Borders::ALL).title(" Peers "))
        .column_spacing(1);

        f.render_widget(table, chunks[1]);
    }

    fn render_peers(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self.connection_state.peers.iter().enumerate().map(|(i, peer)| {
            let state_color = match peer.state {
                vnet_proto::message::PeerState::Connected => Color::Green,
                vnet_proto::message::PeerState::Handshaking => Color::Yellow,
                vnet_proto::message::PeerState::Reconnecting => Color::Blue,
                _ => Color::Red,
            };

            let endpoint = peer.endpoint.map(|e| format!("{}:{}", e.0, e.1)).unwrap_or_else(|| "pending".to_string());
            
            let peer_id_hex = hex::encode(peer.session_id);
            let peer_id_display = peer_id_hex[..peer_id_hex.len().min(32)].to_string();
            let virtual_ip_str = peer.virtual_ip.to_string();
            
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(peer_id_display, Style::default().fg(Color::Cyan)),
                    Span::raw("  "),
                    Span::styled(virtual_ip_str, Style::default().fg(Color::Yellow)),
                    Span::raw("  "),
                    Span::styled(endpoint, Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::raw("  State: "),
                    Span::styled(format!("{:?}", peer.state), Style::default().fg(state_color).add_modifier(Modifier::BOLD)),
                    Span::raw("  MTU: "),
                    Span::styled(peer.mtu.to_string(), Style::default().fg(Color::White)),
                ]),
            ])
        }).collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Peers "))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::DarkGray))
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, area, &mut self.peer_list_state);
    }

    fn render_logs(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self.connection_state.logs.iter().rev().take(200).map(|log| {
            let level_style = match log.level.as_str() {
                "ERROR" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                "WARN" => Style::default().fg(Color::Yellow),
                "INFO" => Style::default().fg(Color::Green),
                "DEBUG" => Style::default().fg(Color::Blue),
                _ => Style::default().fg(Color::White),
            };

            ListItem::new(Line::from(vec![
                Span::styled(format!("[{:>5}] ", log.level), level_style),
                Span::styled(format!("{:.3}s ", log.timestamp.elapsed().as_secs_f32()), Style::default().fg(Color::Gray)),
                Span::raw(&log.message),
            ]))
        }).collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Logs (newest first) "))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD).bg(Color::DarkGray));

        f.render_stateful_widget(list, area, &mut self.log_list_state);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(" q ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" Quit  "),
            Span::styled(" Tab ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" Switch tabs  "),
            Span::styled(" ↑↓ ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" Navigate  "),
            Span::styled(" c ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" Connect  "),
            Span::styled(" d ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(" Disconnect"),
        ]))
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center);

        f.render_widget(footer, area);
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(mut client) = self.ipc_client.take() {
            let _ = tokio::runtime::Handle::current().block_on(client.disconnect());
        }
    }
}