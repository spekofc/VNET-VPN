//! vnet-gui — protótipo alternativo de interface (egui/eframe)
//!
//! Layout: frameless title bar with logo, Sistema/Rede/Ajuda menu bar,
//! profile card with power button + status pill, collapsible network list.

use std::time::{Duration, Instant};
use std::path::PathBuf;

use eframe::egui::{
    self, pos2, Color32, RichText, Rounding, Sense, Stroke, Vec2,
};
use tokio::sync::mpsc;
use vnet_core::SessionState;
use vnet_ipc::{ClientConfig, IpcClient, IpcServer, MethodRegistry, ServerConfig};
use vnet_proto::message::{PeerInfo, PeerState};

// ---- Palette (azul-marinho escuro) ----
const BG_MAIN: Color32 = Color32::from_rgb(0x1f, 0x28, 0x36);
const BG_PANEL: Color32 = Color32::from_rgb(0x27, 0x32, 0x44);
const BG_TITLE: Color32 = Color32::from_rgb(0x22, 0x2b, 0x3a);
const ACCENT: Color32 = Color32::from_rgb(0x35, 0xc3, 0xc9);
const ORANGE: Color32 = Color32::from_rgb(0xe8, 0x76, 0x3a);
const TEXT: Color32 = Color32::from_rgb(0xe7, 0xea, 0xf0);
const MUTED: Color32 = Color32::from_rgb(0x9a, 0xa7, 0xb5);

/// GUI application configuration
#[derive(Debug, Clone)]
pub struct GuiConfig {
    pub width: f32,
    pub height: f32,
    pub title: String,
    pub resizable: bool,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            width: 380.0,
            height: 640.0,
            title: "VNet VPN".into(),
            resizable: false,
        }
    }
}

/// GUI result type
pub type GuiResult<T> = std::result::Result<T, GuiError>;

/// GUI errors
#[derive(Debug, thiserror::Error)]
pub enum GuiError {
    #[error("Window error: {0}")]
    Window(String),
    #[error("IPC error: {0}")]
    Ipc(String),
    #[error("Core error: {0}")]
    Core(String),
}

// ---- Persistence ----

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Persisted {
    #[serde(default)]
    nickname: String,
    #[serde(default)]
    network: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    virtual_ip: String,
}

fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("vnet").join("gui.json"))
}

fn load_persisted() -> Persisted {
    config_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_persisted(p: &Persisted) {
    if let Some(path) = config_path() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string_pretty(p) {
            let _ = std::fs::write(path, json);
        }
    }
}

/// Auto-assign a virtual IP in the 10.144.0.0/24 range
fn generate_virtual_ip() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("10.144.0.{}", n % 253 + 2)
}

/// Main GUI application
pub struct GuiApp {
    config: GuiConfig,
    event_tx: mpsc::UnboundedSender<GuiEvent>,
    event_rx: mpsc::UnboundedReceiver<GuiEvent>,
    initialized: bool,
    last_refresh: Instant,

    // Connection state
    session_state: SessionState,
    peers: Vec<PeerInfo>,
    virtual_ip: String,
    network_name: Option<String>,
    network_expanded: bool,
    last_connect: Option<(String, Option<String>, String)>,

    // Identity
    nickname: String,

    // Dialogs
    dialog_join: bool,
    dialog_create: bool,
    dialog_rename: bool,
    dialog_settings: bool,
    dialog_about: bool,
    dialog_firewall: bool,

    // Dialog fields
    join_network: String,
    join_password: String,
    create_network: String,
    create_password: String,
    rename_buf: String,
}

#[derive(Debug)]
enum GuiEvent {
    RefreshState,
    UpdatePeers(Vec<PeerInfo>),
    UpdateSessionState(SessionState),
    UpdateIp(String),
}

impl GuiApp {
    pub fn new(config: GuiConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let saved = load_persisted();
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "SNYX-PC".into());
        let nickname = if saved.nickname.is_empty() { hostname } else { saved.nickname.clone() };
        let virtual_ip = if saved.virtual_ip.is_empty() { generate_virtual_ip() } else { saved.virtual_ip.clone() };
        let last_connect = if saved.network.is_empty() {
            None
        } else {
            Some((
                saved.network.clone(),
                if saved.password.is_empty() { None } else { Some(saved.password.clone()) },
                virtual_ip.clone(),
            ))
        };
        Self {
            config,
            event_tx,
            event_rx,
            initialized: false,
            last_refresh: Instant::now(),
            session_state: SessionState::Disconnected,
            peers: Vec::new(),
            virtual_ip,
            network_name: None,
            network_expanded: true,
            last_connect,
            nickname,
            dialog_join: false,
            dialog_create: false,
            dialog_rename: false,
            dialog_settings: false,
            dialog_about: false,
            dialog_firewall: false,
            join_network: String::new(),
            join_password: String::new(),
            create_network: String::new(),
            create_password: String::new(),
            rename_buf: String::new(),
        }
    }

    pub async fn run(self) -> GuiResult<()> {
        let title = self.config.title.clone();

        // Embedded daemon: this process owns \\.\pipe\vnet unless another
        // instance already does. One process = everything works.
        tokio::spawn(async move {
            let mut server = IpcServer::new(ServerConfig::default(), MethodRegistry::new());
            if let Err(e) = server.start().await {
                tracing::debug!("using existing daemon: {}", e);
            }
            // Task runs for the app lifetime; dropping the handle detaches it.
        });

        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_decorations(false)
                .with_inner_size([self.config.width, self.config.height])
                .with_min_inner_size([360.0, 520.0])
                .with_resizable(self.config.resizable)
                .with_title(&title),
            ..Default::default()
        };

        eframe::run_native(
            &title,
            options,
            Box::new(
                move |_cc: &eframe::CreationContext<'_>| -> Result<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>> {
                    Ok(Box::new(self))
                },
            ),
        )
        .map_err(|e| GuiError::Window(e.to_string()))
    }

    fn is_online(&self) -> bool {
        matches!(self.session_state, SessionState::Connected)
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // One-time style + background refresh loop
        if !self.initialized {
            self.initialized = true;
            apply_style(ctx);
            self.spawn_refresh();
        }

        while let Ok(event) = self.event_rx.try_recv() {
            self.handle_event(event);
        }

        if self.last_refresh.elapsed() >= Duration::from_secs(2) {
            self.spawn_refresh();
            self.last_refresh = Instant::now();
        }

        // Ins = Conectar à rede
        if ctx.input(|i| i.key_pressed(egui::Key::Insert)) {
            self.dialog_join = true;
        }

        ctx.request_repaint_after(Duration::from_millis(100));

        self.render_title_bar(ctx);
        self.render_menu_bar(ctx);
        self.render_dialogs(ctx);
        self.render_main(ctx);
    }
}

impl GuiApp {
    // ---- IPC plumbing ----

    fn spawn_refresh(&mut self) {
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let mut client = IpcClient::new(ClientConfig::default());
            if client.connect().await.is_err() {
                return;
            }
            if let Ok(result) = client.call("session.state", serde_json::json!({})).await {
                if let Some(state_str) = result.get("state").and_then(|v| v.as_str()) {
                    let state = match state_str {
                        "Disconnected" => SessionState::Disconnected,
                        "Connecting" => SessionState::Connecting,
                        "Handshaking" => SessionState::Handshaking,
                        "NatTraversal" => SessionState::NatTraversal,
                        "Connected" => SessionState::Connected,
                        "Disconnecting" => SessionState::Disconnecting,
                        other => SessionState::Failed(other.to_string()),
                    };
                    let _ = tx.send(GuiEvent::UpdateSessionState(state));
                }
                if let Some(ip) = result.get("virtual_ip").and_then(|v| v.as_str()) {
                    let _ = tx.send(GuiEvent::UpdateIp(ip.to_string()));
                }
            }
            if let Ok(result) = client.call("peer.list", serde_json::json!({})).await {
                if let Some(peers_val) = result.get("peers").and_then(|v| v.as_array()) {
                    let peers: Vec<PeerInfo> = peers_val.iter().filter_map(parse_peer_info).collect();
                    let _ = tx.send(GuiEvent::UpdatePeers(peers));
                }
            }
        });
    }

    fn do_connect(&mut self, name: String, password: Option<String>, ip: String) {
        if name.is_empty() {
            return;
        }
        self.network_name = Some(name.clone());
        self.network_expanded = true;
        self.virtual_ip = ip.clone();
        self.session_state = SessionState::Connecting;
        self.last_connect = Some((name.clone(), password.clone(), ip.clone()));

        // Remember everything so the next click is one-press connect
        save_persisted(&Persisted {
            nickname: self.nickname.clone(),
            network: name.clone(),
            password: password.clone().unwrap_or_default(),
            virtual_ip: ip.clone(),
        });

        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let mut client = IpcClient::new(ClientConfig::default());
            if client.connect().await.is_err() {
                let _ = tx.send(GuiEvent::UpdateSessionState(SessionState::Failed(
                    "daemon indisponível".into(),
                )));
                return;
            }
            let params = serde_json::json!({
                "name": name,
                "password": password,
                "virtual_ip": ip,
            });
            if client.call("session.create", params).await.is_err() {
                let _ = tx.send(GuiEvent::UpdateSessionState(SessionState::Failed(
                    "session.create falhou".into(),
                )));
                return;
            }
            let _ = client.call("session.initialize", serde_json::json!({})).await;
            let _ = client.call("session.connect", serde_json::json!({})).await;
        });
    }

    fn do_disconnect(&mut self) {
        self.session_state = SessionState::Disconnecting;
        tokio::spawn(async move {
            let mut client = IpcClient::new(ClientConfig::default());
            if client.connect().await.is_ok() {
                let _ = client.call("session.disconnect", serde_json::json!({})).await;
            }
        });
    }

    fn do_power_toggle(&mut self) {
        if self.is_online() || !matches!(self.session_state, SessionState::Disconnected) {
            self.do_disconnect();
        } else if let Some((name, password, ip)) = self.last_connect.clone() {
            self.do_connect(name, password, ip);
        } else {
            self.dialog_join = true;
        }
    }
    fn do_remove_peer(&self, peer_id: String) {
        tokio::spawn(async move {
            let mut client = IpcClient::new(ClientConfig::default());
            if client.connect().await.is_ok() {
                let _ = client
                    .call("peer.remove", serde_json::json!({ "peer_id": peer_id }))
                    .await;
            }
        });
    }

    fn handle_event(&mut self, event: GuiEvent) {
        match event {
            GuiEvent::RefreshState => self.spawn_refresh(),
            GuiEvent::UpdatePeers(peers) => self.peers = peers,
            GuiEvent::UpdateSessionState(state) => self.session_state = state,
            GuiEvent::UpdateIp(ip) => {
                if !ip.is_empty() {
                    self.virtual_ip = ip;
                }
            }
        }
    }

    // ---- Title bar (frameless) ----

    fn render_title_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("title_bar")
            .exact_height(34.0)
            .frame(
                egui::Frame::none()
                    .fill(BG_TITLE)
                    .inner_margin(egui::Margin::symmetric(10.0, 0.0)),
            )
            .show(ctx, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    draw_logo(ui);
                    ui.add_space(4.0);
                    ui.label(RichText::new("VNET").size(17.0).strong().color(ACCENT));
                    ui.label(RichText::new("VPN").size(17.0).strong().color(TEXT));

                    // Drag area
                    let (_, drag) = ui.allocate_exact_size(
                        Vec2::new((ui.available_width() - 64.0).max(10.0), 30.0),
                        Sense::drag(),
                    );
                    if drag.drag_started() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                    }

                    if ui
                        .add_sized([26.0, 22.0], egui::Button::new(RichText::new("–").color(MUTED)))
                        .clicked()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                    if ui
                        .add_sized([26.0, 22.0], egui::Button::new(RichText::new("×").color(MUTED)))
                        .clicked()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
    }

    // ---- Menu bar: Sistema / Rede / Ajuda ----

    fn render_menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar")
            .exact_height(26.0)
            .frame(egui::Frame::none().fill(BG_MAIN).inner_margin(egui::Margin::symmetric(6.0, 0.0)))
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("Sistema", |ui| {
                        if ui.button("Alterar nome").clicked() {
                            self.rename_buf = self.nickname.clone();
                            self.dialog_rename = true;
                            ui.close_menu();
                        }
                        ui.menu_button("Exceções do firewall ▸", |ui| {
                            if ui.button("Permitir todos os aplicativos").clicked() {
                                self.dialog_firewall = true;
                                ui.close_menu();
                            }
                            if ui.button("Adicionar aplicação").clicked() {
                                self.dialog_firewall = true;
                                ui.close_menu();
                            }
                        });
                        if ui.button("Configurações").clicked() {
                            self.dialog_settings = true;
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Sair").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("Rede", |ui| {
                        ui.horizontal(|ui| {
                            if ui.button("Criar rede").clicked() {
                                self.dialog_create = true;
                                ui.close_menu();
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.weak("Ins");
                            });
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Conectar à rede").clicked() {
                                self.dialog_join = true;
                                ui.close_menu();
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.weak("+");
                            });
                        });
                    });
                    ui.menu_button("Ajuda", |ui| {
                        if ui.button("Sobre o VNet VPN").clicked() {
                            self.dialog_about = true;
                            ui.close_menu();
                        }
                    });
                });
            });
    }

    // ---- Main area: profile card + network list ----

    fn render_main(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG_MAIN)
                    .inner_margin(egui::Margin::same(8.0)),
            )
            .show(ctx, |ui| {
                self.render_profile_card(ui);
                ui.add_space(6.0);
                self.render_networks(ui);
            });
    }

    fn render_profile_card(&mut self, ui: &mut egui::Ui) {
        let online = self.is_online();
        egui::Frame::none()
            .fill(BG_PANEL)
            .rounding(Rounding::same(6.0))
            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    self.power_button(ui, online);
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.add_space(2.0);
                        ui.label(RichText::new(&self.nickname).size(18.0).strong().color(ACCENT));
                        ui.add_space(1.0);
                        ui.label(RichText::new(&self.virtual_ip).size(15.0).strong().color(TEXT));
                        ui.add_space(4.0);
                        self.status_pill(ui, online);
                    });
                });
            });
    }

    fn power_button(&mut self, ui: &mut egui::Ui, online: bool) {
        let (rect, resp) = ui.allocate_exact_size(Vec2::splat(56.0), Sense::click());
        let p = ui.painter_at(rect);
        let c = rect.center();
        let base = if online { ACCENT } else { ORANGE };
        let base = if resp.hovered() { base.linear_multiply(1.25) } else { base };
        let inner = base.linear_multiply(0.55);

        p.circle_filled(c, 27.0, base);
        p.circle_filled(c, 21.0, inner);

        if online {
            p.text(
                c,
                egui::Align2::CENTER_CENTER,
                "ON",
                egui::FontId::proportional(15.0),
                Color32::WHITE,
            );
        } else {
            let stroke = Stroke::new(2.6, Color32::WHITE);
            p.circle_stroke(c + Vec2::new(0.0, 3.5), 8.0, stroke);
            p.line_segment(
                [c + Vec2::new(0.0, -11.0), c + Vec2::new(0.0, 2.5)],
                stroke,
            );
        }
        if resp.clicked() {
            self.do_power_toggle();
        }
        resp.on_hover_text(if online { "Desligar VPN" } else { "Ligar VPN" });
    }

    fn status_pill(&mut self, ui: &mut egui::Ui, online: bool) {
        let (label, fg) = if online { ("Online", ACCENT) } else { ("Off-line", ORANGE) };
        egui::Frame::none()
            .fill(fg.linear_multiply(0.22))
            .rounding(Rounding::same(10.0))
            .inner_margin(egui::Margin::symmetric(10.0, 2.0))
            .show(ui, |ui| {
                ui.label(RichText::new(label).size(13.0).strong().color(fg));
            });
    }

    fn render_networks(&mut self, ui: &mut egui::Ui) {
        let name = match &self.network_name {
            Some(n) => n.clone(),
            None => return, // offline: empty area
        };
        let expanded = self.network_expanded;

        egui::Frame::none()
            .fill(BG_PANEL)
            .rounding(Rounding::same(6.0))
            .inner_margin(egui::Margin::symmetric(8.0, 6.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Expand/collapse triangle
                    let (r, resp) = ui.allocate_exact_size(Vec2::new(14.0, 16.0), Sense::click());
                    let p = ui.painter_at(r);
                    let c = r.center();
                    let color = if resp.hovered() { TEXT } else { MUTED };
                    let pts = if expanded {
                        vec![pos2(c.x - 4.0, c.y - 3.0), pos2(c.x + 4.0, c.y - 3.0), pos2(c.x, c.y + 4.0)]
                    } else {
                        vec![pos2(c.x - 3.0, c.y - 4.0), pos2(c.x - 3.0, c.y + 4.0), pos2(c.x + 4.0, c.y)]
                    };
                    p.add(egui::Shape::convex_polygon(pts, color, Stroke::NONE));
                    if resp.clicked() {
                        self.network_expanded = !self.network_expanded;
                    }

                    ui.label(RichText::new(&name).size(14.0).strong().color(TEXT));

                    // Chat bubble (decorative for now)
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (cr, cres) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::click());
                        draw_chat_bubble(&ui.painter_at(cr), cr.center());
                        cres.on_hover_text("Chat (em breve)");
                    });
                });

                if expanded {
                    ui.add_space(2.0);
                    if self.peers.is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new("Nenhum membro na rede").size(12.0).color(MUTED));
                    }
                    for peer in self.peers.clone() {
                        self.member_row(ui, &peer);
                    }
                }
            });
    }

    fn member_row(&mut self, ui: &mut egui::Ui, peer: &PeerInfo) {
        let id_hex = hex::encode(&peer.session_id[..]);
        let short = if id_hex.len() > 8 { &id_hex[..8] } else { &id_hex[..] };
        let node = format!("PC-{}", short.to_uppercase());
        let ip = peer.virtual_ip.to_string();
        let state_ok = matches!(peer.state, PeerState::Connected);

        ui.horizontal(|ui| {
            if ui
                .add_sized(
                    [16.0, 16.0],
                    egui::Button::new(RichText::new("×").size(10.0).color(MUTED)),
                )
                .on_hover_text("Remover membro")
                .clicked()
            {
                self.do_remove_peer(id_hex);
            }
            ui.label(RichText::new(node).size(12.0).color(if state_ok { TEXT } else { MUTED }));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(ip).size(12.0).color(MUTED));
            });
        });
        ui.add_space(2.0);
    }

    // ---- Dialogs ----

    fn render_dialogs(&mut self, ctx: &egui::Context) {
        if self.dialog_join {
            egui::Window::new(RichText::new("Conectar à rede").strong())
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    egui::Grid::new("join_grid").num_columns(2).spacing([8.0, 8.0]).show(ui, |ui| {
                        ui.label("Nome da rede:");
                        ui.text_edit_singleline(&mut self.join_network);
                        ui.end_row();
                        ui.label("Senha:");
                        ui.add(egui::TextEdit::singleline(&mut self.join_password).password(true));
                        ui.end_row();
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Conectar").strong().color(ACCENT)).clicked() {
                            let pw = if self.join_password.is_empty() { None } else { Some(self.join_password.clone()) };
                            self.do_connect(self.join_network.clone(), pw, self.virtual_ip.clone());
                            self.dialog_join = false;
                        }
                        if ui.button("Cancelar").clicked() {
                            self.dialog_join = false;
                        }
                    });
                });
        }

        if self.dialog_create {
            egui::Window::new(RichText::new("Criar rede").strong())
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    egui::Grid::new("create_grid").num_columns(2).spacing([8.0, 8.0]).show(ui, |ui| {
                        ui.label("Nome da rede:");
                        ui.text_edit_singleline(&mut self.create_network);
                        ui.end_row();
                        ui.label("Senha:");
                        ui.add(egui::TextEdit::singleline(&mut self.create_password).password(true));
                        ui.end_row();
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Criar").strong().color(ACCENT)).clicked() {
                            let pw = if self.create_password.is_empty() { None } else { Some(self.create_password.clone()) };
                            self.do_connect(self.create_network.clone(), pw, self.virtual_ip.clone());
                            self.dialog_create = false;
                        }
                        if ui.button("Cancelar").clicked() {
                            self.dialog_create = false;
                        }
                    });
                });
        }

        if self.dialog_rename {
            egui::Window::new(RichText::new("Alterar nome").strong())
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Nome exibido no perfil:");
                    ui.text_edit_singleline(&mut self.rename_buf);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Salvar").clicked() {
                            let new = self.rename_buf.trim().to_string();
                            if !new.is_empty() {
                                self.nickname = new;
                                save_persisted(&Persisted {
                                    nickname: self.nickname.clone(),
                                    network: self.last_connect.as_ref().map(|(n, _, _)| n.clone()).unwrap_or_default(),
                                    password: self.last_connect.as_ref().and_then(|(_, p, _)| p.clone()).unwrap_or_default(),
                                    virtual_ip: self.virtual_ip.clone(),
                                });
                            }
                            self.dialog_rename = false;
                        }
                        if ui.button("Cancelar").clicked() {
                            self.dialog_rename = false;
                        }
                    });
                });
        }

        if self.dialog_settings {
            egui::Window::new(RichText::new("Configurações").strong())
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new("Criptografia").strong().color(ACCENT));
                    ui.label("AEAD: ChaCha20-Poly1305, AES-256-GCM");
                    ui.label("Troca de chaves: ECDH P-256");
                    ui.label("Derivação: HKDF-SHA256");
                    ui.separator();
                    ui.label(RichText::new("Rede").strong().color(ACCENT));
                    ui.label("NAT: STUN + ICE");
                    ui.label("STUN: stun.l.google.com:19302");
                    ui.label("MTU: 1400 · Keepalive: 30s");
                });
        }

        if self.dialog_about {
            egui::Window::new(RichText::new("Sobre").strong())
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        draw_logo(ui);
                        ui.label(RichText::new("VNet VPN").size(18.0).strong().color(ACCENT));
                    });
                    ui.add_space(4.0);
                    ui.label("VPN open-source escrita em Rust.");
                    ui.label("Protocolo v2 · ECDH P-256 · AEAD · ICE/STUN");
                    ui.label(RichText::new("v0.1.0").color(MUTED));
                });
        }

        if self.dialog_firewall {
            egui::Window::new(RichText::new("Exceções do firewall").strong())
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Para permitir o tráfego do VNet VPN no firewall do Windows:");
                    ui.add_space(2.0);
                    ui.label("1. Abra o Painel de Controle → Firewall do Windows");
                    ui.label("2. Permitir um aplicativo pelo firewall");
                    ui.label("3. Adicione vnet.exe e vnet-gui.exe");
                    ui.add_space(2.0);
                    ui.label(RichText::new("Integração automática com o firewall chegará em breve.")
                        .color(MUTED));
                });
        }
    }
}

// ---- Helpers ----

fn apply_style(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG_MAIN;
    v.window_fill = BG_PANEL;
    v.override_text_color = Some(TEXT);
    v.widgets.noninteractive.bg_fill = BG_PANEL;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.inactive.bg_fill = BG_PANEL;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.hovered.bg_fill = BG_PANEL.linear_multiply(1.25);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    v.widgets.active.bg_fill = BG_PANEL.linear_multiply(0.85);
    v.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    v.selection.bg_fill = ACCENT.linear_multiply(0.4);
    ctx.set_visuals(v);
}

fn draw_logo(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(20.0, 22.0), Sense::hover());
    let p = ui.painter_at(rect);
    let (x, y) = (rect.min.x, rect.min.y);
    let pts = vec![
        pos2(x + 1.0, y + 2.0),
        pos2(x + 19.0, y + 2.0),
        pos2(x + 19.0, y + 11.0),
        pos2(x + 10.0, y + 21.0),
        pos2(x + 1.0, y + 11.0),
    ];
    p.add(egui::Shape::convex_polygon(pts, ACCENT, Stroke::NONE));
    p.add(egui::Shape::line(
        vec![pos2(x + 5.0, y + 10.5), pos2(x + 9.0, y + 14.5), pos2(x + 15.5, y + 5.5)],
        Stroke::new(2.2, BG_TITLE),
    ));
}

fn draw_chat_bubble(p: &egui::Painter, center: egui::Pos2) {
    let rect = egui::Rect::from_center_size(center, Vec2::new(15.0, 12.0));
    let stroke = Stroke::new(1.2, MUTED);
    p.rect(rect, Rounding::same(5.0), Color32::TRANSPARENT, stroke);
    p.line_segment(
        [pos2(rect.min.x + 3.0, rect.max.y - 1.0), pos2(rect.min.x + 0.5, rect.max.y + 3.0)],
        stroke,
    );
    for dx in [-3.5f32, 0.0, 3.5] {
        p.circle_filled(center + Vec2::new(dx, 0.0), 1.2, MUTED);
    }
}

fn parse_peer_info(value: &serde_json::Value) -> Option<PeerInfo> {
    let session_id_str = value.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
    let virtual_ip = value.get("virtual_ip")?.as_str()?.parse().ok()?;
    let state_str = value.get("state")?.as_str()?;
    let state = match state_str {
        "Handshaking" => PeerState::Handshaking,
        "Connected" => PeerState::Connected,
        "Disconnected" => PeerState::Disconnected,
        "Reconnecting" => PeerState::Reconnecting,
        "Blocked" => PeerState::Blocked,
        _ => PeerState::Disconnected,
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

    let session_id = if let Ok(bytes) = hex::decode(session_id_str) {
        let mut arr = [0u8; 16];
        let len = bytes.len().min(16);
        arr[..len].copy_from_slice(&bytes[..len]);
        arr
    } else {
        [0u8; 16]
    };

    Some(PeerInfo {
        session_id,
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
