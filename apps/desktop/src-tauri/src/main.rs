#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! VNET VPN — Desktop (Tauri 2)
//!
//! O backend é o túnel de malha (`vnet_core::p2p`):
//!   * a rede é definida por **nome + senha** — não existe servidor nem dono;
//!   * cada PC deriva o próprio IP virtual (`10.144.0.X`) de um id persistente;
//!   * quem entra com um código `IP:PORTA` troca HELLO com esse membro e
//!     descobre os demais por gossip, conectando-se direto a eles;
//!   * todo membro gera código de convite (UPnP/STUN best-effort) e repassa
//!     pacotes de quem não é vizinho direto;
//!   * todo tráfego IP passa cifrado (ChaCha20-Poly1305) entre as máquinas.
//!
//! O adaptador TUN exige Administrador. Quando o app não está elevado, o
//! comando `connect` grava os dados em `%LOCALAPPDATA%\vnet\pending.json`,
//! relança o próprio exe via `runas` e encerra — a instância elevada lê o
//! arquivo com `--autoconnect` e conecta sozinha.

use std::net::SocketAddr;
use std::panic;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use vnet_core::p2p::{Event, P2pConfig, Role, Snapshot, Tunnel};

// ---------------------------------------------------------------------------
// Estado
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pending {
    name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    code: String,
}

struct AppState {
    tunnel: Mutex<Option<Arc<Tunnel>>>,
    last: Mutex<Option<Pending>>,
    close_to_tray: Mutex<bool>,
}

impl AppState {
    fn new() -> Self {
        Self {
            tunnel: Mutex::new(None),
            last: Mutex::new(None),
            close_to_tray: Mutex::new(false),
        }
    }

    fn snapshot(&self) -> Snapshot {
        match self.tunnel.lock().unwrap().as_ref() {
            Some(t) => {
                let mut s = t.snapshot();
                if s.state.is_empty() {
                    s.state = "Disconnected".into();
                }
                s
            }
            None => Snapshot {
                state: "Disconnected".into(),
                ..Default::default()
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Emissão de eventos para o frontend
// ---------------------------------------------------------------------------

fn emit_snapshot(app: &AppHandle, s: &Snapshot) {
    let _ = app.emit(
        "vnet://state",
        serde_json::json!({
            "state": s.state,
            "error": s.error,
            "virtualIp": s.virtual_ip,
            "tunReady": s.tun_ready,
        }),
    );

    let peers: Vec<serde_json::Value> = s
        .peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "virtualIp": p.ip,
                "state": "Connected",
                "endpoint": p.endpoint,
                "rttMs": p.rtt_ms,
                "isHost": p.is_host,
            })
        })
        .collect();
    let _ = app.emit("vnet://peers", serde_json::json!({ "peers": peers }));

    let _ = app.emit(
        "vnet://room",
        serde_json::json!({
            "code": s.code,
            "publicEndpoint": s.public_endpoint,
            "localEndpoint": s.local_endpoint,
            "mapped": s.mapped,
            "role": s.role,
            "room": s.room,
            "virtualIp": s.virtual_ip,
            "state": s.state,
        }),
    );

    if let Some(err) = &s.error {
        let _ = app.emit(
            "vnet://error",
            serde_json::json!({ "source": "tunnel", "message": err }),
        );
    }
}

/// Consome os eventos do túnel e mantém a UI sincronizada.
fn spawn_monitor(app: AppHandle, tunnel: Arc<Tunnel>) {
    tauri::async_runtime::spawn(async move {
        let mut last = Instant::now();
        loop {
            let tick = tokio::time::sleep(Duration::from_millis(600));
            tokio::pin!(tick);

            tokio::select! {
                ev = tunnel.next_event() => {
                    match ev {
                        Some(Event::Snapshot(s)) => {
                            emit_snapshot(&app, &s);
                            last = Instant::now();
                            if s.state == "Disconnected" || s.state == "Failed" {
                                break;
                            }
                        }
                        Some(Event::Log(line)) => {
                            eprintln!("vnet: {line}");
                            let _ = app.emit("vnet://log", serde_json::json!({ "message": line }));
                        }
                        None => break,
                    }
                }
                _ = &mut tick => {
                    if last.elapsed() >= Duration::from_millis(500) {
                        emit_snapshot(&app, &tunnel.snapshot());
                        last = Instant::now();
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Elevação / instância elevada
// ---------------------------------------------------------------------------

fn pending_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    let mut p = PathBuf::from(base);
    p.push("vnet");
    Some(p.join("pending.json"))
}

fn write_pending(p: &Pending) -> Result<(), String> {
    let path = pending_path().ok_or("LOCALAPPDATA não definido")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec(p).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

fn read_pending() -> Option<Pending> {
    let path = pending_path()?;
    let bytes = std::fs::read(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    serde_json::from_slice(&bytes).ok()
}

#[cfg(windows)]
fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(windows)]
fn relaunch_elevated() -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let verb = wide(std::ffi::OsStr::new("runas"));
    let file = wide(exe.as_os_str());
    let params = wide(std::ffi::OsStr::new("--autoconnect"));

    let rc = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if rc as isize <= 32 {
        Err(format!("elevação recusada (código {})", rc as isize))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Núcleo da conexão
// ---------------------------------------------------------------------------

fn start_tunnel(app: AppHandle, state: &AppState, p: Pending) -> Result<(), String> {
    if let Some(t) = state.tunnel.lock().unwrap().as_ref() {
        let s = t.snapshot();
        if s.state == "Connected" || s.state == "Waiting" || s.state == "Connecting" {
            return Err("Já existe uma sessão ativa".into());
        }
    }

    let role = if p.code.trim().is_empty() {
        Role::Host
    } else {
        let host: SocketAddr = p
            .code
            .trim()
            .parse()
            .map_err(|_| "Código inválido — use IP:PORTA (ex.: 201.10.0.5:7000)".to_string())?;
        Role::Join { host }
    };

    let cfg = P2pConfig {
        room: p.name.clone(),
        password: p.password.clone(),
        role,
        mtu: 1400,
        node_id: None,
    };

    let tunnel = Arc::new(Tunnel::start(cfg).map_err(|e| format!("{e:#}"))?);
    *state.tunnel.lock().unwrap() = Some(tunnel.clone());
    *state.last.lock().unwrap() = Some(p);
    spawn_monitor(app, tunnel);
    Ok(())
}

// ---------------------------------------------------------------------------
// Comandos
// ---------------------------------------------------------------------------

#[tauri::command]
async fn connect(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    name: String,
    password: Option<String>,
    code: Option<String>,
) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Nome da rede é obrigatório".into());
    }
    let pending = Pending {
        name,
        password: password.unwrap_or_default(),
        code: code.unwrap_or_default().trim().to_string(),
    };
    *state.last.lock().unwrap() = Some(pending.clone());

    // TUN precisa de Administrador; eleva e reabre com --autoconnect.
    #[cfg(windows)]
    {
        if !is_elevated() && std::env::var_os("VNET_NO_ELEVATE").is_none() {
            write_pending(&pending)?;
            relaunch_elevated()?;
            std::process::exit(0);
        }
    }

    start_tunnel(app, &state, pending)
}

#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    if let Some(t) = state.tunnel.lock().unwrap().as_ref() {
        t.disconnect();
    }
    Ok(())
}

#[tauri::command]
async fn get_state(state: tauri::State<'_, AppState>) -> Result<serde_json::Value, String> {
    let snap = state.snapshot();
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".into());
    Ok(serde_json::json!({
        "state": snap.state,
        "hostname": hostname,
        "code": snap.code,
        "publicEndpoint": snap.public_endpoint,
        "localEndpoint": snap.local_endpoint,
        "role": snap.role,
        "room": snap.room,
        "mapped": snap.mapped,
        "tunReady": snap.tun_ready,
        "virtualIp": snap.virtual_ip,
        "error": snap.error,
    }))
}

#[tauri::command]
async fn list_peers(state: tauri::State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let snap = state.snapshot();
    Ok(snap
        .peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "virtualIp": p.ip,
                "state": "Connected",
                "endpoint": p.endpoint,
                "rttMs": p.rtt_ms,
                "isHost": p.is_host,
            })
        })
        .collect())
}

#[tauri::command]
async fn ping_peer(state: tauri::State<'_, AppState>, peer_id: String) -> Result<(), String> {
    if let Some(t) = state.tunnel.lock().unwrap().as_ref() {
        t.ping(&peer_id);
    }
    Ok(())
}

#[tauri::command]
async fn remove_peer(_peer_id: String) -> Result<(), String> {
    // A rede é a malha inteira; remover é só uma ação local da lista.
    Ok(())
}

#[tauri::command]
fn set_close_to_tray(state: tauri::State<'_, AppState>, enabled: bool) -> Result<(), String> {
    *state.close_to_tray.lock().unwrap() = enabled;
    Ok(())
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("panic desconhecido");
        let location = info.location().map(|l| l.to_string()).unwrap_or_default();
        eprintln!("vnet-desktop: PANIC: {msg} at {location}");
    }));

    let autoconnect = std::env::args().any(|a| a == "--autoconnect");

    tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            get_state,
            list_peers,
            ping_peer,
            remove_peer,
            set_close_to_tray,
            quit_app
        ])
        .setup(move |app| {
            let app_handle = app.handle().clone();

            if autoconnect {
                if let Some(pending) = read_pending() {
                    let handle = app_handle.clone();
                    let state = app.state::<AppState>();
                    let result = start_tunnel(handle, &state, pending);
                    if let Err(e) = result {
                        eprintln!("vnet-desktop: autoconnect: {e}");
                        let _ = app_handle.emit(
                            "vnet://error",
                            serde_json::json!({ "source": "autoconnect", "message": e }),
                        );
                    }
                }
            }

            // Bandeja do sistema
            let menu = tauri::menu::Menu::with_items(
                app,
                &[
                    &tauri::menu::MenuItem::with_id(
                        app, "open", "Abrir VNET VPN", true, None::<&str>,
                    )?,
                    &tauri::menu::MenuItem::with_id(
                        app, "toggle", "Conectar / Desconectar", true, None::<&str>,
                    )?,
                    &tauri::menu::PredefinedMenuItem::separator(app)?,
                    &tauri::menu::MenuItem::with_id(app, "quit", "Sair", true, None::<&str>)?,
                ],
            )?;

            let _tray = tauri::tray::TrayIconBuilder::with_id("tray")
                .icon(app.default_window_icon().expect("ícone padrão").clone())
                .tooltip("VNET VPN")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "open" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "toggle" => {
                        let state = app.state::<AppState>();
                        let snap = state.snapshot();
                        match snap.state.as_str() {
                            "Connected" | "Waiting" | "Connecting" => {
                                if let Some(t) = state.tunnel.lock().unwrap().as_ref() {
                                    t.disconnect();
                                }
                            }
                            _ => {
                                let last = state.last.lock().unwrap().clone();
                                if let Some(p) = last {
                                    let app2 = app.clone();
                                    let _ = start_tunnel(app2, &state, p);
                                }
                            }
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let close_to_tray = *app.state::<AppState>().close_to_tray.lock().unwrap();
                if close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("erro ao rodar o VNET VPN");
}
