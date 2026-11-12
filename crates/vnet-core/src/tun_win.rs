//! TUN no Windows via Wintun (camada 3, IP puro).
//!
//! Diferente de `vnet-tun`, esta implementação:
//!  - configura o endereço IP da interface (o driver sozinho não configura);
//!  - lê pacotes com `receive_blocking` numa thread dedicada, sem busy-loop;
//!  - expõe `send` livre de async, para uso direto no loop do túnel.

#![cfg(windows)]

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc::UnboundedSender;

pub const ADAPTER_NAME: &str = "VNET";

/// Executa um comando sem abrir janela de console.
fn run_quiet(exe: &str, args: &[&str]) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Marca o adaptador VNET como rede Privada.
///
/// Sem isso o Windows trata a interface nova como Pública e o firewall
/// bloqueia o tráfego entre os pares — o Minecraft não enxerga a LAN.
pub fn ensure_private_profile(alias: &str) {
    let alias = alias.to_string();
    std::thread::Builder::new()
        .name("vnet-netprofile".into())
        .spawn(move || {
            let script = format!(
                "try {{ Set-NetConnectionProfile -InterfaceAlias '{alias}' \
                 -NetworkCategory Private -ErrorAction Stop }} catch {{ \
                 Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ \
                 $_.InterfaceDescription -like 'VNET*' }} | ForEach-Object {{ \
                 Set-NetConnectionProfile -InterfaceIndex $_.ifIndex \
                 -NetworkCategory Private -ErrorAction SilentlyContinue }} }}"
            );
            let ok = run_quiet(
                "powershell",
                &["-NoProfile", "-NonInteractive", "-Command", &script],
            );
            tracing::info!("perfil de rede da interface {alias}: privado={ok}");
        })
        .ok();
}

/// Libera as portas do túnel no firewall do Windows (idempotente).
///
/// Só tem efeito quando o processo está elevado; caso contrário o `netsh`
/// falha e o app segue (o usuário pode liberar manualmente).
pub fn ensure_firewall_rules() {
    static ONCE: AtomicBool = AtomicBool::new(false);
    if ONCE.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::Builder::new()
        .name("vnet-firewall".into())
        .spawn(|| {
            for (name, port) in [("VNET VPN (UDP)", "7000-7100"), ("VNET LAN (UDP)", "4445")] {
                // Remove a versão antiga para manter a regra sempre atualizada.
                let _ = run_quiet(
                    "netsh",
                    &["advfirewall", "firewall", "delete", "rule", &format!("name={name}")],
                );
                let ok = run_quiet(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={name}"),
                        "dir=in",
                        "action=allow",
                        "protocol=UDP",
                        &format!("localport={port}"),
                        "profile=any",
                    ],
                );
                tracing::info!("regra de firewall {name}: {ok}");
            }
        })
        .ok();
}

/// Handle de escrita + leitura do adaptador Wintun.
pub struct TunHandle {
    session: Arc<wintun::Session>,
    _adapter: Arc<wintun::Adapter>,
    _wintun: wintun::Wintun,
    pub name: String,
    pub ip: Ipv4Addr,
    stop: Arc<AtomicBool>,
}

impl TunHandle {
    /// Cria (ou reabre) o adaptador e aplica IP/máscara. Requer Administrador.
    pub fn create(ip: Ipv4Addr, mtu: u16) -> anyhow::Result<TunHandle> {
        let wintun = unsafe { wintun::load() }
            .map_err(|e| anyhow::anyhow!("wintun.dll não encontrada: {e}"))?;

        let adapter = match wintun::Adapter::create(&wintun, ADAPTER_NAME, "VNET", None) {
            Ok(a) => a,
            Err(e) => anyhow::bail!("criar adaptador Wintun: {e}"),
        };

        adapter.set_mtu(mtu as usize).ok();

        let name = adapter.get_name().unwrap_or_else(|_| ADAPTER_NAME.to_string());

        // 10.144.0.0/24 — fora de outras faixas de VPN de malha (25/8, 26/8),
        // CGNAT (100.64/10) e das LANs domésticas comuns.
        // `netsh` sem console (o processo é GUI) evita o flash de janela preta
        // que o helper do crate provocaria.
        let mask = "255.255.255.0";
        let quiet = run_quiet(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "address",
                &format!("name={name}"),
                "source=static",
                &format!("address={ip}"),
                &format!("mask={mask}"),
            ],
        );
        if !quiet {
            // Fallback: helper do próprio crate (pode piscar um console).
            let mask_ip = Ipv4Addr::new(255, 255, 255, 0);
            if let Err(e) =
                adapter.set_network_addresses_tuple(IpAddr::V4(ip), IpAddr::V4(mask_ip), None)
            {
                tracing::warn!("falha ao aplicar IP {ip} em {name}: {e}");
            }
        }

        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| anyhow::anyhow!("iniciar sessão Wintun: {e}"))?,
        );

        // Interface nova nasce como "Pública" — o firewall barraria a LAN.
        ensure_private_profile(&name);

        Ok(TunHandle {
            session,
            _adapter: adapter,
            _wintun: wintun,
            name,
            ip,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Injeta um pacote IP na pilha do Windows.
    pub fn send(&self, packet: &[u8]) {
        if packet.is_empty() || packet.len() > u16::MAX as usize {
            return;
        }
        match self.session.allocate_send_packet(packet.len() as u16) {
            Ok(mut p) => {
                p.bytes_mut().copy_from_slice(packet);
                self.session.send_packet(p);
            }
            Err(e) => tracing::warn!("TUN write falhou: {e}"),
        }
    }

    /// Thread dedicada de leitura: cada pacote IP sai pelo canal.
    pub fn spawn_reader(self: &Arc<Self>, tx: UnboundedSender<Vec<u8>>) {
        let session = self.session.clone();
        let stop = self.stop.clone();
        std::thread::Builder::new()
            .name("vnet-tun-read".into())
            .spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match session.receive_blocking() {
                    Ok(pkt) => {
                        if tx.send(pkt.bytes().to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        // Sessão encerrada (desconexão) — sai do loop.
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            })
            .ok();
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
