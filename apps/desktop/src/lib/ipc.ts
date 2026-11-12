/**
 * Camada de comunicação com o backend Tauri (Rust).
 * Comandos: connect, disconnect, get_state, list_peers, ping_peer,
 * remove_peer, set_close_to_tray, quit_app.
 */
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { Peer, RoomInfo } from "../types";

export const appWindow = getCurrentWindow();

export const ipc = {
  /**
   * Entra na rede. `code` vazio = abrir a rede (ficar em espera);
   * preenchido (`IP:PORTA` de um membro) = conectar a ele na hora.
   */
  connect: (name: string, password: string | null, code: string | null) =>
    invoke<void>("connect", { name, password, code }),

  disconnect: () => invoke<void>("disconnect"),

  getState: () =>
    invoke<{
      state: string;
      hostname: string;
      code: string | null;
      publicEndpoint: string | null;
      localEndpoint: string | null;
      role: string;
      room: string | null;
      mapped: boolean;
      tunReady: boolean;
      virtualIp: string | null;
      error: string | null;
    }>("get_state"),

  listPeers: () => invoke<Peer[]>("list_peers"),

  pingPeer: (peerId: string) => invoke<void>("ping_peer", { peerId }),

  removePeer: (peerId: string) => invoke<void>("remove_peer", { peerId }),

  setCloseToTray: (enabled: boolean) =>
    invoke<void>("set_close_to_tray", { enabled }),

  /** Sai do processo de verdade (o menu Sistema → Sair usa isto) */
  quitApp: () => invoke<void>("quit_app"),
};

/** Estado da sessão (evento + tick do backend) */
export function listenState(
  cb: (state: { state: string; tunReady?: boolean; virtualIp?: string | null }) => void
): Promise<UnlistenFn> {
  return listen<{ state: string; tunReady?: boolean; virtualIp?: string | null }>(
    "vnet://state",
    (e) => cb(e.payload)
  );
}

/** Lista de membros do túnel */
export function listenPeers(
  cb: (peers: Peer[]) => void
): Promise<UnlistenFn> {
  return listen<{ peers: Peer[] }>("vnet://peers", (e) => cb(e.payload.peers));
}

/** Código de convite, papel (`mesh`) e estado do mapeamento UPnP */
export function listenRoom(
  cb: (room: RoomInfo) => void
): Promise<UnlistenFn> {
  return listen<RoomInfo>("vnet://room", (e) => cb(e.payload));
}

/** Linhas de diagnóstico do túnel (TUN, UPnP, STUN) */
export function listenLog(cb: (msg: string) => void): Promise<UnlistenFn> {
  return listen<{ message: string }>("vnet://log", (e) =>
    cb(e.payload.message)
  );
}

/** Evento de erro do backend (panic, falha de conexão, etc) */
export function listenError(
  cb: (err: { source: string; message: string }) => void
): Promise<UnlistenFn> {
  return listen<{ source: string; message: string }>("vnet://error", (e) =>
    cb(e.payload)
  );
}
