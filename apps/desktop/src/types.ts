/** Tipos compartilhados entre frontend e backend Tauri */

export type SessionStateName =
  | "Disconnected"
  | "Connecting"
  | "Waiting"
  | "Handshaking"
  | "NatTraversal"
  | "Connected"
  | "Disconnecting"
  | "Failed";

export interface Peer {
  /** id hex do peer (session_id) */
  id: string;
  virtualIp: string;
  state: string;
  endpoint: string | null;
  /** latência medida por PING/PONG, em ms */
  rttMs?: number | null;
  /** sempre `false` na malha (compatibilidade do JSON) */
  isHost?: boolean;
}

export interface RoomInfo {
  code: string | null;
  publicEndpoint?: string | null;
  localEndpoint?: string | null;
  mapped: boolean;
  role: "host" | "join" | string;
  /** nome da sala ativa (rede) */
  room?: string | null;
  virtualIp: string | null;
  state: string;
}

export type Lang = "pt-BR" | "en-US";

export interface Settings {
  /** TODO: requer tauri-plugin-autostart */
  startWithWindows: boolean;
  /** Wired: backend `set_close_to_tray` */
  closeToTray: boolean;
  theme: "dark" | "light"; // TODO: tema claro
  language: Lang;
}

export interface Toast {
  id: number;
  kind: "info" | "success" | "error";
  msg: string;
}
