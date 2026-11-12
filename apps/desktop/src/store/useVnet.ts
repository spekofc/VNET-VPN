/**
 * Estado global do app (Zustand).
 * Persistência local: perfil (nickname/rede/senha/IP) e configurações em localStorage.
 */
import { create } from "zustand";
import { ipc, listenPeers, listenState, listenError, listenRoom } from "../lib/ipc";
import { setLang, t } from "../lib/i18n";
import type { Lang, Peer, SessionStateName, Settings, Toast } from "../types";

const LS_PROFILE = "vnet.profile";
const LS_SETTINGS = "vnet.settings";

interface Persisted {
  nickname: string;
  lastNetwork: string | null;
  lastPassword: string | null;
  lastCode: string | null;
  virtualIp: string | null;
}

const defaultSettings: Settings = {
  startWithWindows: false, // TODO: tauri-plugin-autostart
  closeToTray: true,
  theme: "dark",
  language: "pt-BR",
};

function loadProfile(): Persisted {
  try {
    const raw = localStorage.getItem(LS_PROFILE);
    if (raw) {
      return { ...emptyProfile(), ...(JSON.parse(raw) as Partial<Persisted>) };
    }
  } catch {
    /* ignore */
  }
  return emptyProfile();
}

function emptyProfile(): Persisted {
  return {
    nickname: "", // preenchido pelo hostname vindo do backend no init
    lastNetwork: null,
    lastPassword: null,
    lastCode: null,
    virtualIp: null,
  };
}

function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(LS_SETTINGS);
    if (raw) {
      return { ...defaultSettings, ...(JSON.parse(raw) as Partial<Settings>) };
    }
  } catch {
    /* ignore */
  }
  return defaultSettings;
}

interface VnetStore {
  stateName: SessionStateName;
  peers: Peer[];
  nickname: string;
  lastNetwork: string | null;
  lastPassword: string | null;
  lastCode: string | null;
  /** Código `IP:PORTA` exibido para convidar (qualquer membro gera o seu) */
  roomCode: string | null;
  roomPublic: string | null;
  roomLocal: string | null;
  /** `mesh` — a rede não tem dono */
  roomRole: string | null;
  roomMapped: boolean;
  /** Adaptador virtual ativo (Wintun). Sem ele, o jogo não vê a rede. */
  tunReady: boolean;
  virtualIp: string | null;
  settings: Settings;
  connectedAt: number | null;
  expanded: boolean;
  search: string;
  dialog: null | "create" | "join" | "settings" | "about";
  renaming: boolean;
  toasts: Toast[];
  toastSeq: number;

  /** Registra listeners de eventos do backend; retorna cleanup p/ React */
  init: () => Promise<() => void>;
  connect: (name: string, password: string | null, code: string | null) => Promise<void>;
  disconnect: () => Promise<void>;
  toggleExpanded: () => void;
  setSearch: (s: string) => void;
  openDialog: (d: VnetStore["dialog"]) => void;
  closeDialog: () => void;
  setRenaming: (v: boolean) => void;
  rename: (n: string) => void;
  setCloseToTray: (v: boolean) => Promise<void>;
  setStartWithWindows: (v: boolean) => void;
  setLanguage: (l: Lang) => void;
  removePeer: (id: string) => Promise<void>;
  pingPeer: (id: string) => Promise<void>;
  toast: (kind: Toast["kind"], msg: string) => void;
  dismissToast: (id: number) => void;
}

function persistProfile(p: Partial<Persisted>) {
  const merged = { ...loadProfile(), ...p };
  localStorage.setItem(LS_PROFILE, JSON.stringify(merged));
}

function persistSettings(s: Settings) {
  localStorage.setItem(LS_SETTINGS, JSON.stringify(s));
}

export const useVnet = create<VnetStore>((set, get) => ({
  stateName: "Disconnected",
  peers: [],
  nickname: "",
  lastNetwork: null,
  lastPassword: null,
  lastCode: null,
  roomCode: null,
  roomPublic: null,
  roomLocal: null,
  roomRole: null,
  roomMapped: false,
  tunReady: false,
  virtualIp: loadProfile().virtualIp,
  settings: loadSettings(),
  connectedAt: null,
  expanded: true,
  search: "",
  dialog: null,
  renaming: false,
  toasts: [],
  toastSeq: 0,

  init: async () => {
    const st = loadSettings();
    setLang(st.language);
    set({
      settings: st,
      lastNetwork: loadProfile().lastNetwork,
      lastCode: loadProfile().lastCode,
    });
    void ipc.setCloseToTray(st.closeToTray).catch(() => {});

    const un1 = await listenState((st) => {
      set((prev) => ({
        stateName: st.state as SessionStateName,
        tunReady: st.tunReady ?? prev.tunReady,
        connectedAt:
          st.state === "Connected" || st.state === "Waiting"
            ? prev.connectedAt ?? Date.now()
            : null,
      }));
    });
    const un2 = await listenPeers((peers) => set({ peers }));
    const un3 = await listenError((err) => {
      get().toast("error", `${err.source}: ${err.message}`);
    });
    const un4 = await listenRoom((room) => {
      set((prev) => ({
        roomCode: room.code,
        roomPublic: room.publicEndpoint ?? null,
        roomLocal: room.localEndpoint ?? null,
        roomRole: room.role ?? "mesh",
        roomMapped: room.mapped,
        virtualIp: room.virtualIp ?? prev.virtualIp,
        // O backend é a fonte da verdade: se ele está numa sala, a UI mostra.
        lastNetwork: room.room || prev.lastNetwork,
      }));
    });

    // Estado inicial imediato (antes do primeiro tick do backend)
    try {
      const snap = await ipc.getState();
      set((prev) => ({
        stateName: snap.state as SessionStateName,
        nickname: prev.nickname || snap.hostname,
        roomCode: snap.code,
        roomPublic: snap.publicEndpoint,
        roomLocal: snap.localEndpoint,
        roomRole: snap.role ?? "mesh",
        roomMapped: snap.mapped,
        tunReady: snap.tunReady,
        virtualIp: snap.virtualIp ?? prev.virtualIp,
        lastNetwork: snap.room || prev.lastNetwork,
      }));
    } catch {
      /* backend ainda subindo */
    }
    try {
      set({ peers: await ipc.listPeers() });
    } catch {
      /* idem */
    }

    return () => {
      un1();
      un2();
      un3();
      un4();
    };
  },

  connect: async (name, password, code) => {
    set({
      stateName: "Connecting",
      dialog: null,
      expanded: true,
      roomCode: null,
    });
    try {
      await ipc.connect(name.trim(), password, code);
      set({
        lastNetwork: name.trim(),
        lastPassword: password,
        lastCode: code,
      });
      persistProfile({
        lastNetwork: name.trim(),
        lastPassword: password,
        lastCode: code,
      });
    } catch (e) {
      set({ stateName: "Failed" });
      get().toast("error", `${t("toast.connectError")}: ${String(e)}`);
    }
  },

  disconnect: async () => {
    set({ stateName: "Disconnecting" });
    try {
      await ipc.disconnect();
    } catch {
      /* o emit loop corrige o estado em 2s */
    }
  },

  toggleExpanded: () => set((s) => ({ expanded: !s.expanded })),
  setSearch: (search) => set({ search }),
  openDialog: (dialog) => set({ dialog }),
  closeDialog: () => set({ dialog: null }),
  setRenaming: (renaming) => set({ renaming }),

  rename: (n) => {
    const nickname = n.trim();
    if (!nickname) return;
    set({ nickname, renaming: false });
    persistProfile({ nickname });
  },

  setCloseToTray: async (v) => {
    const settings = { ...get().settings, closeToTray: v };
    set({ settings });
    persistSettings(settings);
    await ipc.setCloseToTray(v).catch(() => {});
  },

  setStartWithWindows: (v) => {
    const settings = { ...get().settings, startWithWindows: v };
    set({ settings });
    persistSettings(settings);
  },

  setLanguage: (l) => {
    const settings = { ...get().settings, language: l };
    set({ settings });
    persistSettings(settings);
    setLang(l);
    // força re-render geral dos componentes que usam t()
    set((s) => ({ toasts: [...s.toasts] }));
  },

  removePeer: async (id) => {
    try {
      await ipc.removePeer(id);
      get().toast("success", t("toast.removed"));
    } catch (e) {
      get().toast("error", String(e));
    }
  },

  pingPeer: async (id) => {
    try {
      await ipc.pingPeer(id);
      get().toast("info", "Ping enviado");
    } catch (e) {
      get().toast("error", String(e));
    }
  },

  toast: (kind, msg) => {
    const id = get().toastSeq + 1;
    set((s) => ({
      toasts: [...s.toasts, { id, kind, msg }],
      toastSeq: id,
    }));
  },

  dismissToast: (id) =>
    set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })),
}));
