import { Minus, X } from "lucide-react";
import logoUrl from "../assets/vnet-logo.png";
import { appWindow } from "../lib/ipc";

/** Logo do VNET (ícone do app, embutido pelo Vite) */
export function Logo({ size = 20 }: { size?: number }) {
  return (
    <img
      src={logoUrl}
      width={size}
      height={size}
      alt=""
      draggable={false}
      className="shrink-0 select-none"
      style={{ borderRadius: Math.round(size * 0.22) }}
    />
  );
}

/** Title bar frameless: logo + wordmark + minimizar / fechar */
export default function TitleBar() {
  return (
    <header
      data-tauri-drag-region
      className="flex h-[32px] shrink-0 items-center border-b border-black/40 bg-title pl-2.5 select-none"
    >
      <div className="flex items-center gap-1.5" data-tauri-drag-region>
        <Logo size={19} />
        <span
          data-tauri-drag-region
          className="text-[13.5px] font-bold tracking-[0.06em] text-white"
        >
          VNET
        </span>
        <span
          data-tauri-drag-region
          className="-ml-0.5 text-[13.5px] font-bold tracking-[0.06em]"
          style={{ color: "var(--v-primary-text)" }}
        >
          VPN
        </span>
      </div>

      <div data-tauri-drag-region className="flex-1" />

      <button
        type="button"
        aria-label="Minimizar"
        title="Minimizar"
        onClick={() => void appWindow.minimize()}
        className="v-winbtn"
      >
        <Minus size={13} strokeWidth={1.6} />
      </button>
      <button
        type="button"
        aria-label="Fechar"
        title="Fechar"
        onClick={() => void appWindow.close()}
        className="v-winbtn v-winbtn-close"
      >
        <X size={13} strokeWidth={1.6} />
      </button>
    </header>
  );
}
