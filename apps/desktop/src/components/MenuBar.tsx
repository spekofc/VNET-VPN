import { useEffect, useRef, useState } from "react";
import { ipc } from "../lib/ipc";
import { useVnet } from "../store/useVnet";

type MenuId = "sistema" | "rede" | "ajuda";

/** Menu bar estilo VNET: Sistema / Rede / Ajuda com dropdowns */
export default function MenuBar() {
  const [open, setOpen] = useState<MenuId | null>(null);
  const [firewallOpen, setFirewallOpen] = useState(false);
  const [firewallFlip, setFirewallFlip] = useState(false);
  const navRef = useRef<HTMLElement | null>(null);

  const openDialog = useVnet((s) => s.openDialog);
  const setRenaming = useVnet((s) => s.setRenaming);
  const toast = useVnet((s) => s.toast);

  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (navRef.current && !navRef.current.contains(e.target as Node)) {
        setOpen(null);
        setFirewallOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "INPUT" || el.tagName === "SELECT")) return;
      if (e.key === "Escape") {
        setOpen(null);
        setFirewallOpen(false);
      }
      if (e.key === "Insert") {
        e.preventDefault();
        openDialog("create");
      }
      if (e.key === "+") {
        e.preventDefault();
        openDialog("join");
      }
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [openDialog]);

  function pick(fn: () => void) {
    setOpen(null);
    setFirewallOpen(false);
    fn();
  }

  const labelCls = (id: MenuId) =>
    `flex h-[26px] cursor-default items-center px-3 text-[12px] text-text ${
      open === id ? "bg-[#2c3f5c]" : "hover:bg-[#2c3f5c]"
    }`;

  return (
    <nav
      ref={navRef}
      className="relative z-50 flex h-[26px] shrink-0 items-stretch border-b border-black/30 bg-title pl-1"
      aria-label="Menu principal"
    >
      {/* Sistema */}
      <div className="relative">
        <button
          type="button"
          className={labelCls("sistema")}
          onClick={() => {
            setOpen(open === "sistema" ? null : "sistema");
            setFirewallOpen(false);
          }}
          onMouseEnter={() => open && setOpen("sistema")}
        >
          Sistema
        </button>
        {open === "sistema" && (
          <div className="v-menu-panel" role="menu">
            <button
              type="button"
              role="menuitem"
              className="v-menu-item w-full text-left"
              onClick={() => pick(() => setRenaming(true))}
            >
              Alterar nome
            </button>

            <div
              className="relative"
              onMouseEnter={(e) => {
                const r = e.currentTarget.getBoundingClientRect();
                setFirewallFlip(r.right + 172 > window.innerWidth);
                setFirewallOpen(true);
              }}
              onMouseLeave={() => setFirewallOpen(false)}
            >
              <button
                type="button"
                role="menuitem"
                className="v-menu-item w-full text-left"
                onClick={(e) => {
                  const r = e.currentTarget.getBoundingClientRect();
                  setFirewallFlip(r.right + 172 > window.innerWidth);
                  setFirewallOpen((v) => !v);
                }}
              >
                Exceções do firewall
                <span className="v-menu-shortcut">▸</span>
              </button>
              {firewallOpen && (
                <div
                  className="v-menu-panel"
                  style={
                    firewallFlip
                      ? { right: "100%", top: 0, minWidth: 168 }
                      : { left: "100%", top: 0, minWidth: 168 }
                  }
                >
                  <button
                    type="button"
                    role="menuitem"
                    className="v-menu-item w-full text-left"
                    onClick={() =>
                      pick(() => toast("info", "Exceções do firewall em breve"))
                    }
                  >
                    Adicionar exceção
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    className="v-menu-item w-full text-left"
                    onClick={() =>
                      pick(() => toast("info", "Exceções do firewall em breve"))
                    }
                  >
                    Remover exceção
                  </button>
                </div>
              )}
            </div>

            <button
              type="button"
              role="menuitem"
              className="v-menu-item w-full text-left"
              onClick={() => pick(() => openDialog("settings"))}
            >
              Configurações
            </button>

            <div className="v-menu-sep" />

            <button
              type="button"
              role="menuitem"
              className="v-menu-item w-full text-left"
              onClick={() => pick(() => void ipc.quitApp())}
            >
              Sair
            </button>
          </div>
        )}
      </div>

      {/* Rede */}
      <div className="relative">
        <button
          type="button"
          className={labelCls("rede")}
          onClick={() => setOpen(open === "rede" ? null : "rede")}
          onMouseEnter={() => open && setOpen("rede")}
        >
          Rede
        </button>
        {open === "rede" && (
          <div className="v-menu-panel" role="menu">
            <button
              type="button"
              role="menuitem"
              className="v-menu-item w-full text-left"
              onClick={() => pick(() => openDialog("create"))}
            >
              Criar rede
              <span className="v-menu-shortcut">Ins</span>
            </button>
            <button
              type="button"
              role="menuitem"
              className="v-menu-item w-full text-left"
              onClick={() => pick(() => openDialog("join"))}
            >
              Conectar à rede
              <span className="v-menu-shortcut">+</span>
            </button>
          </div>
        )}
      </div>

      {/* Ajuda */}
      <div className="relative">
        <button
          type="button"
          className={labelCls("ajuda")}
          onClick={() => setOpen(open === "ajuda" ? null : "ajuda")}
          onMouseEnter={() => open && setOpen("ajuda")}
        >
          Ajuda
        </button>
        {open === "ajuda" && (
          <div className="v-menu-panel" role="menu">
            <button
              type="button"
              role="menuitem"
              className="v-menu-item w-full text-left"
              onClick={() => pick(() => openDialog("about"))}
            >
              Sobre o VNET VPN
            </button>
            <button
              type="button"
              role="menuitem"
              className="v-menu-item w-full text-left"
              onClick={() =>
                pick(() => toast("info", "Documentação em breve"))
              }
            >
              Ajuda on-line
            </button>
          </div>
        )}
      </div>
    </nav>
  );
}
