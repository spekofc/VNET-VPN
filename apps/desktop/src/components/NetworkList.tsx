import {
  ChevronDown,
  Copy,
  Folder,
  Gauge,
  MessageSquare,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
import { memberName } from "../lib/format";
import { useVnet } from "../store/useVnet";
import type { Peer } from "../types";

function ContextItem({
  icon,
  label,
  danger,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  danger?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      onClick={onClick}
      className={`v-menu-item w-full min-w-[170px] text-left ${
        danger ? "text-error" : ""
      }`}
    >
      {icon}
      {label}
    </button>
  );
}

/** Card de rede estilo VNET: header com chevron + nome + chat, linhas com x + membro + IP */
export default function NetworkList() {
  const {
    stateName,
    peers,
    lastNetwork,
    expanded,
    toggleExpanded,
    removePeer,
    pingPeer,
    toast,
    roomCode,
    roomPublic,
    roomLocal,
    roomMapped,
    tunReady,
  } = useVnet();

  const [menu, setMenu] = useState<{ x: number; y: number; peer: Peer } | null>(
    null
  );

  const connected = stateName === "Connected" || stateName === "Waiting";

  // IP de um membro da malha, usado no jogo (a rede não tem host).
  const peerIp = peers[0]?.virtualIp ?? "";

  function copyIp(ip: string) {
    void navigator.clipboard.writeText(ip);
    toast("success", "IP copiado");
    setMenu(null);
  }

  function copy(value: string | null, label: string) {
    if (!value) return;
    void navigator.clipboard.writeText(value);
    toast("success", label);
  }

  return (
    <>
      <section className="overflow-hidden rounded-[4px] bg-card">
        {/* Header da rede */}
        <button
          type="button"
          onClick={toggleExpanded}
          aria-expanded={expanded}
          className="flex h-[30px] w-full items-center gap-1 bg-cardhead px-1.5 text-left hover:bg-[#223146]"
        >
          <ChevronDown
            size={14}
            strokeWidth={2.4}
            className={`shrink-0 text-[#8fa6bd] transition-transform duration-100 ${
              expanded ? "" : "-rotate-90"
            }`}
          />
          <span className="min-w-0 flex-1 truncate text-[12px] font-bold text-white">
            {lastNetwork}
          </span>
          <span
            role="button"
            tabIndex={0}
            aria-label="Chat da rede"
            title="Chat da rede"
            onClick={(e) => {
              e.stopPropagation();
              toast("info", "Chat chega em breve");
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.stopPropagation();
                toast("info", "Chat chega em breve");
              }
            }}
            className="mr-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded text-[#7d8fa5] hover:bg-[#2c3f5c] hover:text-white"
          >
            <MessageSquare size={13} />
          </span>
        </button>

        {/* Membros */}
        {expanded && connected && peers.length > 0 && (
          <ul>
            {peers.map((p, i) => (
                <li
                  key={p.id}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setMenu({ x: e.clientX, y: e.clientY, peer: p });
                  }}
                  className={`flex h-[22px] items-center gap-1.5 px-2 text-[11px] hover:bg-[#24344a] ${
                    i > 0 ? "border-t border-[#22303f]" : ""
                  }`}
                >
                  <button
                    type="button"
                    aria-label="Remover membro"
                    title="Remover membro"
                    onClick={() => void removePeer(p.id)}
                    className="flex shrink-0 items-center justify-center text-[#5f7183] hover:text-white"
                  >
                    <X size={9} strokeWidth={2.6} />
                  </button>
                  <span
                    className={`min-w-0 flex-1 truncate ${
                      p.state === "Connected" ? "text-[#c3cdda]" : "text-[#7c8da1]"
                    }`}
                  >
                    {memberName(p.id)}
                  </span>
                  <span className="shrink-0 font-mono text-white">
                    {p.virtualIp}
                  </span>
                </li>
              ))
            }
          </ul>
        )}

        {/* Adaptador virtual inativo = jogo não vê a rede */}
        {expanded && connected && !tunReady && (
          <div className="border-t border-[#22303f] px-2 py-1 text-[10px] leading-snug text-[#e0a06a]">
            Adaptador virtual inativo. Feche o VNET e abra como administrador
            (ou aceite a elevação) para o jogo enxergar a rede.
          </div>
        )}

        {/* Atalho para jogar: IP do outro membro */}
        {expanded && connected && peerIp && (
          <div className="flex items-center justify-between border-t border-[#22303f] px-2 py-1 text-[10px] text-dim">
            <span>
              No jogo: Conexão direta →{" "}
              <span className="font-mono text-white">{peerIp}</span>
              <span className="text-[#6f8095]"> + porta da LAN (do outro PC)</span>
            </span>
            <button
              type="button"
              onClick={() => copy(peerIp, "IP do membro copiado")}
              className="flex items-center gap-1 text-[10px] text-[#5fc7d6] hover:underline"
            >
              <Copy size={9} /> copiar
            </button>
          </div>
        )}
      </section>

      {/* Código de convite: qualquer membro gera o seu */}
      {roomCode && (stateName === "Waiting" || stateName === "Connected") && (
        <section className="mt-1.5 rounded-[4px] border border-[#24344a] bg-[#141f30] px-2 py-1.5">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-wider text-dim">
              Código para convidar
            </span>
            <button
              type="button"
              onClick={() => copy(roomCode, "Código copiado")}
              className="flex items-center gap-1 text-[10.5px] text-[#5fc7d6] hover:underline"
            >
              <Copy size={10} /> copiar
            </button>
          </div>
          <p className="mt-0.5 select-all font-mono text-[12px] text-white">
            {roomCode}
          </p>

          {!roomMapped && (
            <div className="mt-1 space-y-1 border-t border-[#22303f] pt-1 text-[10px] leading-snug">
              {roomPublic && (
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-dim">Pela internet — use</span>
                    <button
                      type="button"
                      onClick={() => copy(roomPublic, "Código público copiado")}
                      className="flex items-center gap-1 text-[10px] text-[#5fc7d6] hover:underline"
                    >
                      <Copy size={9} /> copiar
                    </button>
                  </div>
                  <p className="select-all font-mono text-[11.5px] text-white">
                    {roomPublic}
                  </p>
                  <p className="mt-0.5 text-[#c9a227]">
                    No roteador, encaminhe a porta UDP{" "}
                    {roomCode.split(":")[1]} para{" "}
                    <span className="font-mono">{roomLocal}</span> (esta máquina).
                  </p>
                </div>
              )}
              {!roomPublic && (
                <p className="text-[#c9a227]">
                  Na mesma rede, use {roomLocal}. Fora dela, libere UDP{" "}
                  {roomCode.split(":")[1]} no roteador.
                </p>
              )}
            </div>
          )}
        </section>
      )}

      {/* Menu de contexto do membro */}
      {menu && (
        <div
          role="menu"
          className="v-menu-panel fixed z-[70]"
          style={{
            left: Math.min(menu.x, window.innerWidth - 190),
            top: Math.min(menu.y, window.innerHeight - 190),
          }}
        >
          <ContextItem
            icon={<Copy size={12} />}
            label="Copiar IP"
            onClick={() => copyIp(menu.peer.virtualIp)}
          />
          <ContextItem
            icon={<Gauge size={12} />}
            label="Pingar"
            onClick={() => {
              void pingPeer(menu.peer.id);
              setMenu(null);
            }}
          />
          <ContextItem
            icon={<Folder size={12} />}
            label="Pasta compartilhada"
            onClick={() => {
              toast("info", "Pastas compartilhadas chegam em breve");
              setMenu(null);
            }}
          />
          <ContextItem
            icon={<MessageSquare size={12} />}
            label="Chat"
            onClick={() => {
              toast("info", "Chat entre membros chega em breve");
              setMenu(null);
            }}
          />
          <div className="v-menu-sep" />
          <ContextItem
            icon={<Trash2 size={12} />}
            label="Remover membro"
            danger
            onClick={() => {
              void removePeer(menu.peer.id);
              setMenu(null);
            }}
          />
        </div>
      )}

      {/* Fecha menu de contexto ao clicar fora */}
      {menu && (
        <div
          className="fixed inset-0 z-[65]"
          onMouseDown={() => setMenu(null)}
          onContextMenu={(e) => {
            e.preventDefault();
            setMenu(null);
          }}
        />
      )}
    </>
  );
}
