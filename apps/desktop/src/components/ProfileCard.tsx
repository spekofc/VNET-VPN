import { useVnet } from "../store/useVnet";
import PowerButton from "./PowerButton";

/** Topo estilo VNET: power à esquerda, nome/IP/status à direita */
export default function ProfileCard({ onToggle }: { onToggle: () => void }) {
  const { stateName, nickname, virtualIp, toast, setRenaming } = useVnet();

  const ip = virtualIp ?? "—";

  function copyIp() {
    if (!virtualIp) return;
    void navigator.clipboard.writeText(virtualIp);
    toast("success", "IP copiado");
  }

  const value =
    stateName === "Connected"
      ? { label: "Online", cls: "" }
      : stateName === "Waiting"
        ? { label: "Aguardando", cls: "v-status-busy" }
        : stateName === "Failed"
          ? { label: "Falha", cls: "v-status-error" }
          : stateName === "Disconnected"
            ? { label: "Off-line", cls: "v-status-offline" }
            : { label: "Conectando…", cls: "v-status-busy" };

  return (
    <section aria-label="Perfil" className="flex items-center gap-3.5 pb-2.5 pt-1">
      <PowerButton stateName={stateName} onToggle={onToggle} />

      <div className="min-w-0 flex-1">
        <div
          className="truncate text-[15px] font-bold leading-tight"
          style={{ color: "var(--v-primary-text)" }}
          title="Duplo clique para alterar o nome"
          onDoubleClick={() => setRenaming(true)}
        >
          {nickname || "Meu PC"}
        </div>

        <button
          type="button"
          onClick={copyIp}
          title="Copiar IP"
          className="mt-0.5 block truncate font-mono text-[13px] text-white hover:underline"
        >
          {ip}
        </button>

        <div className="mt-1.5">
          <span className={`v-status ${value.cls}`}>{value.label}</span>
        </div>
      </div>
    </section>
  );
}
