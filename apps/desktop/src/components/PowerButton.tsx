import type { SessionStateName } from "../types";

interface Props {
  stateName: SessionStateName;
  onToggle: () => void;
}

function visualFor(state: SessionStateName): "off" | "busy" | "on" {
  switch (state) {
    case "Connected":
    case "Waiting":
      return "on";
    case "Connecting":
    case "Handshaking":
    case "NatTraversal":
    case "Disconnecting":
      return "busy";
    default:
      return "off";
  }
}

/**
 * Botão de power estilo VNET: círculo de 84px com anel teal,
 * interior escuro, ícone de power e rótulo ON/OFF.
 */
export default function PowerButton({ stateName, onToggle }: Props) {
  const v = visualFor(stateName);
  const label = v === "on" ? "Desligar VPN" : "Ligar VPN";

  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onToggle}
      className={`v-power ${v === "off" ? "v-power-off" : v === "busy" ? "v-power-busy" : ""}`}
    >
      <svg
        className="v-power-icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 3v9" />
        <path d="M6.5 6.5a8 8 0 1 0 11 0" />
      </svg>
      <span className="v-power-label">
        {v === "on" ? "ON" : v === "busy" ? "···" : "OFF"}
      </span>
    </button>
  );
}
