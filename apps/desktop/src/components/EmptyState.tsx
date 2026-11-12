import { useVnet } from "../store/useVnet";

/** Estado vazio estilo VNET: texto discreto + atalhos de texto */
export default function EmptyState() {
  const openDialog = useVnet((s) => s.openDialog);

  return (
    <div className="flex flex-1 select-none flex-col items-center justify-center gap-1 px-5 pb-10 text-center">
      <p className="text-[12px] font-semibold text-dim">Nenhuma rede</p>
      <p className="mt-0.5 text-[11px] leading-relaxed text-muted">
        Crie uma rede nova ou conecte-se a uma existente para começar.
      </p>
      <div className="mt-2.5 flex items-center gap-2 text-[11.5px]">
        <button
          type="button"
          onClick={() => openDialog("create")}
          className="cursor-pointer border-none bg-transparent p-0 hover:underline"
          style={{ color: "var(--v-primary-text)" }}
        >
          Criar rede
        </button>
        <span className="text-muted">·</span>
        <button
          type="button"
          onClick={() => openDialog("join")}
          className="cursor-pointer border-none bg-transparent p-0 hover:underline"
          style={{ color: "var(--v-primary-text)" }}
        >
          Conectar à rede
        </button>
      </div>
    </div>
  );
}
