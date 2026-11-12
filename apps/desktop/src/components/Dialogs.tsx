import { AnimatePresence, motion } from "framer-motion";
import { Eye, EyeOff, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useVnet } from "../store/useVnet";
import { Logo } from "./TitleBar";
import type { Lang } from "../types";

function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.1 }}
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/45 p-4"
      onMouseDown={onClose}
    >
      <motion.div
        role="dialog"
        aria-label={title}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 4 }}
        transition={{ duration: 0.1 }}
        className="v-dialog"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="v-dialog-head">
          <span className="v-dialog-title">{title}</span>
          <button
            type="button"
            aria-label="Fechar"
            onClick={onClose}
            className="flex h-5 w-5 items-center justify-center rounded-sm text-dim hover:bg-[#2c3f5c] hover:text-text"
          >
            <X size={12} />
          </button>
        </div>
        <div className="v-dialog-body">{children}</div>
      </motion.div>
    </motion.div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  password,
  error,
  autoFocus,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  password?: boolean;
  error?: string;
  autoFocus?: boolean;
}) {
  const [show, setShow] = useState(false);
  return (
    <div>
      <label className="v-label">{label}</label>
      <div className="relative">
        <input
          type={password && !show ? "password" : "text"}
          value={value}
          autoFocus={autoFocus}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className={`v-input ${password ? "pr-8" : ""} ${
            error ? "border-error" : ""
          }`}
        />
        {password && (
          <button
            type="button"
            aria-label="Mostrar/ocultar senha"
            onClick={() => setShow((s) => !s)}
            className="absolute right-1 top-1/2 flex h-5 w-5 -translate-y-1/2 items-center justify-center text-dim hover:text-text"
          >
            {show ? <EyeOff size={12} /> : <Eye size={12} />}
          </button>
        )}
      </div>
      {error && <p className="mt-1 text-[10.5px] text-error">{error}</p>}
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <div
      className="flex cursor-pointer items-center justify-between py-1.5"
      onClick={() => onChange(!checked)}
    >
      <span className="text-[12px] text-text">{label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        data-on={checked}
        className="v-switch"
        onClick={(e) => {
          e.stopPropagation();
          onChange(!checked);
        }}
      >
        <span />
      </button>
    </div>
  );
}

function NetworkDialog({ mode }: { mode: "create" | "join" }) {
  const { connect, closeDialog } = useVnet();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [touched, setTouched] = useState(false);

  const err = !name.trim()
    ? "Nome da rede é obrigatório"
    : name.trim().length < 3
      ? "Mínimo 3 caracteres"
      : undefined;

  const codeErr =
    mode === "join"
      ? !code.trim()
        ? "Informe o código de um membro"
        : !/^[^:\s]+:\d{1,5}$/.test(code.trim())
          ? "Formato: IP:porta (ex.: 201.10.0.5:7000)"
          : undefined
      : undefined;

  const title = mode === "create" ? "Criar rede" : "Conectar à rede";
  const action = mode === "create" ? "Criar" : "Conectar";

  function submit() {
    setTouched(true);
    if (err || codeErr) return;
    void connect(
      name,
      password || null,
      mode === "join" ? code.trim() : null
    );
  }

  return (
    <Modal title={title} onClose={closeDialog}>
      <div className="space-y-2.5">
        <Field
          autoFocus
          label="Nome da rede"
          value={name}
          onChange={setName}
          placeholder="minha-rede"
          error={touched ? err : undefined}
        />
        <Field
          password
          label="Senha"
          value={password}
          onChange={setPassword}
          placeholder={mode === "create" ? "opcional" : "senha da sala"}
        />
        {mode === "join" && (
          <Field
            label="Código de um membro"
            value={code}
            onChange={setCode}
            placeholder="201.10.0.5:7000"
            error={touched ? codeErr : undefined}
          />
        )}
        {mode === "create" && (
          <p className="text-[10.5px] leading-relaxed text-dim">
            Ao criar, o app mostra um código <span className="font-mono">IP:porta</span>{" "}
            — envie para o outro PC junto com a senha. A rede é só nome + senha:
            quem tiver os dois entra e vira membro, sem servidor.
          </p>
        )}
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <button type="button" onClick={closeDialog} className="v-btn">
          Cancelar
        </button>
        <button
          type="button"
          onClick={submit}
          className="v-btn v-btn-primary"
        >
          {action}
        </button>
      </div>
    </Modal>
  );
}

function RenameDialog() {
  const { nickname, rename, setRenaming } = useVnet();
  const [value, setValue] = useState(nickname);

  return (
    <Modal title="Alterar nome" onClose={() => setRenaming(false)}>
      <Field
        autoFocus
        label="Nome"
        value={value}
        onChange={setValue}
        placeholder="Meu PC"
      />
      <div className="mt-4 flex justify-end gap-2">
        <button
          type="button"
          onClick={() => setRenaming(false)}
          className="v-btn"
        >
          Cancelar
        </button>
        <button
          type="button"
          onClick={() => rename(value)}
          className="v-btn v-btn-primary"
        >
          Salvar
        </button>
      </div>
    </Modal>
  );
}

function SettingsDialog() {
  const {
    settings,
    closeDialog,
    setCloseToTray,
    setStartWithWindows,
    setLanguage,
    toast,
  } = useVnet();

  return (
    <Modal title="Configurações" onClose={closeDialog}>
      <div>
        <p className="mb-1 text-[10px] font-bold uppercase tracking-wider text-dim">
          Geral
        </p>
        <Toggle
          label="Iniciar com o Windows"
          checked={settings.startWithWindows}
          onChange={(v) => {
            setStartWithWindows(v);
            if (v) toast("info", "Disponível em breve");
          }}
        />
        <Toggle
          label="Fechar para a bandeja"
          checked={settings.closeToTray}
          onChange={(v) => void setCloseToTray(v)}
        />

        <div className="flex items-center justify-between py-1.5">
          <span className="text-[12px] text-text">Idioma</span>
          <select
            value={settings.language}
            onChange={(e) => setLanguage(e.target.value as Lang)}
            className="v-input h-6 w-auto px-1.5"
          >
            <option value="pt-BR">Português (BR)</option>
            <option value="en-US">English (US)</option>
          </select>
        </div>

        <p className="mb-1 mt-3 text-[10px] font-bold uppercase tracking-wider text-dim">
          Criptografia
        </p>
        <div className="space-y-0.5 rounded-sm border border-border bg-[#111b2a] px-2.5 py-2 text-[10.5px] leading-relaxed text-dim">
          <p>ChaCha20-Poly1305 · AES-256-GCM</p>
          <p>ECDH P-256 · HKDF-SHA256</p>
          <p>STUN + ICE · MTU 1400</p>
        </div>
      </div>

      <div className="mt-3 flex justify-end">
        <button
          type="button"
          onClick={closeDialog}
          className="v-btn v-btn-primary"
        >
          OK
        </button>
      </div>
    </Modal>
  );
}

function AboutDialog() {
  const closeDialog = useVnet((s) => s.closeDialog);
  return (
    <Modal title="Sobre o VNET VPN" onClose={closeDialog}>
      <div className="flex flex-col items-center gap-1 py-1 text-center">
        <Logo size={34} />
        <p className="mt-1 text-[13px] font-bold text-white">VNET VPN</p>
        <p className="text-[11px] text-dim">VPN open-source em Rust</p>
        <p className="text-[10.5px] text-muted">
          Protocolo v2 · ECDH P-256 · AEAD · ICE/STUN
        </p>
        <p className="mt-1 font-mono text-[10.5px] text-muted">v0.1.0</p>
      </div>
    </Modal>
  );
}

export default function Dialogs() {
  const dialog = useVnet((s) => s.dialog);
  return (
    <AnimatePresence>
      {dialog === "create" && <NetworkDialog key="create" mode="create" />}
      {dialog === "join" && <NetworkDialog key="join" mode="join" />}
      {dialog === "settings" && <SettingsDialog key="settings" />}
      {dialog === "about" && <AboutDialog key="about" />}
      <RenameGate key="rename" />
    </AnimatePresence>
  );
}

function RenameGate() {
  const renaming = useVnet((s) => s.renaming);
  return <AnimatePresence>{renaming && <RenameDialog />}</AnimatePresence>;
}
