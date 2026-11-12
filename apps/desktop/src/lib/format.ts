/** Formatação e helpers puros */

/** PC-XXXX estável derivado do id hex (TODO: hostname real do peer via backend) */
export function memberName(id: string): string {
  return `PC-${id.replace(/[^0-9a-fA-F]/g, "").slice(0, 4).toUpperCase()}`;
}

export function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** Cor do ping por qualidade (verde/bom, laranja/regular, vermelho/ruim) */
export function pingColor(ms: number): string {
  if (ms < 40) return "text-online";
  if (ms < 120) return "text-warn";
  return "text-error";
}

/** Ping mockado e estável por peer — TODO: backend ainda não expõe RTT real */
export function mockPing(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i++) {
    h = (h * 31 + id.charCodeAt(i)) >>> 0;
  }
  return 8 + (h % 110);
}
