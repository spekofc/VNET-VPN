import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { useEffect } from "react";
import { useVnet } from "../store/useVnet";
import type { Toast } from "../types";

function ToastItem({ toast }: { toast: Toast }) {
  const dismiss = useVnet((s) => s.dismissToast);

  useEffect(() => {
    const id = setTimeout(() => dismiss(toast.id), 3000);
    return () => clearTimeout(id);
  }, [toast.id, dismiss]);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.1 }}
      className={`v-toast v-toast-${toast.kind} flex items-center gap-2`}
      role="status"
    >
      <span className="min-w-0 flex-1">{toast.msg}</span>
      <button
        type="button"
        aria-label="Fechar"
        onClick={() => dismiss(toast.id)}
        className="shrink-0 text-dim hover:text-text"
      >
        <X size={11} />
      </button>
    </motion.div>
  );
}

export default function Toasts() {
  const toasts = useVnet((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed bottom-2 right-2 z-[80] flex w-[240px] flex-col gap-1">
      <AnimatePresence>
        {toasts.map((toast) => (
          <div key={toast.id} className="pointer-events-auto">
            <ToastItem toast={toast} />
          </div>
        ))}
      </AnimatePresence>
    </div>
  );
}
