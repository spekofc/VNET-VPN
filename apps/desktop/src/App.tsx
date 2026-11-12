import { useEffect, useRef } from "react";
import TitleBar from "./components/TitleBar";
import MenuBar from "./components/MenuBar";
import ProfileCard from "./components/ProfileCard";
import NetworkList from "./components/NetworkList";
import EmptyState from "./components/EmptyState";
import Dialogs from "./components/Dialogs";
import Toasts from "./components/Toasts";
import { useVnet } from "./store/useVnet";

export default function App() {
  const init = useVnet((s) => s.init);
  const stateName = useVnet((s) => s.stateName);
  const lastNetwork = useVnet((s) => s.lastNetwork);
  const lastPassword = useVnet((s) => s.lastPassword);
  const lastCode = useVnet((s) => s.lastCode);
  const connect = useVnet((s) => s.connect);
  const disconnect = useVnet((s) => s.disconnect);
  const openDialog = useVnet((s) => s.openDialog);

  // init roda uma única vez (StrictMode remonta, reuso a mesma promise)
  const initRef = useRef<Promise<() => void> | null>(null);
  useEffect(() => {
    if (!initRef.current) initRef.current = init();
    let un: (() => void) | undefined;
    void initRef.current.then((fn) => {
      un = fn;
    });
    return () => {
      un?.();
    };
  }, [init]);

  function togglePower() {
    if (stateName === "Disconnected" || stateName === "Failed") {
      if (lastNetwork) {
        void connect(lastNetwork, lastPassword, lastCode);
      } else {
        openDialog("join");
      }
    } else {
      void disconnect();
    }
  }

  const hasNetwork = lastNetwork !== null;

  return (
    <div className="flex h-full flex-col overflow-hidden bg-base text-text">
      <TitleBar />
      <MenuBar />

      <main className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto px-2.5 pb-2.5 pt-2">
        <ProfileCard onToggle={togglePower} />
        {hasNetwork ? <NetworkList /> : <EmptyState />}
      </main>

      <Dialogs />
      <Toasts />
    </div>
  );
}
