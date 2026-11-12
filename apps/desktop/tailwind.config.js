/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: ["Segoe UI", "system-ui", "sans-serif"],
      },
      colors: {
        base: "var(--v-bg-base)",
        title: "var(--v-bg-title)",
        surface: "var(--v-bg-surface)",
        card: "var(--v-bg-card)",
        cardhead: "var(--v-bg-card-head)",
        menu: "var(--v-bg-menu)",
        hover: "var(--v-bg-hover)",
        border: "var(--v-border)",
        primary: "var(--v-primary)",
        online: "var(--v-online)",
        offline: "var(--v-offline)",
        warn: "var(--v-warn)",
        error: "var(--v-error)",
        text: "var(--v-text)",
        dim: "var(--v-text-dim)",
        muted: "var(--v-text-muted)",
      },
      borderRadius: {
        vs: "3px",
        v: "4px",
      },
    },
  },
  plugins: [],
};
