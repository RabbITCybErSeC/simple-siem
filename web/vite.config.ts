import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const apiTarget = `http://${process.env.API_HOST ?? "127.0.0.1"}:${process.env.API_PORT ?? "8080"}`;

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    host: "0.0.0.0",
    port: Number(process.env.WEB_PORT ?? 5173),
    strictPort: true,
    watch: {
      usePolling: true,
    },
    proxy: {
      // Keys starting with ^ are regular expressions; plain keys are prefixes
      // and would also proxy client routes such as /api-keys or /versions.
      "^/api(/|$)": apiTarget,
      "^/(healthz|readyz|version)$": apiTarget,
    },
  },
  test: {
    environment: "jsdom",
  },
});
