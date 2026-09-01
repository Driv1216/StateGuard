import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const backend = "http://127.0.0.1:9471";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../src/stateguard/dashboard/static",
    emptyOutDir: true,
    assetsDir: "assets",
  },
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api/v1": {
        target: backend,
        changeOrigin: true,
        headers: { Origin: backend },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    css: false,
  },
});
