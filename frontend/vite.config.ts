import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API base is same-origin in production (served behind one reverse proxy);
// in dev we proxy /api and the SSE stream to the FastAPI backend.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.MEMTRIAGE_API ?? "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
