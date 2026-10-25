import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built bundle is mounted by FastAPI at /app, so asset URLs must be
// relative to that base rather than to the site root.
export default defineConfig({
  plugins: [react()],
  base: "/app/",
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    port: 5173,
    // During development the API runs separately on :8000.
    proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: true } },
  },
});
