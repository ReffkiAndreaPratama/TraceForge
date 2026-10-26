import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build is served by the local TraceForge bridge at "/".
// During development the app talks to the bridge directly on 127.0.0.1:8765
// (the bridge's CORS allowlist includes the Vite dev origins).
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
  },
});
