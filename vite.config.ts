import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      // During local dev, proxy /agents/* to wrangler dev server
      "/agents": {
        target: "http://localhost:8787",
        ws: true,
      },
    },
  },
});
