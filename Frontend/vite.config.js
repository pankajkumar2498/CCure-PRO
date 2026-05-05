import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 3000,
    proxy: {
      "/auth":    "http://localhost:8000",
      "/scan":    "http://localhost:8000",
      "/scans":   "http://localhost:8000",
      "/reports": "http://localhost:8000",
      "/admin":   "http://localhost:8000",
    },
  },
});
