import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // Proxy API calls to FastAPI so you don't have to hard-code the backend URL
      "/auth": "http://localhost:8000",
      "/scan": "http://localhost:8000",
      "/scans": "http://localhost:8000",
    },
  },
});
