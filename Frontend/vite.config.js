import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 3000,
    proxy: {
      "/auth": "http://localhost:8000",
      "/scan": "http://localhost:8000",
      "/scans": "http://localhost:8000",
      "/web-scans": "http://localhost:8000",
      "/reports": "http://localhost:8000",
      "/admin": "http://localhost:8000",
      "/dashboard": "http://localhost:8000",
      "/assets": "http://localhost:8000",
      "/findings": "http://localhost:8000",
      "/notifications": "http://localhost:8000",
      "/topology": "http://localhost:8000",
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/__tests__/setupTests.js"],
    // Paired with asyncUtilTimeout in setupTests.js: a test that waits up to
    // 5 s several times must not be cut off by the 5 s default here.
    testTimeout: 20000,
  },
});
