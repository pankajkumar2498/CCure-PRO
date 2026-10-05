import { defineConfig, devices } from "@playwright/test";
import os from "node:os";
import path from "node:path";

export default defineConfig({
  testDir: "./browser-tests",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  workers: 4,
  timeout: 120000,
  expect: { timeout: 10000 },
  outputDir:
    process.env.UX4G_BROWSER_OUTPUT ||
    path.join(os.tmpdir(), "ccure-ux4g-browser-results"),
  reporter: [
    ["line"],
    [
      "json",
      {
        outputFile:
          process.env.UX4G_BROWSER_REPORT ||
          path.join(os.tmpdir(), "ccure-ux4g-browser-report.json"),
      },
    ],
  ],
  use: {
    baseURL: "http://127.0.0.1:3277",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    serviceWorkers: "block",
    reducedMotion: "reduce",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        channel: process.env.UX4G_CHROME_CHANNEL,
      },
    },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    {
      name: "webkit",
      use: {
        ...devices["Desktop Safari"],
        launchOptions: process.env.UX4G_WEBKIT_EXECUTABLE
          ? { executablePath: process.env.UX4G_WEBKIT_EXECUTABLE }
          : {},
      },
    },
  ],
  webServer: {
    command: "node scripts/ux4g-harness/browser-server.mjs",
    url: "http://127.0.0.1:3277/__health",
    reuseExistingServer: false,
    timeout: 60000,
  },
});
