/**
 * Headless Chrome over the DevTools protocol, with no dependency beyond Node.
 *
 * Node 22+ ships a global WebSocket and fetch, which is all the protocol needs.
 * Each launch uses a throwaway profile and a DevTools port chosen by Chrome
 * (read back from DevToolsActivePort), so two runs cannot collide and a stale
 * profile cannot leak state between them.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean);

export function findChrome() {
  const found = CANDIDATES.find((c) => existsSync(c));
  if (!found) {
    throw new Error("No Chrome or Chromium found. Set CHROME_PATH.");
  }
  return found;
}

function killTree(child) {
  if (!child?.pid) return;
  // `child.kill()` stops only the parent on Windows; the renderer and GPU
  // helpers survive it and keep the profile directory locked.
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
      stdio: "ignore",
    });
  } else {
    try {
      process.kill(child.pid, "SIGKILL");
    } catch {
      /* already gone */
    }
  }
}

/* Anything still running with this launch's profile in its command line.
   `taskkill /T` enumerates the tree from the parent, so a helper whose parent
   has already gone is not in it: a session's runs left 12 whole browser trees
   (36 processes) behind. The profile directory name is unique per launch, so
   matching it cannot touch any other Chrome. */
function sweepProfile(profile) {
  if (process.platform !== "win32") return;
  const tag = path.basename(profile);
  if (!/^ccure-harness-profile-[A-Za-z0-9]+$/.test(tag)) return;
  spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `Get-CimInstance Win32_Process -Filter "CommandLine like '%${tag}%'" | Where-Object { $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`,
    ],
    { stdio: "ignore" },
  );
}

export class CDP {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.seq = 0;
    this.pending = new Map();
    this.listeners = new Set();
  }

  open() {
    return new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
      this.ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.id && this.pending.has(m.id)) {
          const { resolve: ok, reject: bad } = this.pending.get(m.id);
          this.pending.delete(m.id);
          if (m.error) bad(new Error(m.error.message));
          else ok(m.result);
        } else if (m.method) {
          for (const fn of this.listeners) fn(m);
        }
      };
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.seq;
    this.ws.send(
      JSON.stringify({
        id,
        method,
        params,
        ...(sessionId ? { sessionId } : {}),
      }),
    );
    return new Promise((resolve, reject) =>
      this.pending.set(id, { resolve, reject }),
    );
  }

  on(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
}

export async function launchChrome() {
  const profile = mkdtempSync(path.join(os.tmpdir(), "ccure-harness-profile-"));
  const child = spawn(
    findChrome(),
    [
      "--headless=new",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-sync",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-features=Translate,OptimizationHints,MediaRouter,AutofillServerCommunication",
      "--metrics-recording-only",
      "--mute-audio",
      "--hide-scrollbars",
      "--force-color-profile=srgb",
      "--font-render-hinting=none",
      "--disable-lcd-text",
      "--disable-gpu",
      "--window-size=1440,900",
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  const portFile = path.join(profile, "DevToolsActivePort");
  let wsUrl = null;
  for (let i = 0; i < 120 && !wsUrl; i += 1) {
    if (existsSync(portFile)) {
      const [port, browserPath] = readFileSync(portFile, "utf8").split(/\r?\n/);
      if (port && browserPath) wsUrl = `ws://127.0.0.1:${port}${browserPath}`;
    }
    if (!wsUrl) await sleep(150);
  }
  if (!wsUrl) {
    killTree(child);
    sweepProfile(profile);
    throw new Error("Chrome did not expose a DevTools endpoint.");
  }

  const cdp = new CDP(wsUrl);
  await cdp.open();

  return {
    cdp,
    async close() {
      // Ask the browser to exit first — it takes its renderer, GPU and utility
      // helpers with it — and only then force what is left.
      const exited =
        child.exitCode !== null
          ? Promise.resolve()
          : new Promise((resolve) => child.once("exit", resolve));
      cdp.send("Browser.close").catch(() => {});
      await Promise.race([exited, sleep(5000)]);
      try {
        cdp.ws.close();
      } catch {
        /* closing anyway */
      }
      killTree(child);
      sweepProfile(profile);
      await sleep(800);
      try {
        rmSync(profile, {
          recursive: true,
          force: true,
          maxRetries: 5,
          retryDelay: 200,
        });
      } catch {
        /* a locked temp profile is harmless */
      }
    },
  };
}
