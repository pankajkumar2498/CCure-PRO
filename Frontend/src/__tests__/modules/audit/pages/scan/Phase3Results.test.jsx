/**
 * Phase3Results (`/scan/vulnerability-audit`, `/scan/:scanId/phase3`) —
 * Checkpoint 3C batch 24 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 24 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The page reads only the scan context and starts work from it. On mount, if
 * discovery found live hosts and the context holds no pipeline, no audit
 * results and no un-queued port-scan results, it starts the automated
 * pipeline exactly once:
 *
 *   POST /scan/asset-discovery        (unless starting from the audit)
 *   POST /auth/ticket  → WebSocket /scans/{id}/progress?ticket=… (phase 2)
 *   GET  /scans/{id}
 *   POST /scan/vulnerability-audit
 *   POST /auth/ticket  → WebSocket /scans/{id}/progress?ticket=… (phase 3)
 *   GET  /scans/{id}
 *
 * Each socket is closed on its phase's `complete` or `failed` frame. Without
 * `scans:execute` nothing is requested and the page reports an authorization
 * failure. Cancel aborts the pipeline and posts /scans/{id}/stop. Weak FTP
 * credentials are shown as `user/********`.
 *
 * Only the axios instance and `WebSocket` are replaced; the scan context is
 * the real provider, seeded through sessionStorage as the pipeline leaves it.
 */

import { StrictMode } from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

import Phase3Results from "@audit/pages/scan/Phase3Results";
import { ScanProvider } from "@audit/context/ScanContext";
import api from "@shell/api/axiosInstance";
import { SRC, AUDIT_SRC } from "../../../../testPaths";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle, saveStatus }) => (
    <div
      data-testid="app-layout"
      data-page-title={pageTitle}
      data-save-status={saveStatus}
    >
      {children}
    </div>
  ),
}));

vi.mock("@audit/components/layout/ScanStepper", () => ({
  default: ({ current }) => (
    <div data-testid="scan-stepper" data-current={current} />
  ),
}));

const navigate = vi.fn();
let locationState = null;
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useLocation: () => ({
      pathname: "/scan/vulnerability-audit",
      search: "",
      state: locationState,
    }),
  };
});

let user;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user }),
}));

const EXECUTOR = {
  id: 1,
  username: "operator",
  role: { name: "analyst", permissions: ["scans:read", "scans:execute"] },
};
const VIEWER = {
  id: 2,
  username: "viewer",
  role: { name: "viewer", permissions: ["scans:read"] },
};

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const P1_HOSTS = [
  {
    ip_address: "10.50.0.11",
    hostname: "web-01",
    mac_address: "00:1A:2B:3C:4D:11",
    vendor: "Dell Inc.",
    discovery_method: "ARP",
    is_active: true,
  },
  {
    ip_address: "10.50.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    mac_address: "00:1A:2B:3C:4D:12",
    vendor: "HP",
    discovery_method: "ICMP",
    is_active: true,
  },
  {
    ip_address: "10.50.0.13",
    hostname: "Unknown",
    netbios_names: [{ name: "KIOSK-07" }],
    discovery_method: "TCP",
    is_active: true,
  },
  {
    ip_address: "10.50.0.14",
    hostname: "Unknown",
    discovery_method: "ICMP",
    is_active: false,
  },
];
const ACTIVE_P1 = P1_HOSTS.filter((h) => h.is_active);
const P1_SUMMARY = {
  total_hosts: 4,
  active_hosts: 3,
  inactive_hosts: 1,
  scan_duration: 12.34,
};

const P2_HOSTS = [
  {
    ip_address: "10.50.0.11",
    hostname: "web-01",
    is_active: true,
    open_ports: [
      { port: 22, service: "ssh" },
      { port: 443, service: "https" },
    ],
    os_fingerprint_full: { os: "Linux 5.x" },
  },
  {
    ip_address: "10.50.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    is_active: true,
    open_ports: [{ port: 9100, service: "jetdirect" }],
    os_guess: "HP embedded",
  },
  {
    ip_address: "10.50.0.14",
    hostname: "Unknown",
    is_active: false,
    open_ports: [],
  },
];
const P2_SUMMARY = { total_hosts: 3, hosts_with_ports: 2, scan_duration: 40.5 };

const P3_HOSTS = [
  {
    ip_address: "10.50.0.11",
    hostname: "web-01",
    is_active: true,
    os_guess: "Ubuntu 22.04",
    open_ports: [{ port: 22 }, { port: 21 }, { port: 80 }],
    device_category: "server",
    device_category_signal: "banner",
    credentialed: true,
    exposure_summary: {
      correlated_with_port_scan: true,
      listeners_exposed: 2,
      listeners_host_only: 1,
    },
    host_risk_level: "Critical",
    cves: [
      {
        cve_id: "CVE-2024-6387",
        severity: "Critical",
        cvss_score: 8.1,
        description: "Signal handler race in sshd",
        affected_software: "OpenSSH 8.9p1",
      },
      {
        cve_id: "CVE-2023-0286",
        severity: "high",
        cvss_score: 7.4,
        description: "X.400 type confusion",
      },
      { cve_id: "CVE-2023-2650", severity: "Medium" },
      { cve_id: "CCURE-CHK-NOTE", severity: "low", description: "A note" },
      { cve_id: "CVE-2023-1", severity: null, cvss_score: 0 },
    ],
    heartbleed_info: { vulnerable: true },
    ldap_info: { anonymous_bind: { allowed: true } },
    ftp_info: {
      open: true,
      banner: `220 ${"x".repeat(130)}`,
      issues: ["Anonymous login allowed"],
      anonymous_login: true,
      write_access: true,
      weak_credentials: [
        { user: "ftpuser", password: "placeholder" },
        { password: "placeholder" },
      ],
    },
    http_audit: {
      server_header: "nginx/1.18.0",
      issues: [
        "Missing CSP",
        "Missing HSTS",
        "Missing X-Frame-Options",
        "Missing Referrer-Policy",
        "Missing Permissions-Policy",
      ],
      exposed_paths: [
        { path: "/.git/config", status: 200, note: "repository" },
        { path: "/backup/", status: 200, note: "directory listing" },
      ],
      admin_panels: [
        { product: "Tomcat Manager", path: "/manager/html", status: 401 },
      ],
      dangerous_methods: ["PUT", "DELETE"],
    },
    tls_info: { cert_expired: true },
    smb_info: { open: true, null_session: true },
  },
  {
    ip_address: "10.50.0.12",
    hostname: "Unknown",
    is_active: true,
    os_guess: "Unknown",
    open_ports: [],
    snmp_device_type: "printer",
    device_category: "server",
    host_risk_level: "Low",
    cves: [],
  },
  {
    ip_address: "10.50.0.14",
    hostname: "Unknown",
    is_active: false,
    device_category: "unknown",
    cves: [],
  },
];
const P3_SUMMARY = {
  total_hosts: 3,
  critical_hosts: 1,
  high_risk_hosts: 0,
  scan_duration: 88.2,
  credentialed_hosts: 1,
  credentialed_skipped: [
    { target: "10.50.0.12", reason: "No credential matched" },
  ],
};

const FULL_SCAN = {
  id: "p3-7",
  results: {
    phase2: { data: P2_HOSTS, summary: P2_SUMMARY },
    phase3: { data: P3_HOSTS, summary: P3_SUMMARY },
  },
  report_executive_path: "/reports/p3-7-exec.pdf",
  report_technical_path: "/reports/p3-7-tech.pdf",
};

const base = (extra = {}) => ({
  cc_scanId: "p3-7",
  cc_scanNo: 3207,
  cc_target: "10.50.0.0/28",
  cc_pipelineMode: "vulnerability_audit",
  cc_intensity: "deep",
  cc_phase1Hosts: P1_HOSTS,
  cc_phase1Summary: P1_SUMMARY,
  cc_pipelineState: "DISCOVERY",
  ...extra,
});
const REPORT = base({
  cc_pipelineState: "REPORT_READY",
  cc_phase2Results: P2_HOSTS,
  cc_phase2Summary: P2_SUMMARY,
  cc_phase3AuditResults: P3_HOSTS,
  cc_phase3Summary: P3_SUMMARY,
  cc_pipelinePhaseTimings: { portScan: "40.5", vulnScan: "88.2" },
});

/* ── A WebSocket this file controls ─────────────────────────────────────── */
let sockets;
let calls;
class FakeWebSocket {
  constructor(url) {
    this.url = url;
    this.closeCalls = 0;
    sockets.push(this);
    calls.push(`WS ${url}`);
  }
  close() {
    this.closeCalls += 1;
  }
  frame(phase, status, extra = {}) {
    this.onmessage?.({
      data: JSON.stringify({ phase, progress: { status, ...extra } }),
    });
  }
  fail() {
    this.onerror?.(new Event("error"));
  }
}

/* ── Harness ────────────────────────────────────────────────────────────── */
let postReply;
let getReply;
let consoleError;

const seed = (entries) => {
  for (const [key, value] of Object.entries(entries))
    sessionStorage.setItem(key, JSON.stringify(value));
};
const stored = (key) => JSON.parse(sessionStorage.getItem(key));

const renderPage = (strict = false) => {
  const tree = (
    <ScanProvider>
      <Phase3Results />
    </ScanProvider>
  );
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
};
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
const loaded = async (entries, strict = false) => {
  seed(entries);
  const view = renderPage(strict);
  await flush();
  return view;
};
const advance = async (ms) => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
  await flush();
};
const frame = async (i, phase, status, extra) => {
  await act(async () => {
    sockets[i].frame(phase, status, extra);
  });
  await flush();
};
const runToReport = async (entries = base()) => {
  const view = await loaded(entries);
  await frame(0, 2, "complete");
  await frame(1, 3, "complete");
  return view;
};

const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
// CVELink's new-tab hint is `hidden`: part of textContent, never shown.
const visibleText = (el) => {
  const copy = el.cloneNode(true);
  copy.querySelectorAll("[hidden]").forEach((n) => n.remove());
  return squash(copy);
};
const bodyText = () => squash(document.body);
const layout = () => screen.getByTestId("app-layout");
const saveStatus = () => layout().getAttribute("data-save-status");
const posts = (url) => api.post.mock.calls.filter(([u]) => u === url);
const sectionFor = (re) => screen.getByText(re).closest("section");
const tableIn = (scope, ...headers) =>
  [...scope.querySelectorAll("table")].find((t) => {
    const hs = [...t.querySelectorAll("thead th")].map(squash);
    return headers.every((h) => hs.includes(h));
  });
const headersOf = (t) => [...t.querySelectorAll("thead th")].map(squash);
const cellsOf = (t) =>
  [...t.querySelectorAll("tbody tr")].map((tr) =>
    [...tr.querySelectorAll("td, th")].map(squash),
  );
const button = (scope, re) => within(scope).getByRole("button", { name: re });
const dialog = () => screen.getByRole("dialog");
const openReport = async () => {
  fireEvent.click(screen.getByRole("button", { name: /View Risk Report/ }));
  await flush();
  return dialog();
};

beforeEach(() => {
  sessionStorage.clear();
  sockets = [];
  calls = [];
  locationState = null;
  user = EXECUTOR;
  navigate.mockReset();
  vi.stubGlobal("WebSocket", FakeWebSocket);
  postReply = (url) => {
    if (url === "/auth/ticket") return { data: { ticket: "tk+1" } };
    if (url.endsWith("/stop")) return { data: { success: true } };
    return { data: { success: true } };
  };
  getReply = () => ({ data: FULL_SCAN });
  api.get.mockReset();
  api.get.mockImplementation((url, config) => {
    calls.push(`GET ${url}`);
    const r = getReply(url, config);
    return r instanceof Promise ? r : Promise.resolve(r);
  });
  for (const verb of ["post", "put", "patch", "delete"]) api[verb].mockReset();
  api.post.mockImplementation((url, body, config) => {
    calls.push(`POST ${url}`);
    const r = postReply(url, body, config);
    return r instanceof Promise ? r : Promise.resolve(r);
  });
  consoleError = vi.spyOn(console, "error");
});

afterEach(() => {
  // The pipeline's writes, the ticket and the stop — nothing else, never PUT,
  // PATCH or DELETE; every read is the scan record; every socket is progress.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const [url] of api.post.mock.calls) {
    expect(url).toMatch(
      /^\/scan\/asset-discovery$|^\/scan\/vulnerability-audit$|^\/auth\/ticket$|^\/scans\/p3-7\/stop$/,
    );
  }
  for (const [url] of api.get.mock.calls) expect(url).toBe("/scans/p3-7");
  for (const s of sockets) {
    expect(s.url).toMatch(/^\/api\/scans\/p3-7\/progress\?ticket=tk%2B1$/);
  }
  consoleError.mockRestore();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("Phase3Results — contract", () => {
  describe("mounting and the automatic start", () => {
    it("without discovered hosts, sends the user back to /scan and renders nothing", async () => {
      await loaded({ cc_scanId: "p3-7" });
      expect(navigate).toHaveBeenCalledWith("/scan", { replace: true });
      expect(screen.queryByTestId("app-layout")).toBeNull();
      expect(api.post).not.toHaveBeenCalled();
      expect(sockets).toHaveLength(0);
    });

    it("starts the port scan on mount with the live hosts, intensity, scan id, mode and phases", async () => {
      await loaded(base());
      expect(calls).toEqual([
        "POST /scan/asset-discovery",
        "POST /auth/ticket",
        "WS /api/scans/p3-7/progress?ticket=tk%2B1",
      ]);
      const [url, body, config] = api.post.mock.calls[0];
      expect(url).toBe("/scan/asset-discovery");
      expect(body).toEqual({
        hosts: ACTIVE_P1,
        intensity: "deep",
        scan_id: "p3-7",
        pipeline_mode: "vulnerability_audit",
        phases: [1, 2],
      });
      expect(config.signal).toBeInstanceOf(AbortSignal);
      expect(api.post.mock.calls[1][0]).toBe("/auth/ticket");
      expect(api.post.mock.calls[1][1]).toBeNull();
      expect(api.post.mock.calls[1][2].signal).toBe(config.signal);
      expect(stored("cc_pipelineState")).toBe("PORT_SCAN");
      expect(saveStatus()).toBe("saving");
      expect(layout().getAttribute("data-page-title")).toBe(
        "Vulnerability Audit",
      );
    });

    it("runs the whole pipeline in order, reading the record after each phase", async () => {
      await runToReport();
      expect(calls).toEqual([
        "POST /scan/asset-discovery",
        "POST /auth/ticket",
        "WS /api/scans/p3-7/progress?ticket=tk%2B1",
        "GET /scans/p3-7",
        "POST /scan/vulnerability-audit",
        "POST /auth/ticket",
        "WS /api/scans/p3-7/progress?ticket=tk%2B1",
        "GET /scans/p3-7",
      ]);
      const audit = posts("/scan/vulnerability-audit")[0];
      expect(audit[1]).toEqual({
        hosts: P2_HOSTS,
        scan_id: "p3-7",
        pipeline_mode: "vulnerability_audit",
        vulnerability_profile: "recommended",
        phases: [1, 2, 3],
      });
      expect(audit[2].signal).toBeInstanceOf(AbortSignal);
      for (const [, config] of api.get.mock.calls) {
        expect(config.signal).toBeInstanceOf(AbortSignal);
      }
      expect(sockets.map((s) => s.closeCalls)).toEqual([1, 1]);
      expect(stored("cc_pipelineState")).toBe("REPORT_READY");
      expect(stored("cc_phase2Results")).toEqual(P2_HOSTS);
      expect(stored("cc_phase2Summary")).toEqual(P2_SUMMARY);
      expect(stored("cc_phase3AuditResults")).toEqual(P3_HOSTS);
      expect(stored("cc_phase3Summary")).toEqual(P3_SUMMARY);
      const timings = stored("cc_pipelinePhaseTimings");
      expect(timings.portScan).toMatch(/^\d+\.\d$/);
      expect(timings.vulnScan).toMatch(/^\d+\.\d$/);
      expect(saveStatus()).toBe("saved");
      expect(
        screen.getByRole("button", { name: /View Risk Report/ }),
      ).toBeTruthy();
    });

    it("clears the saved indicator 4 s after the pipeline completes", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      await runToReport();
      expect(saveStatus()).toBe("saved");
      await advance(3999);
      expect(saveStatus()).toBe("saved");
      await advance(1);
      expect(saveStatus()).toBe("");
    });

    it("ignores frames for another phase and frames that are not terminal", async () => {
      await loaded(base());
      await act(async () => {
        sockets[0].frame(3, "complete");
        sockets[0].frame(2, "running");
        sockets[0].frame(2, "queued");
      });
      await flush();
      expect(api.get).not.toHaveBeenCalled();
      expect(sockets[0].closeCalls).toBe(0);
      expect(stored("cc_pipelineState")).toBe("PORT_SCAN");
    });

    it("starts the audit directly from an audit queue, auditing the queue", async () => {
      await loaded(base({ cc_phase3Results: P2_HOSTS.slice(0, 1) }));
      expect(calls[0]).toBe("POST /scan/vulnerability-audit");
      expect(posts("/scan/asset-discovery")).toHaveLength(0);
      expect(posts("/scan/vulnerability-audit")[0][1].hosts).toEqual(
        P2_HOSTS.slice(0, 1),
      );
      expect(stored("cc_pipelineState")).toBe("VULN_SCAN");
    });

    it("with an audit queue and port-scan results, audits the port-scan results", async () => {
      await loaded(
        base({
          cc_phase3Results: P2_HOSTS.slice(0, 1),
          cc_phase2Results: P2_HOSTS,
        }),
      );
      expect(posts("/scan/vulnerability-audit")[0][1].hosts).toEqual(P2_HOSTS);
    });

    it.each([
      ["a running port scan", { cc_pipelineState: "PORT_SCAN" }],
      ["a running audit", { cc_pipelineState: "VULN_SCAN" }],
      ["a finished report", { cc_pipelineState: "REPORT_READY" }],
      ["a completed pipeline", { cc_pipelineState: "COMPLETE" }],
      ["audit results", { cc_phase3AuditResults: P3_HOSTS }],
      ["port-scan results and no audit queue", { cc_phase2Results: P2_HOSTS }],
      [
        "no live host",
        {
          cc_phase1Hosts: P1_HOSTS.map((h) => ({ ...h, is_active: false })),
        },
      ],
    ])("does not start with %s", async (_, extra) => {
      await loaded(base(extra));
      expect(api.post).not.toHaveBeenCalled();
      expect(sockets).toHaveLength(0);
    });

    it("a route-level start phase wins over a stale running state and port-scan results", async () => {
      locationState = { startPhase: "PORT_SCAN" };
      await loaded(
        base({ cc_pipelineState: "PORT_SCAN", cc_phase2Results: P2_HOSTS }),
      );
      expect(calls[0]).toBe("POST /scan/asset-discovery");
    });

    it("a route-level start never restarts a finished pipeline", async () => {
      locationState = { startPhase: "PORT_SCAN" };
      await loaded(base({ cc_pipelineState: "REPORT_READY" }));
      expect(api.post).not.toHaveBeenCalled();
    });

    it("a route-level audit start carries the requested vulnerability profile", async () => {
      locationState = { startPhase: "VULN_SCAN", vulnerabilityProfile: "deep" };
      await loaded(base({ cc_phase2Results: P2_HOSTS }));
      expect(posts("/scan/asset-discovery")).toHaveLength(0);
      expect(posts("/scan/vulnerability-audit")[0][1]).toEqual({
        hosts: P2_HOSTS,
        scan_id: "p3-7",
        pipeline_mode: "vulnerability_audit",
        vulnerability_profile: "deep",
        phases: [1, 2, 3],
      });
    });

    it("starts exactly once, under StrictMode and across re-renders", async () => {
      await loaded(base(), true);
      expect(posts("/scan/asset-discovery")).toHaveLength(1);
      expect(posts("/auth/ticket")).toHaveLength(1);
      expect(sockets).toHaveLength(1);
      fireEvent.click(screen.getByRole("button", { name: /^All \(4\)$/ }));
      await flush();
      expect(posts("/scan/asset-discovery")).toHaveLength(1);
    });

    it("without scans:execute, requests nothing and reports an authorization failure", async () => {
      user = VIEWER;
      await loaded(base());
      expect(api.post).not.toHaveBeenCalled();
      expect(sockets).toHaveLength(0);
      expect(stored("cc_pipelineState")).toBe("ERROR");
      expect(stored("cc_pipelineError")).toEqual({
        phase: "AUTHORIZATION",
        message: "You do not have permission to perform this action.",
      });
      expect(bodyText()).toMatch(/Pipeline failed at Vulnerability Audit/);
      expect(bodyText()).toMatch(
        /You do not have permission to perform this action\./,
      );
    });
  });

  describe("failures", () => {
    it.each([
      [
        "with its error",
        { success: false, error: "Scope refused" },
        "Scope refused",
      ],
      ["without one", { success: false }, "Port scan trigger failed"],
    ])(
      "a refused port-scan trigger %s fails the port scan, with no ticket",
      async (_, reply, message) => {
        postReply = (url) =>
          url === "/scan/asset-discovery" ? { data: reply } : { data: {} };
        await loaded(base());
        expect(posts("/auth/ticket")).toHaveLength(0);
        expect(stored("cc_pipelineError")).toEqual({
          phase: "PORT_SCAN",
          message,
        });
        expect(bodyText()).toMatch(/Pipeline failed at Port Scan/);
        expect(bodyText()).toContain(message);
        expect(saveStatus()).toBe("error");
      },
    );

    it("clears the error indicator 4 s later", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      postReply = () => ({ data: { success: false } });
      await loaded(base());
      expect(saveStatus()).toBe("error");
      await advance(4000);
      expect(saveStatus()).toBe("");
    });

    it.each([
      [2, "Port scan background task failed.", "PORT_SCAN"],
      [3, "Vulnerability audit background task failed.", "VULN_SCAN"],
    ])(
      "a failed phase %i frame fails that phase and closes its socket",
      async (phase, message, errorPhase) => {
        await loaded(base());
        if (phase === 3) await frame(0, 2, "complete");
        await frame(phase - 2, phase, "failed");
        expect(stored("cc_pipelineError")).toEqual({
          phase: errorPhase,
          message,
        });
        expect(sockets[phase - 2].closeCalls).toBe(1);
      },
    );

    it.each([
      ["port scan", "phase2", "Port scan completed but returned no hosts."],
      [
        "audit",
        "phase3",
        "Vulnerability audit completed but returned no hosts.",
      ],
    ])(
      "a %s with no hosts in the record fails",
      async (label, key, message) => {
        getReply = () => ({
          data: {
            results: {
              ...FULL_SCAN.results,
              [key]: { data: [], summary: {} },
            },
          },
        });
        await loaded(base());
        await frame(0, 2, "complete");
        if (key === "phase3") await frame(1, 3, "complete");
        expect(stored("cc_pipelineError").message).toBe(message);
      },
    );

    it("a socket error fails the phase", async () => {
      await loaded(base());
      await act(async () => sockets[0].fail());
      await flush();
      expect(stored("cc_pipelineError")).toEqual({
        phase: "PORT_SCAN",
        message: "Phase 2 WebSocket failed",
      });
      expect(sockets[0].closeCalls).toBe(1);
    });

    it("a phase that reports nothing for 20 minutes times out", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      await loaded(base());
      await advance(1_199_999);
      expect(stored("cc_pipelineState")).toBe("PORT_SCAN");
      await advance(1);
      expect(stored("cc_pipelineError")).toEqual({
        phase: "PORT_SCAN",
        message: "Phase 2 timed out",
      });
    });

    it("a rejected request reports the API's detail, else its message", async () => {
      postReply = (url) =>
        url === "/scan/asset-discovery"
          ? Promise.reject({ response: { data: { detail: "Quota exceeded" } } })
          : { data: {} };
      await loaded(base());
      expect(stored("cc_pipelineError").message).toBe("Quota exceeded");
      cleanup();
      sessionStorage.clear();

      postReply = (url) =>
        url === "/auth/ticket"
          ? Promise.reject(new Error("ticket refused"))
          : { data: { success: true } };
      await loaded(base());
      expect(stored("cc_pipelineError")).toEqual({
        phase: "PORT_SCAN",
        message: "ticket refused",
      });
    });

    it("retries from the failed phase: the audit alone, or the port scan again", async () => {
      await loaded(
        base({
          cc_pipelineState: "ERROR",
          cc_pipelineError: { phase: "VULN_SCAN", message: "boom" },
          cc_phase2Results: P2_HOSTS,
        }),
      );
      expect(api.post).not.toHaveBeenCalled();
      fireEvent.click(
        screen.getByRole("button", { name: /Retry from Vulnerability Audit/ }),
      );
      await flush();
      expect(calls[0]).toBe("POST /scan/vulnerability-audit");
      expect(posts("/scan/asset-discovery")).toHaveLength(0);
      cleanup();
      sessionStorage.clear();
      calls = [];
      api.post.mockClear();

      await loaded(
        base({
          cc_pipelineState: "ERROR",
          cc_pipelineError: { phase: "PORT_SCAN", message: "boom" },
          cc_phase2Results: P2_HOSTS,
        }),
      );
      fireEvent.click(
        screen.getByRole("button", { name: /Retry from Port Scan/ }),
      );
      await flush();
      expect(calls[0]).toBe("POST /scan/asset-discovery");
    });

    it("restarting the full pipeline clears every result and starts the port scan", async () => {
      await loaded(
        base({
          cc_pipelineState: "ERROR",
          cc_pipelineError: { phase: "VULN_SCAN", message: "boom" },
          cc_phase2Results: P2_HOSTS,
          cc_phase2Summary: P2_SUMMARY,
        }),
      );
      fireEvent.click(
        screen.getByRole("button", { name: /Restart Full Pipeline/ }),
      );
      await flush();
      expect(calls[0]).toBe("POST /scan/asset-discovery");
      expect(stored("cc_phase2Results")).toEqual([]);
      expect(stored("cc_phase2Summary")).toBeNull();
      expect(stored("cc_phase3AuditResults")).toEqual([]);
      expect(stored("cc_pipelineError")).toBeNull();
    });
  });

  describe("cancelling and unmounting", () => {
    it("Cancel aborts the running phase, stops the scan and shows it cancelled", async () => {
      await loaded(base());
      fireEvent.click(screen.getByRole("button", { name: /Cancel Scan/ }));
      await flush();
      expect(sockets[0].closeCalls).toBe(1);
      expect(posts("/scans/p3-7/stop")).toEqual([["/scans/p3-7/stop"]]);
      expect(stored("cc_pipelineState")).toBe("CANCELLED");
      expect(bodyText()).toMatch(/Scan Cancelled/);
      expect(bodyText()).toMatch(/The pipeline was stopped by user request\./);
      expect(screen.queryByRole("button", { name: /Cancel Scan/ })).toBeNull();
    });

    it("a refused stop is logged and the scan still reads cancelled", async () => {
      const refusal = new Error("stop refused");
      postReply = (url) =>
        url.endsWith("/stop")
          ? Promise.reject(refusal)
          : url === "/auth/ticket"
            ? { data: { ticket: "tk+1" } }
            : { data: { success: true } };
      consoleError.mockImplementation(() => {});
      await loaded(base());
      fireEvent.click(screen.getByRole("button", { name: /Cancel Scan/ }));
      await flush();
      expect(console.error).toHaveBeenCalledWith(
        "Failed to stop scan in backend:",
        refusal,
      );
      expect(stored("cc_pipelineState")).toBe("CANCELLED");
    });

    it("the cancelled view restarts the pipeline or goes back to a new scan", async () => {
      await loaded(
        base({ cc_pipelineState: "CANCELLED", cc_phase2Results: P2_HOSTS }),
      );
      expect(api.post).not.toHaveBeenCalled();
      fireEvent.click(screen.getByRole("button", { name: /New Scan/ }));
      expect(navigate).toHaveBeenCalledWith("/scan");
      fireEvent.click(screen.getByRole("button", { name: /Restart Pipeline/ }));
      await flush();
      expect(calls[0]).toBe("POST /scan/asset-discovery");
    });

    it("unmounting does not stop the pipeline: the socket stays open and a later frame still reads the record", async () => {
      const view = await loaded(base());
      view.unmount();
      expect(sockets[0].closeCalls).toBe(0);
      await frame(0, 2, "complete");
      expect(api.get).toHaveBeenCalledTimes(1);
    });

    it("Back returns to /scan", async () => {
      await loaded(REPORT);
      fireEvent.click(screen.getByRole("button", { name: /Back/ }));
      expect(navigate).toHaveBeenCalledWith("/scan");
    });
  });

  describe("progress, error and banners", () => {
    it("shows the running phase with its detail, and Cancel only while scanning", async () => {
      await loaded(base({ cc_pipelineState: "PORT_SCAN" }));
      expect(bodyText()).toMatch(/Running Port Scan…/);
      expect(bodyText()).toMatch(
        /Mapping open TCP services and grabbing banners\./,
      );
      expect(bodyText()).toMatch(/Phase 2 of 3 · Intensity: deep/);
      expect(screen.getByRole("button", { name: /Cancel Scan/ })).toBeTruthy();
      cleanup();
      sessionStorage.clear();

      await loaded(
        base({ cc_pipelineState: "VULN_SCAN", cc_phase2Results: P2_HOSTS }),
      );
      expect(bodyText()).toMatch(/Running Vulnerability Audit…/);
      expect(bodyText()).toMatch(
        /Analyzing services for CVEs and security risks\./,
      );
      expect(bodyText()).toMatch(/Phase 3 of 3 · 3 hosts queued for audit/);
      cleanup();
      sessionStorage.clear();

      await loaded(
        base({
          cc_pipelineState: "VULN_SCAN",
          cc_phase2Results: P2_HOSTS.slice(0, 1),
        }),
      );
      expect(bodyText()).toMatch(/1 host queued for audit/);
      cleanup();
      sessionStorage.clear();

      await loaded(REPORT);
      expect(screen.queryByRole("button", { name: /Cancel Scan/ })).toBeNull();
      expect(bodyText()).not.toMatch(/Running /);
    });

    it("an error names its phase and offers retry and restart", async () => {
      await loaded(
        base({
          cc_pipelineState: "ERROR",
          cc_pipelineError: { phase: "PORT_SCAN", message: "Scanner offline" },
          cc_phase2Results: P2_HOSTS,
        }),
      );
      expect(bodyText()).toMatch(/Pipeline failed at Port Scan/);
      expect(bodyText()).toContain("Scanner offline");
      expect(
        screen.getByRole("button", { name: /Retry from Port Scan/ }),
      ).toBeTruthy();
      expect(
        screen.getByRole("button", { name: /Restart Full Pipeline/ }),
      ).toBeTruthy();
    });

    it("warns that the host is unreachable when discovery found nothing live", async () => {
      await loaded(
        base({
          cc_phase1Hosts: P1_HOSTS.map((h) => ({ ...h, is_active: false })),
          cc_phase1Summary: {
            total_hosts: 4,
            active_hosts: 0,
            inactive_hosts: 4,
          },
        }),
      );
      expect(bodyText()).toMatch(/Host is unavailable\/down\/unreachable/);
      expect(bodyText()).toMatch(
        /The automated pipeline stopped because Phase 1 \(Discovery\) found no active hosts\. Verify the target network and probes before re-scanning\./,
      );
      cleanup();
      sessionStorage.clear();

      await loaded(
        base({
          cc_pipelineState: "REPORT_READY",
          cc_phase1Summary: { status: "unreachable" },
        }),
      );
      expect(bodyText()).toMatch(/Host is unavailable/);
      cleanup();
      sessionStorage.clear();

      await loaded(REPORT);
      expect(bodyText()).not.toMatch(/Host is unavailable/);
    });
  });

  describe("results", () => {
    it("heads the page with the target and marks the stepper by what has results", async () => {
      await loaded(REPORT);
      expect(bodyText()).toMatch(
        /Full pipeline execution from 10\.50\.0\.0\/28/,
      );
      expect(
        screen.getByTestId("scan-stepper").getAttribute("data-current"),
      ).toBe("3");
      cleanup();
      sessionStorage.clear();
      await loaded(
        base({ cc_pipelineState: "PORT_SCAN", cc_phase2Results: P2_HOSTS }),
      );
      expect(
        screen.getByTestId("scan-stepper").getAttribute("data-current"),
      ).toBe("2");
      cleanup();
      sessionStorage.clear();
      await loaded(base({ cc_pipelineState: "PORT_SCAN" }));
      expect(
        screen.getByTestId("scan-stepper").getAttribute("data-current"),
      ).toBe("1");
    });

    it("summarises discovery from its summary, or counts the hosts", async () => {
      await loaded(REPORT);
      const text = bodyText();
      expect(text).toMatch(/4 Total discovered/);
      expect(text).toMatch(/3 Active/);
      expect(text).toMatch(/1 Inactive/);
      expect(text).toMatch(/12\.3s Discovery time/);
      cleanup();
      sessionStorage.clear();
      await loaded({ ...REPORT, cc_phase1Summary: null });
      expect(bodyText()).toMatch(/4 Total discovered/);
      expect(bodyText()).toMatch(/—s Discovery time/);
    });

    it("lists discovered hosts with name fallbacks, active by default, all on request", async () => {
      await loaded(REPORT);
      const section = sectionFor(/1\. Discovery Results/);
      const table = () =>
        tableIn(
          section,
          "IP Address",
          "Hostname",
          "MAC",
          "Vendor",
          "Method",
          "Status",
        );
      expect(headersOf(table())).toEqual([
        "IP Address",
        "Hostname",
        "MAC",
        "Vendor",
        "Method",
        "Status",
      ]);
      expect(cellsOf(table())).toEqual([
        [
          "10.50.0.11",
          "web-01",
          "00:1A:2B:3C:4D:11",
          "Dell Inc.",
          "ARP",
          "Active",
        ],
        [
          "10.50.0.12",
          "printer-2f.local",
          "00:1A:2B:3C:4D:12",
          "HP",
          "ICMP",
          "Active",
        ],
        ["10.50.0.13", "KIOSK-07", "—", "—", "TCP", "Active"],
      ]);
      fireEvent.click(button(section, /^All \(4\)$/));
      await flush();
      expect(cellsOf(table()).at(-1)).toEqual([
        "10.50.0.14",
        "Unknown",
        "—",
        "—",
        "ICMP",
        "Inactive",
      ]);
      fireEvent.click(button(section, /^Active \(3\)$/));
      await flush();
      expect(cellsOf(table())).toHaveLength(3);
    });

    it("lists port-scan results with their summary, services and OS", async () => {
      await loaded(REPORT);
      const section = sectionFor(/2\. Port Scan Results/);
      const text = squash(section);
      expect(text).toMatch(/Open services discovered during Phase 2\./);
      expect(text).toMatch(/40\.5s/);
      expect(text).toMatch(/3 Hosts scanned/);
      expect(text).toMatch(/2 Have open ports/);
      expect(text).toMatch(/40\.5s Duration/);
      const table = () => tableIn(section, "IP Address", "Open Ports");
      expect(headersOf(table())).toEqual([
        "IP Address",
        "Hostname",
        "Open Ports",
        "OS (Guess)",
      ]);
      expect(cellsOf(table())).toEqual([
        ["10.50.0.11", "web-01", "22/ssh, 443/https", "Linux 5.x"],
        ["10.50.0.12", "printer-2f.local", "9100/jetdirect", "HP embedded"],
      ]);
      fireEvent.click(button(section, /^All \(3\)$/));
      await flush();
      expect(cellsOf(table()).at(-1)).toEqual([
        "10.50.0.14",
        "Unknown",
        "—",
        "—",
      ]);
    });

    it("shows no port or audit section without their results", async () => {
      await loaded(base({ cc_pipelineState: "PORT_SCAN" }));
      expect(screen.queryByText(/2\. Port Scan Results/)).toBeNull();
      expect(screen.queryByText(/3\. Vulnerability Results/)).toBeNull();
    });

    it("summarises the audit, its authenticated coverage and the hosts it skipped", async () => {
      await loaded(REPORT);
      const section = sectionFor(/3\. Vulnerability Results/);
      const text = squash(section);
      expect(text).toMatch(/88\.2s/);
      expect(text).toMatch(/3 Audited/);
      expect(text).toMatch(/1 Critical/);
      expect(text).toMatch(/0 High risk/);
      expect(text).toMatch(/88\.2s Duration/);
      expect(text).toMatch(/1 Authenticated/);
      expect(text).toMatch(/Authenticated checks/);
      expect(text).toMatch(
        /1 host was logged into and assessed against the installed-package inventory\. Listening services on those hosts were correlated with the port scan, so exposed services are distinguished from ones that are running but unreachable\./,
      );
      expect(text).toMatch(
        /1 host not authenticated — findings for these are network-only/,
      );
      expect(text).toMatch(/10\.50\.0\.12 — No credential matched/);

      cleanup();
      sessionStorage.clear();
      await loaded({
        ...REPORT,
        cc_phase3Summary: {
          ...P3_SUMMARY,
          credentialed_hosts: 2,
          credentialed_skipped: [],
        },
      });
      const again = squash(sectionFor(/3\. Vulnerability Results/));
      expect(again).toMatch(/2 hosts were logged into/);
      expect(again).not.toMatch(/not authenticated/);

      cleanup();
      sessionStorage.clear();
      await loaded({ ...REPORT, cc_phase3Summary: { total_hosts: 3 } });
      expect(squash(sectionFor(/3\. Vulnerability Results/))).not.toMatch(
        /Authenticated/,
      );
    });

    it("lists audited hosts with authentication, device, OS, CVE and finding counts, and risk", async () => {
      await loaded(REPORT);
      const section = sectionFor(/3\. Vulnerability Results/);
      const table = () => tableIn(section, "IP Address", "Device", "Risk");
      expect(headersOf(table())).toEqual([
        "IP Address",
        "Device",
        "Operating System",
        "CVEs / Active",
        "Risk",
      ]);
      const rows = cellsOf(table());
      expect(rows[0][0]).toMatch(/^10\.50\.0\.11\s*🔐\s*AUTH\s*web-01$/);
      expect(rows[0][1]).toMatch(/^🖥\s*Server$/);
      expect(rows[0][2]).toBe("Ubuntu 22.04");
      expect(rows[0][3]).toMatch(/^5\s*⚡\s*10 active$/);
      expect(rows[0][4]).toBe("Critical");
      expect(rows[1]).toEqual([
        "10.50.0.12",
        expect.stringMatching(/^🖨\s*Printer$/),
        "Unknown",
        "0",
        "Low",
      ]);
      expect(
        screen.getByText(/AUTH/).closest("[title]").getAttribute("title"),
      ).toBe(
        "Authenticated — 2 listening service(s) confirmed reachable, 1 host-only",
      );
      expect(
        screen
          .getByText(/Server$/)
          .closest("[title]")
          .getAttribute("title"),
      ).toBe("Classified via: banner");
      expect(
        screen
          .getByText(/Printer$/)
          .closest("[title]")
          .getAttribute("title"),
      ).toBe("Classified via: unknown");
      fireEvent.click(button(section, /^All \(3\)$/));
      await flush();
      expect(cellsOf(table()).at(-1)).toEqual([
        "10.50.0.14",
        "—",
        "—",
        "0",
        "Info",
      ]);
    });

    it("titles an authenticated host that was not correlated with the port scan", async () => {
      await loaded({
        ...REPORT,
        cc_phase3AuditResults: [{ ...P3_HOSTS[0], exposure_summary: {} }],
      });
      expect(
        screen.getByText(/AUTH/).closest("[title]").getAttribute("title"),
      ).toBe("Authenticated audit of the installed package inventory");
    });

    it("offers the risk report only once the pipeline is done with results", async () => {
      await loaded(REPORT);
      expect(
        screen.getByRole("button", { name: /View Risk Report/ }),
      ).toBeTruthy();
      cleanup();
      sessionStorage.clear();
      await loaded({ ...REPORT, cc_pipelineState: "VULN_SCAN" });
      expect(
        screen.queryByRole("button", { name: /View Risk Report/ }),
      ).toBeNull();
      cleanup();
      sessionStorage.clear();
      await loaded({
        ...REPORT,
        cc_phase3AuditResults: [],
        cc_pipelineState: "COMPLETE",
      });
      expect(
        screen.queryByRole("button", { name: /View Risk Report/ }),
      ).toBeNull();
    });
  });

  describe("the risk report", () => {
    it("is titled with the scan number and target", async () => {
      await loaded(REPORT);
      const d = await openReport();
      const text = squash(d);
      expect(text).toMatch(/Risk Report - Full Assessment/);
      expect(text).toMatch(/Scan No\. 3207 - Target: 10\.50\.0\.0\/28/);
      expect(text).toMatch(/Full Pipeline Complete/);
      expect(text).toMatch(
        /All scan phases finished successfully\. Complete vulnerability analysis and risk assessment below\./,
      );
    });

    it("counts hosts, CVEs, risk bands, timings and severities", async () => {
      await loaded(REPORT);
      const text = squash(await openReport());
      expect(text).toMatch(/Total Hosts Audited\s*3/);
      expect(text).toMatch(/Total CVEs Found\s*5/);
      expect(text).toMatch(/Critical Risk Hosts\s*1/);
      expect(text).toMatch(/High Risk Hosts\s*0/);
      expect(text).toMatch(/Scan Timeline/);
      expect(text).toMatch(/Phase 1: Discovery\s*12\.3s/);
      expect(text).toMatch(/Phase 2: Port Scan\s*40\.5s/);
      expect(text).toMatch(/Phase 3: Vulnerability Audit\s*88\.2s/);
      expect(text).toMatch(/Vulnerability Severity Distribution/);
      for (const band of ["Critical", "High", "Medium", "Low", "Info"]) {
        expect(text).toMatch(new RegExp(`1\\s*${band}`));
      }
    });

    it("shows missing timings as a dash", async () => {
      await loaded({ ...REPORT, cc_pipelinePhaseTimings: {} });
      const text = squash(await openReport());
      expect(text).toMatch(/Phase 2: Port Scan\s*—s/);
      expect(text).toMatch(/Phase 3: Vulnerability Audit\s*—s/);
    });

    it("lists every audited host", async () => {
      await loaded(REPORT);
      const d = await openReport();
      expect(squash(d)).toMatch(/Affected Hosts \(3 total\)/);
      const table = tableIn(d, "IP Address", "Vulnerabilities", "Status");
      expect(headersOf(table)).toEqual([
        "IP Address",
        "Hostname",
        "Open Ports",
        "OS",
        "Vulnerabilities",
        "Risk",
        "Status",
      ]);
      expect(cellsOf(table)).toEqual([
        [
          "10.50.0.11",
          "web-01",
          "3",
          "Ubuntu 22.04",
          "5",
          "Critical",
          expect.stringMatching(/^✓\s*Active$/),
        ],
        [
          "10.50.0.12",
          "Not detected",
          "—",
          "Not detected",
          "0",
          "Low",
          expect.stringMatching(/^✓\s*Active$/),
        ],
        [
          "10.50.0.14",
          "Not detected",
          "—",
          "Not detected",
          "0",
          "Info",
          expect.stringMatching(/^○\s*Inactive$/),
        ],
      ]);
    });

    it("details each host with findings: misconfigurations, FTP, HTTP and CVEs", async () => {
      await loaded(REPORT);
      const text = visibleText(await openReport());
      expect(text).toMatch(/Detailed Vulnerability Analysis/);
      expect(text).toMatch(/10\.50\.0\.11\s*web-01\s*Critical Risk/);
      expect(text).toMatch(/Active Misconfiguration Findings/);
      for (const label of [
        "Heartbleed",
        "LDAP Anon Bind",
        "FTP Anon Login",
        "FTP Write Access",
        "FTP Weak Creds (2)",
        "Exposed Paths (2)",
        "Admin Panels (1)",
        "Dangerous HTTP Methods",
        "SMB Null Session",
        "TLS Cert Expired",
      ]) {
        expect(text).toContain(label);
      }
      expect(text).not.toMatch(/EternalBlue|DNS Zone Transfer/);
      expect(text).toMatch(/FTP Service/);
      expect(text).toContain(`Banner: 220 ${"x".repeat(116)}...`);
      expect(text).not.toContain("x".repeat(117));
      expect(text).toMatch(/• Anonymous login allowed/);
      expect(text).toMatch(
        /Weak credentials accepted:\s*ftpuser\/\*\*\*\*\*\*\*\*\s*user\/\*\*\*\*\*\*\*\*/,
      );
      expect(text).toMatch(/HTTP Service/);
      expect(text).toMatch(/Server: nginx\/1\.18\.0/);
      for (const issue of [
        "Missing CSP",
        "Missing HSTS",
        "Missing X-Frame-Options",
        "Missing Referrer-Policy",
      ]) {
        expect(text).toContain(`• ${issue}`);
      }
      expect(text).not.toContain("Missing Permissions-Policy");
      expect(text).toMatch(
        /Exposed Paths:\s*\/\.git\/config \[200\]\s*\/backup\/ \[200\]\s*📂/,
      );
      expect(text).toMatch(
        /Admin Panels Detected:\s*⚙️?\s*Tomcat Manager @ \/manager\/html \(HTTP 401\)/,
      );
      expect(text).toMatch(/Dangerous Methods:\s*PUT \| DELETE/);
      expect(text).toMatch(/CVEs/);
      expect(text).toMatch(
        /CVE-2024-6387\s*Critical\s*CVSS Score:\s*8\.1\/10\s*Signal handler race in sshd\s*Affected: OpenSSH 8\.9p1/,
      );
      // The fixture's lowercase "high": the band is pinned, and only its first
      // letter may change case (the batch 24 block pins the rendered label).
      expect(text).toMatch(/CVE-2023-0286\s*[Hh]igh\s*CVSS Score:\s*7\.4\/10/);
      expect(text).toMatch(/CVE-2023-2650\s*Medium\s*CCURE-CHK-NOTE/);
      expect(text).toMatch(/CVE-2023-1\s*Info/);
      const link = within(dialog()).getByRole("link", {
        name: "CVE-2024-6387",
      });
      expect(link.getAttribute("href")).toBe(
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
      );
      expect(text).not.toMatch(/10\.50\.0\.12\s*Not detected\s*Low Risk/);
    });

    it("never renders a weak credential's password", async () => {
      await loaded(REPORT);
      await openReport();
      expect(document.documentElement.outerHTML).not.toContain("placeholder");
    });

    it("sums the report and says so when no host has a finding", async () => {
      await loaded(REPORT);
      const text = squash(await openReport());
      expect(text).toMatch(/Report Summary/);
      for (const line of [
        "Total hosts scanned: 3",
        "Hosts with vulnerabilities: 1",
        "Total CVEs identified: 5",
        "Critical severity: 1",
        "High severity: 1",
        "FTP misconfigurations: 1 host(s)",
        "HTTP exposed paths: 2",
        "HTTP admin panels found: 1",
        "Active misconfiguration findings: 10",
      ]) {
        expect(text).toContain(line);
      }
      expect(text).toMatch(
        /Tip: Close this modal and navigate to Scan History to export full PDF\/XML reports with additional formatting and charts\./,
      );
      cleanup();
      sessionStorage.clear();
      await loaded({
        ...REPORT,
        cc_phase3AuditResults: [P3_HOSTS[1], P3_HOSTS[2]],
      });
      expect(squash(await openReport())).toMatch(
        /No vulnerabilities found in this scan\./,
      );
    });

    it.each([
      [
        "its close button",
        () =>
          fireEvent.click(
            within(dialog()).getByRole("button", { name: "Close" }),
          ),
      ],
      ["Escape", () => fireEvent.keyDown(document, { key: "Escape" })],
      ["a click outside it", () => fireEvent.click(dialog().parentElement)],
    ])("closes with %s", async (_, close) => {
      await loaded(REPORT);
      await openReport();
      close();
      await flush();
      expect(screen.queryByRole("dialog")).toBeNull();
    });

    it("does not close on a click inside it", async () => {
      await loaded(REPORT);
      const d = await openReport();
      fireEvent.click(within(d).getByText(/Report Summary/));
      await flush();
      expect(screen.queryByRole("dialog")).not.toBeNull();
    });
  });

  describe("routes", () => {
    it("App.jsx mounts both routes behind the base sign-in check only", () => {
      const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
      const baseAt = app.indexOf("<Route element={<PrivateRoute />}>");
      const firstGate = app.indexOf("requiredPermission", baseAt);
      for (const re of [
        /<Route\s+path="\/scan\/vulnerability-audit"\s+element=\{<Phase3Results \/>\}\s*\/>/,
        /<Route\s+path="\/scan\/:scanId\/phase3"\s+element=\{<Phase3Results \/>\}\s*\/>/,
      ]) {
        const at = app.search(re);
        expect(at).toBeGreaterThan(baseAt);
        expect(at).toBeLessThan(firstGate);
      }
      expect(app.match(/<Phase3Results\b/g)).toHaveLength(2);
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 24 — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const ERROR_STATE = base({
  cc_pipelineState: "ERROR",
  cc_pipelineError: { phase: "PORT_SCAN", message: "Scanner offline" },
  cc_phase2Results: P2_HOSTS,
});

describe("Phase3Results — batch 24", () => {
  it("has one level-one heading and a level-two heading per result section", async () => {
    await loaded(REPORT);
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(
      screen.getByRole("heading", { level: 1, name: "Vulnerability Audit" }),
    ).toBeTruthy();
    for (const name of [
      "1. Discovery Results",
      "2. Port Scan Results",
      "3. Vulnerability Results",
    ]) {
      expect(screen.getByRole("heading", { level: 2, name })).toBeTruthy();
    }
  });

  it("groups each result filter and states which option is selected", async () => {
    await loaded(REPORT);
    for (const name of [
      "Show discovered hosts",
      "Show port-scanned hosts",
      "Show audited hosts",
    ]) {
      const group = screen.getByRole("group", { name });
      const [active, all] = within(group).getAllByRole("button");
      expect(active.getAttribute("aria-pressed")).toBe("true");
      expect(all.getAttribute("aria-pressed")).toBe("false");
    }
  });

  it("captions every table and scopes its column headers", async () => {
    await loaded(REPORT);
    await openReport();
    const tables = [...document.querySelectorAll("table")];
    for (const t of tables) {
      expect(squash(t.querySelector("caption"))).not.toBe("");
      for (const th of t.querySelectorAll("thead th")) {
        expect(th.getAttribute("scope")).toBe("col");
      }
    }
    expect(tables).toHaveLength(4);
  });

  it("reports the running phase as a status with a named progress bar", async () => {
    await loaded(base({ cc_pipelineState: "PORT_SCAN" }));
    const bar = screen.getByRole("progressbar", { name: "Running Port Scan…" });
    expect(bar.getAttribute("aria-valuenow")).toBeNull();
    expect(squash(screen.getByRole("status"))).toMatch(/Running Port Scan…/);
  });

  it("announces a pipeline failure and an unreachable host", async () => {
    await loaded(ERROR_STATE);
    expect(squash(screen.getByRole("alert"))).toMatch(
      /Pipeline failed at Port Scan.*Scanner offline/,
    );
    cleanup();
    sessionStorage.clear();
    await loaded(
      base({
        cc_phase1Hosts: P1_HOSTS.map((h) => ({ ...h, is_active: false })),
        cc_phase1Summary: { total_hosts: 4, active_hosts: 0 },
      }),
    );
    expect(squash(screen.getByRole("alert"))).toMatch(
      /Host is unavailable\/down\/unreachable/,
    );
  });

  it("presents risk and severity as severity badges, and findings as badges", async () => {
    await loaded(REPORT);
    const section = sectionFor(/3\. Vulnerability Results/);
    expect(section.querySelectorAll(".cc-sev").length).toBeGreaterThanOrEqual(
      2,
    );
    expect(
      within(section)
        .getByText(/Printer/)
        .closest(".cc-badge"),
    ).not.toBeNull();
    const d = await openReport();
    expect(d.querySelector(".cc-sev--critical")).not.toBeNull();
    // The API's lowercase "high" is the design system's High band.
    const cve = within(d).getByText("CVE-2023-0286").closest("li");
    expect(squash(cve.querySelector(".cc-sev--high"))).toBe("High");
    expect(
      within(d).getByText("Heartbleed").closest(".cc-badge"),
    ).not.toBeNull();
  });

  it("the risk report is a named dialog described by its subtitle, with sub-headings", async () => {
    await loaded(REPORT);
    const d = await openReport();
    expect(
      screen.getByRole("dialog", { name: "Risk Report - Full Assessment" }),
    ).toBe(d);
    const described = document.getElementById(
      d.getAttribute("aria-describedby"),
    );
    expect(squash(described)).toBe("Scan No. 3207 - Target: 10.50.0.0/28");
    for (const name of [
      "Scan Timeline",
      "Vulnerability Severity Distribution",
      "Affected Hosts (3 total)",
      "Detailed Vulnerability Analysis",
      "Report Summary",
    ]) {
      expect(within(d).getByRole("heading", { level: 3, name })).toBeTruthy();
    }
    expect(within(d).getAllByRole("term").map(squash)).toContain(
      "Total CVEs Found",
    );
  });

  it("hides decorative glyphs from assistive technology", async () => {
    const glyphs =
      /[✕←✓↻↺⏹⚠📊🔐⚡📂🌐💉💣🔓📡✍🔑📁⚙🔧🗂🔒🖥🔍📈📄○→🔀🔗🛡🖨💻📞💾🔌🏭❓]/u;
    const exposed = () => {
      const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
      );
      const out = [];
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        if (
          glyphs.test(n.textContent) &&
          !n.parentElement.closest("[aria-hidden=true]")
        ) {
          out.push(n.textContent.trim());
        }
      }
      return out;
    };
    await loaded(REPORT);
    await openReport();
    expect(exposed()).toEqual([]);
    cleanup();
    sessionStorage.clear();
    await loaded(ERROR_STATE);
    expect(exposed()).toEqual([]);
    cleanup();
    sessionStorage.clear();
    await loaded(
      base({ cc_pipelineState: "CANCELLED", cc_phase2Results: P2_HOSTS }),
    );
    expect(exposed()).toEqual([]);
    cleanup();
    sessionStorage.clear();
    await loaded(base({ cc_pipelineState: "PORT_SCAN" }));
    expect(exposed()).toEqual([]);
  });

  it("renders no inline style of its own", async () => {
    const styled = () =>
      [...document.body.querySelectorAll("[style]")].filter(
        (el) => !el.classList.contains("cc-progress__bar"),
      );
    await loaded(REPORT);
    await openReport();
    expect(styled()).toEqual([]);
    cleanup();
    sessionStorage.clear();
    await loaded(base({ cc_pipelineState: "PORT_SCAN" }));
    expect(styled()).toEqual([]);
    cleanup();
    sessionStorage.clear();
    await loaded(
      base({
        cc_phase1Hosts: P1_HOSTS.map((h) => ({ ...h, is_active: false })),
        cc_phase1Summary: { total_hosts: 4, active_hosts: 0 },
      }),
    );
    expect(styled()).toEqual([]);
  });

  it("carries no colour literals, legacy classes or legacy modal, and styles itself from tokens", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/scan/Phase3Results.jsx"),
      "utf8",
    );
    expect(source).toMatch(
      /import\s+["']\.\.\/\.\.\/styles\/phase3-results\.css["']/,
    );
    expect(source).toMatch(/from\s+["'](?:\.\.\/)+design-system["']/);
    expect(source).not.toMatch(/components\/layout\/Modal/);
    expect(source).not.toMatch(/style=\{/);
    expect(source).not.toMatch(/onMouse(Enter|Leave|Down|Up)/);
    expect(source.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(source).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(source).not.toMatch(/var\(--/);
    const classes = [
      ...source.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g),
    ].flatMap((m) => (m[1] ?? m[2]).split(/\s+/));
    const legacy = classes.filter((c) =>
      /^(btn|btn--|page-|summary-|pipeline-|section-|filter-tab|results-table|row--|status-dot|progress-|muted|small|ip-code)/.test(
        c,
      ),
    );
    expect(legacy).toEqual([]);
    const cssPath = path.join(AUDIT_SRC, "styles/phase3-results.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)/g) || []).toEqual([]);
    expect(css).toMatch(/var\(--ccure-/);
    expect(css).toMatch(/:focus-visible/);
  });
});
