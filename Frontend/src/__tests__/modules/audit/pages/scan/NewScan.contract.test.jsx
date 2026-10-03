/**
 * NewScan (`/scan/new`, `/scan/active/:scanId`) — Checkpoint 3C batch 25
 * baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 25 block is the
 * specification, and every test in it fails on the legacy page.
 * `NewScan.test.jsx`, which predates this batch, is kept as it was.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Setup builds one request: `POST /scan/host-discovery` with the pipeline's
 * phases and the options chosen, and then follows the scan it started at
 * `/scan/active/{id}`. Following a scan is `POST /auth/ticket` (no body), one
 * WebSocket at `/scans/{id}/progress?ticket=…`, and `GET /scans/{id}` every
 * 2.5 s. When the socket settles, polling stops, the record is read once more,
 * discovery's hosts are stored in the scan context, and a completed asset or
 * audit scan hands over to the next phase's page by itself. Stop Scan is
 * `POST /scans/{id}/stop`.
 *
 * Only the axios instance, the shell, the quota bar, the signed-in user and
 * `WebSocket` are replaced; the scan context and the router are real.
 */

import { StrictMode } from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import {
  MemoryRouter,
  Route,
  Routes,
  useLocation,
  useNavigationType,
} from "react-router-dom";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

import NewScan from "@audit/pages/scan/NewScan";
import { ScanProvider } from "@audit/context/ScanContext";
import api from "@shell/api/axiosInstance";
import { SRC, AUDIT_SRC } from "../../../../testPaths";
import { personaFrom } from "../../../../fixtures/authorization";

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
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

let quotaChange;
vi.mock("@audit/components/scan/ScanQuotaBar", () => ({
  default: ({ onQuotaChange }) => {
    quotaChange = onQuotaChange;
    return <div data-testid="quota-bar" />;
  },
}));

let user;
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(user) }),
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
const SCAN = "ns-9";
const MISSION = `/scan/active/${SCAN}`;
const TICKET_URL = `/api/scans/${SCAN}/progress?ticket=tk%2B1`;

const IT_PORTS =
  "21,22,23,25,53,67,80,88,110,111,123,135,137,139,143,161,389,443,445,465,587,623,636,902,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,10250,27017";
const WEB_PORTS = "80,443,3000,5000,8000,8080,8443,8888,9000,9090,9443";

const HOSTS = [
  {
    ip_address: "10.60.1.11",
    hostname: "db-01",
    mac_address: "00:1A:2B:3C:6D:11",
    vendor: "Dell Inc.",
    is_active: true,
  },
  {
    ip_address: "10.60.1.12",
    hostname: "Unknown",
    mac_address: "N/A",
    is_active: true,
  },
  {
    ip_address: "10.60.1.13",
    hostname: "old-02",
    mac_address: "00:1A:2B:3C:6D:13",
    is_active: false,
  },
];
const SUMMARY = { total_hosts: 3, active_hosts: 2 };
const record = (status, extra = {}) => ({
  id: SCAN,
  status,
  pipeline_mode: "basic",
  results: { phase1: { data: HOSTS, summary: SUMMARY } },
  ...extra,
});
const CREDS = [
  { id: "cred-1", name: "Linux fleet", username: "auditor", port: 2222 },
  { id: "cred-2", name: "Windows estate", username: "svc-scan" },
];

/* ── A WebSocket this file controls ─────────────────────────────────────── */
let sockets;
let calls;
class FakeWebSocket {
  static OPEN = 1;
  constructor(url) {
    this.url = url;
    this.readyState = 1;
    this.closeCalls = 0;
    sockets.push(this);
    calls.push(`WS ${url}`);
  }
  close() {
    this.closeCalls += 1;
    this.readyState = 3;
  }
  send() {}
}

/* ── Harness ────────────────────────────────────────────────────────────── */
let postReply;
let getReply;
let consoleError;
let locations;

function LocationProbe() {
  const location = useLocation();
  const type = useNavigationType();
  locations.push({ path: location.pathname, state: location.state, type });
  return null;
}

const seed = (entries) => {
  for (const [key, value] of Object.entries(entries))
    sessionStorage.setItem(key, JSON.stringify(value));
};
const stored = (key) => JSON.parse(sessionStorage.getItem(key));

const renderAt = (entry, strict = false) => {
  const tree = (
    <ScanProvider>
      <MemoryRouter initialEntries={[entry]}>
        <LocationProbe />
        <Routes>
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scan/active/:scanId" element={<NewScan />} />
          <Route path="*" element={<div data-testid="elsewhere" />} />
        </Routes>
      </MemoryRouter>
    </ScanProvider>
  );
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
};
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await act(async () => {});
  }
};
const mount = async (entry = "/scan/new", session = {}, strict = false) => {
  seed(session);
  const view = renderAt(entry, strict);
  await flush();
  return view;
};
const fakeTimers = () =>
  vi.useFakeTimers({
    toFake: [
      "setTimeout",
      "clearTimeout",
      "setInterval",
      "clearInterval",
      "Date",
    ],
  });
const advance = async (ms) => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
  await flush();
};
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};

const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);
const here = () => locations.at(-1);
const visited = (p) => locations.filter((l) => l.path === p);
const posts = (url) => api.post.mock.calls.filter(([u]) => u === url);
const gets = (url) => api.get.mock.calls.filter(([u]) => u === url);
const layoutTitle = () =>
  screen.getByTestId("app-layout").getAttribute("data-page-title");

/* Setup */
const targetInput = () => screen.getByPlaceholderText(/10\.180\.6\.0\/24/);
const startButton = () =>
  screen.getByRole("button", { name: /Start (Scan|Discovery)/ });
const typeTarget = (value) =>
  fireEvent.change(targetInput(), { target: { value } });
const openSettings = async () => {
  fireEvent.click(
    screen.getByRole("button", { name: /Configure Advanced Settings/i }),
  );
  await flush();
};
const settingsOpen = () =>
  !!document.querySelector(".ns-drawer--open, [role=dialog]");
const closeControl = () =>
  screen.queryByRole("button", { name: /close settings/i }) ||
  screen.getByTitle(/Close Settings/);
const backdrop = () =>
  document.querySelector(".ns-drawer-backdrop") ||
  document.querySelector(".cc-modal__overlay");
/* The one checkbox that shares the nearest ancestor with a piece of text. */
const switchNear = (re) => {
  let el = screen.getAllByText(re)[0];
  while (el && el.querySelectorAll('input[type="checkbox"]').length !== 1)
    el = el.parentElement;
  return el?.querySelector('input[type="checkbox"]');
};
/* The Light / Normal / Deep choices that share an ancestor with their label. */
const choicesNear = (re) => {
  let el = screen.getAllByText(re)[0];
  const has = (node, name) =>
    [...node.querySelectorAll("button")].some((b) =>
      new RegExp(`${name}$`).test(squash(b)),
    );
  while (el && !["Light", "Normal", "Deep"].every((n) => has(el, n)))
    el = el.parentElement;
  return el;
};
const choose = (group, name) =>
  fireEvent.click(
    within(group).getByRole("button", { name: new RegExp(`${name}$`) }),
  );
const removeTokenButton = (token) => {
  const tag = screen.getByText(token, { exact: true });
  return (
    tag.querySelector("button") || tag.parentElement.querySelector("button")
  );
};

/* Target files */
const fileInput = () => document.querySelector('input[type="file"]');
const textFile = (name, content) =>
  new File([content], name, { type: "text/plain" });
const TARGET_FILE = [
  "target",
  "10.60.1.10",
  "10.60.1.0/28, 10.60.1.20 - 10.60.1.30",
  "bad_host!",
  "10.60.1.10",
  "10.60.1.40-45",
  "",
].join("\n");
const TARGETS_READ =
  "10.60.1.10, 10.60.1.0/28, 10.60.1.20-10.60.1.30, 10.60.1.40-45";
const upload = async (file) => {
  fireEvent.change(fileInput(), { target: { files: [file] } });
  await flush();
};
const tableOf = () => document.querySelector("table");
const headersOf = (t) => [...t.querySelectorAll("thead th")].map(squash);
const rowsOf = (t) =>
  [...t.querySelectorAll("tbody tr")].map((tr) =>
    [...tr.querySelectorAll("td, th")].map(squash),
  );

/* Dispatch */
const dispatchBody = () => posts("/scan/host-discovery")[0][1];
const startScan = async () => {
  fireEvent.click(startButton());
  await flush();
};

/* Mission */
const startMission = async (session = {}, entry = MISSION, strict = false) => {
  fakeTimers();
  return mount(
    entry,
    {
      cc_target: "10.60.1.0/28",
      cc_scanNo: 4501,
      cc_pipelineMode: "basic",
      ...session,
    },
    strict,
  );
};
const frame = async (progress, phase = 1) => {
  await act(async () => {
    sockets[0].onmessage?.({ data: JSON.stringify({ phase, progress }) });
  });
  await flush();
};
const rowText = (ip) => screen.getByText(ip).parentElement.textContent;

beforeEach(() => {
  sessionStorage.clear();
  sockets = [];
  calls = [];
  locations = [];
  quotaChange = undefined;
  user = EXECUTOR;
  vi.stubGlobal("WebSocket", FakeWebSocket);
  postReply = (url) => {
    if (url === "/auth/ticket") return { data: { ticket: "tk+1" } };
    if (url === `/scans/${SCAN}/stop`) return { data: { success: true } };
    return { data: { success: true, scan_id: SCAN, scan_no: 4501 } };
  };
  getReply = (url) =>
    url === "/compliance/credentials"
      ? { data: CREDS }
      : { data: record("running", { results: {} }) };
  for (const verb of ["get", "post", "put", "patch", "delete"])
    api[verb].mockReset();
  api.get.mockImplementation((url, config) => {
    calls.push(`GET ${url}`);
    const r = getReply(url, config);
    return r instanceof Promise ? r : Promise.resolve(r);
  });
  api.post.mockImplementation((...args) => {
    calls.push(`POST ${args[0]}`);
    const r = postReply(...args);
    return r instanceof Promise ? r : Promise.resolve(r);
  });
  consoleError = vi.spyOn(console, "error");
});

afterEach(() => {
  // The dispatch, the ticket and the stop — nothing else, never PUT, PATCH or
  // DELETE; every read is the scan record or the stored credentials; every
  // socket is the scan's progress.
  cleanup();
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  expect(api.delete).not.toHaveBeenCalled();
  for (const [url] of api.post.mock.calls) {
    expect(url).toMatch(
      /^\/scan\/host-discovery$|^\/auth\/ticket$|^\/scans\/ns-9\/stop$/,
    );
  }
  for (const [url] of api.get.mock.calls) {
    expect(url).toMatch(/^\/scans\/ns-9$|^\/compliance\/credentials$/);
  }
  for (const s of sockets) expect(s.url).toBe(TICKET_URL);
  consoleError.mockRestore();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */
describe("NewScan — contract", () => {
  describe("setup: the page", () => {
    it.each([
      [
        "basic",
        "Basic Network Scan",
        "Identifies the live hosts in the network.",
        "Basic Scan",
        /^Start Scan/,
      ],
      [
        "asset",
        "Asset Discovery",
        "Identifies Assets in the Network with Open Ports Information.",
        "Asset Discovery",
        /^Start Discovery · normal/,
      ],
      [
        "vulnerability_audit",
        "Vulnerability Audit",
        "Full vulnerability audit pipeline with host, port, and risk assessment.",
        "Vulnerability Audit",
        /^Start Scan/,
      ],
      [
        "advanced",
        "Vulnerability Audit",
        "Full vulnerability audit pipeline with host, port, and risk assessment.",
        "Vulnerability Audit",
        /^Start Scan/,
      ],
    ])(
      "%s: titled from the pipeline, with its start button",
      async (mode, title, description, badge, start) => {
        await mount("/scan/new", { cc_pipelineMode: mode });
        expect(layoutTitle()).toBe("New Scan");
        expect(
          screen.getByRole("heading", { level: 1, name: title }),
        ).toBeTruthy();
        expect(bodyText()).toContain(description);
        expect(bodyText()).toContain(badge);
        expect(squash(startButton())).toMatch(start);
      },
    );

    it("names the chosen discovery intensity on the start button", async () => {
      await mount("/scan/new", {
        cc_pipelineMode: "asset",
        cc_discoveryIntensity: "deep",
      });
      expect(squash(startButton())).toMatch(/^Start Discovery · deep/);
    });

    it("starts only with a target, and not while the quota is exhausted", async () => {
      await mount();
      expect(startButton()).toBeDisabled();
      typeTarget("   ");
      expect(startButton()).toBeDisabled();
      typeTarget("10.60.1.10");
      expect(startButton()).toBeEnabled();
      expect(stored("cc_target")).toBe("10.60.1.10");
      act(() =>
        quotaChange({ quota_exceeded: true, concurrent_exceeded: false }),
      );
      expect(startButton()).toBeDisabled();
      act(() =>
        quotaChange({ quota_exceeded: false, concurrent_exceeded: true }),
      );
      expect(startButton()).toBeDisabled();
      act(() =>
        quotaChange({ quota_exceeded: false, concurrent_exceeded: false }),
      );
      expect(startButton()).toBeEnabled();
    });

    it("Back returns to the dashboard", async () => {
      await mount();
      fireEvent.click(screen.getByRole("button", { name: /Back/ }));
      await flush();
      expect(here().path).toBe("/audit-dashboard");
    });

    it("quick targets fill the target field", async () => {
      await mount();
      for (const t of [
        "10.180.4.1",
        "10.180.6.0/24",
        "10.180.6.45",
        "10.180.6.14",
      ]) {
        fireEvent.click(screen.getByRole("button", { name: t }));
        expect(targetInput().value).toBe(t);
        expect(stored("cc_target")).toBe(t);
      }
    });

    it("without scans:execute nothing can be started", async () => {
      user = VIEWER;
      await mount("/scan/new", { cc_target: "10.60.1.10" });
      expect(targetInput()).toBeDisabled();
      expect(
        screen.getByRole("button", { name: /Upload File/ }),
      ).toBeDisabled();
      expect(screen.getByRole("button", { name: "10.180.4.1" })).toBeDisabled();
      expect(startButton()).toBeDisabled();
      fireEvent.keyDown(targetInput(), { key: "Enter" });
      await flush();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("asset: the discovery profile sets the intensity and describes it", async () => {
      await mount("/scan/new", { cc_pipelineMode: "asset" });
      const group = choicesNear(/discovery profile/i);
      expect(squash(group)).toContain("Fast-first with coverage fallback");
      expect(squash(group)).toContain("Recommended");
      choose(group, "Deep");
      expect(stored("cc_discoveryIntensity")).toBe("deep");
      expect(squash(choicesNear(/discovery profile/i))).toContain(
        "Max coverage — best for firewalled nets",
      );
      expect(squash(choicesNear(/discovery profile/i))).toContain("Thorough");
      expect(squash(startButton())).toMatch(/^Start Discovery · deep/);
      choose(choicesNear(/discovery profile/i), "Light");
      expect(stored("cc_discoveryIntensity")).toBe("light");
      expect(squash(choicesNear(/discovery profile/i))).toContain(
        "Fastest — may miss firewalled hosts",
      );
    });

    it("audit: the scan profile sets the intensity and describes it", async () => {
      await mount("/scan/new", { cc_pipelineMode: "vulnerability_audit" });
      expect(squash(choicesNear(/scan profile/i))).toContain(
        "Balanced port coverage",
      );
      choose(choicesNear(/scan profile/i), "Deep");
      expect(stored("cc_intensity")).toBe("deep");
      expect(squash(choicesNear(/scan profile/i))).toContain(
        "Full port range scan",
      );
    });

    it("a basic scan offers no profile", async () => {
      await mount();
      expect(screen.queryByText(/discovery profile/i)).toBeNull();
      expect(screen.queryByText(/scan profile/i)).toBeNull();
    });
  });

  describe("setup: advanced settings", () => {
    it("opens from its button and closes with its close control, Save & Close, the backdrop and Escape", async () => {
      await mount("/scan/new", { cc_pipelineMode: "asset" });
      expect(settingsOpen()).toBe(false);
      await openSettings();
      expect(settingsOpen()).toBe(true);
      fireEvent.click(closeControl());
      await flush();
      expect(settingsOpen()).toBe(false);

      await openSettings();
      fireEvent.click(screen.getByRole("button", { name: /Save & Close/ }));
      await flush();
      expect(settingsOpen()).toBe(false);

      await openSettings();
      fireEvent.click(backdrop());
      await flush();
      expect(settingsOpen()).toBe(false);

      await openSettings();
      fireEvent.keyDown(document, { key: "Escape" });
      await flush();
      expect(settingsOpen()).toBe(false);
    });

    it("asset: intensity by default, port-based on request, and the preview follows", async () => {
      await mount("/scan/new", { cc_pipelineMode: "asset" });
      await openSettings();
      expect(bodyText()).toContain("Intensity-Based Scan");
      expect(bodyText()).toMatch(/Target Profile \/ Depth\s*Normal Scan/);
      expect(bodyText()).toMatch(/Ports Count\s*Top 1000 ports/);
      expect(bodyText()).toMatch(/Excluded Ports\s*None/);
      expect(squash(choicesNear(/port scan intensity/i))).toContain(
        "Balanced port coverage",
      );
      choose(choicesNear(/port scan intensity/i), "Deep");
      expect(stored("cc_portScanIntensity")).toBe("deep");
      expect(bodyText()).toMatch(/Target Profile \/ Depth\s*Deep Scan/);
      expect(bodyText()).toMatch(/Ports Count\s*All 65535 ports/);
      expect(bodyText()).toContain("Full port range — comprehensive");

      fireEvent.click(screen.getByText("Port-Based Scan"));
      await flush();
      expect(stored("cc_portScanMode")).toBe("port");
      expect(bodyText()).toMatch(/Scan Type\s*Port-Based Scan/);
      expect(bodyText()).toMatch(/Target Profile \/ Depth\s*IT Infrastructure/);
      expect(bodyText()).toMatch(
        new RegExp(`Ports Count\\s*${IT_PORTS.split(",").length} ports`),
      );
      expect(bodyText()).toContain(
        `Included Ports (${IT_PORTS.split(",").length} total)`,
      );
      expect(bodyText()).toContain("Sensitive Ports Detected");

      fireEvent.change(screen.getByDisplayValue("IT Infrastructure"), {
        target: { value: "web" },
      });
      await flush();
      expect(stored("cc_portProfile")).toBe("web");
      expect(bodyText()).toMatch(/Target Profile \/ Depth\s*Web Services/);
      expect(bodyText()).toMatch(/Ports Count\s*11 ports/);
      expect(bodyText()).not.toContain("Sensitive Ports Detected");

      fireEvent.change(screen.getByDisplayValue("Web Services"), {
        target: { value: "it" },
      });
      await flush();
      expect(bodyText()).toContain("Sensitive Ports Detected");
      fireEvent.click(screen.getAllByText("Intensity-Based Scan")[0]);
      await flush();
      expect(stored("cc_portScanMode")).toBe("intensity");
      expect(bodyText()).not.toContain("Sensitive Ports Detected");
    });

    it.each([
      [
        "22,abc",
        "Invalid characters. Only numbers, commas, and hyphens are allowed.",
      ],
      ["80-70", 'Range start must be <= end: "80-70"'],
      ["1-2-3", 'Invalid range format: "1-2-3"'],
      ["-5", 'Invalid range bounds: "-5"'],
      ["0", "Port must be between 1 and 65535: 0"],
      ["70000-70001", 'Ports must be between 1 and 65535: "70000-70001"'],
      ["22,22", "Duplicate port detected: 22"],
      ["20-25,22", "Duplicate port detected: 22"],
    ])("custom ports %s: %s", async (value, message) => {
      await mount("/scan/new", {
        cc_pipelineMode: "asset",
        cc_portScanMode: "port",
        cc_portProfile: "custom",
      });
      await openSettings();
      fireEvent.change(
        screen.getByPlaceholderText("e.g. 22,80,443,8000-8100"),
        {
          target: { value },
        },
      );
      await flush();
      expect(bodyText()).toContain(message);
      expect(bodyText()).not.toContain("Scan Estimation");
    });

    it("custom ports: estimation, presets and the sensitive-port warning", async () => {
      await mount("/scan/new", {
        cc_pipelineMode: "asset",
        cc_portScanMode: "port",
        cc_portProfile: "custom",
      });
      await openSettings();
      const input = screen.getByPlaceholderText("e.g. 22,80,443,8000-8100");
      fireEvent.change(input, { target: { value: "22, 80,443" } });
      await flush();
      expect(stored("cc_customPorts")).toBe("22, 80,443");
      expect(bodyText()).toContain("Scan Estimation");
      expect(bodyText()).toContain("Unique ports: 3");
      expect(bodyText()).toContain("Est. packets per host: 3 packets");
      expect(bodyText()).toContain("Est. duration per host: 1 - 2 seconds");
      expect(bodyText()).toMatch(/Ports Count\s*3 custom ports/);
      fireEvent.change(input, { target: { value: "1-1000" } });
      await flush();
      expect(bodyText()).toContain("Est. duration per host: 20 - 100 seconds");
      fireEvent.change(input, { target: { value: "6443" } });
      await flush();
      expect(bodyText()).toContain("Sensitive Ports Detected");
      expect(bodyText()).toMatch(/Ports Count\s*1 custom port(?!s)/);
      fireEvent.click(screen.getByRole("button", { name: "Web Services" }));
      await flush();
      expect(input.value).toBe(WEB_PORTS);
      expect(bodyText()).toContain("Unique ports: 11");
    });

    it("exclude ports: a switch, a list of tokens, a quick choice and validation", async () => {
      await mount();
      await openSettings();
      const toggle = switchNear(/Exclude Specific Ports/i);
      expect(toggle.checked).toBe(false);
      expect(
        screen.queryByPlaceholderText("e.g. 2375,2376,6443,10250 or 80-90"),
      ).toBeNull();
      fireEvent.click(toggle);
      await flush();
      const input = screen.getByPlaceholderText(
        "e.g. 2375,2376,6443,10250 or 80-90",
      );
      fireEvent.change(input, { target: { value: "80, 443,8080-8090" } });
      await flush();
      expect(stored("cc_excludePorts")).toBe("80, 443,8080-8090");
      fireEvent.click(removeTokenButton("443"));
      await flush();
      expect(stored("cc_excludePorts")).toBe("80, 8080-8090");
      fireEvent.click(
        screen.getByRole("button", { name: /Exclude Sensitive Ports/ }),
      );
      await flush();
      expect(stored("cc_excludePorts")).toBe("2375,2376,6443,10250");
      fireEvent.change(input, { target: { value: "80,abc" } });
      await flush();
      expect(bodyText()).toContain(
        "Invalid characters. Only numbers, commas, and hyphens are allowed.",
      );
      fireEvent.click(switchNear(/Exclude Specific Ports/i));
      await flush();
      expect(stored("cc_excludePorts")).toBe("");
      expect(
        screen.queryByPlaceholderText("e.g. 2375,2376,6443,10250 or 80-90"),
      ).toBeNull();
    });

    it("exclude ports: on already when the context holds some, and listed in the preview", async () => {
      await mount("/scan/new", {
        cc_pipelineMode: "asset",
        cc_excludePorts: "2375, 22",
      });
      await openSettings();
      expect(switchNear(/Exclude Specific Ports/i).checked).toBe(true);
      expect(bodyText()).toMatch(/Excluded Ports\s*2375, 22 \(2 ports\)/);
    });

    it("exclude IPs: a switch and validation", async () => {
      await mount();
      await openSettings();
      fireEvent.click(switchNear(/Exclude Specific IPs/i));
      await flush();
      const input = screen.getByPlaceholderText(
        "e.g. 10.180.12.10,10.190.0.0/16",
      );
      fireEvent.change(input, { target: { value: "10.60.1.99, bad_ip!" } });
      await flush();
      expect(stored("cc_excludeIps")).toBe("10.60.1.99, bad_ip!");
      expect(bodyText()).toContain(
        'Invalid IP, range, or CIDR format: "bad_ip!"',
      );
      fireEvent.change(input, { target: { value: "10.60.1.99" } });
      await flush();
      expect(bodyText()).not.toContain("Invalid IP, range, or CIDR format");
      fireEvent.click(switchNear(/Exclude Specific IPs/i));
      await flush();
      expect(stored("cc_excludeIps")).toBe("");
    });

    it("OS detection and execution mode are offered for asset and audit scans only", async () => {
      await mount();
      await openSettings();
      expect(screen.queryByText(/^OS Detection$/i)).toBeNull();
      expect(screen.queryByDisplayValue("Automatic (Full Chain)")).toBeNull();
      cleanup();
      sessionStorage.clear();

      await mount("/scan/new", { cc_pipelineMode: "asset" });
      await openSettings();
      const os = switchNear(/^OS Detection$/i);
      expect(os.checked).toBe(true);
      expect(bodyText()).toContain("ON (Fingerprint)");
      fireEvent.click(os);
      await flush();
      expect(stored("cc_osDetection")).toBe(false);
      expect(bodyText()).toContain("OFF (Faster Scan)");
      fireEvent.change(screen.getByDisplayValue("Automatic (Full Chain)"), {
        target: { value: "interactive" },
      });
      await flush();
      expect(stored("cc_executionMode")).toBe("interactive");
    });
  });

  describe("setup: authenticated checks and SNMP", () => {
    it("authenticated checks are an audit option, loading stored credentials once, on first use", async () => {
      await mount("/scan/new", { cc_pipelineMode: "asset" });
      await openSettings();
      expect(screen.queryByText(/Authenticated Checks/i)).toBeNull();
      cleanup();
      sessionStorage.clear();

      await mount("/scan/new", { cc_pipelineMode: "vulnerability_audit" });
      await openSettings();
      expect(gets("/compliance/credentials")).toHaveLength(0);
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      expect(gets("/compliance/credentials")).toHaveLength(1);
      expect(bodyText()).toContain("Select the credentials to try.");
      expect(
        squash(
          screen
            .getByRole("checkbox", { name: /Linux fleet/ })
            .closest("label"),
        ),
      ).toMatch(/Linux fleet\s*auditor@:2222/);
      expect(
        squash(
          screen
            .getByRole("checkbox", { name: /Windows estate/ })
            .closest("label"),
        ),
      ).toMatch(/Windows estate\s*svc-scan@:22/);
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      expect(gets("/compliance/credentials")).toHaveLength(1);
    });

    it("with none stored, it explains, links to Compliance, and asks again each time", async () => {
      getReply = (url) =>
        url === "/compliance/credentials"
          ? { data: [] }
          : { data: record("running") };
      await mount("/scan/new", { cc_pipelineMode: "vulnerability_audit" });
      await openSettings();
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      expect(bodyText()).toContain(
        "No stored credentials are registered for this organisation.",
      );
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      expect(gets("/compliance/credentials")).toHaveLength(2);
      fireEvent.click(screen.getByRole("button", { name: "Compliance" }));
      await flush();
      expect(here().path).toBe("/compliance");
    });

    it("a failed load is logged and reads as none stored", async () => {
      const failure = new Error("credentials unavailable");
      getReply = () => Promise.reject(failure);
      consoleError.mockImplementation(() => {});
      await mount("/scan/new", { cc_pipelineMode: "vulnerability_audit" });
      await openSettings();
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      expect(console.error).toHaveBeenCalledWith(
        "Failed to load credentials for scan",
        failure,
      );
      expect(bodyText()).toContain(
        "No stored credentials are registered for this organisation.",
      );
    });

    it("SNMP: v2c with a community by default; v3 asks for a user, masked passphrases, and privacy only when chosen", async () => {
      await mount();
      await openSettings();
      expect(screen.queryByDisplayValue("v2c")).toBeNull();
      fireEvent.click(switchNear(/Network Topology \(SNMP\)/i));
      await flush();
      expect(screen.getByDisplayValue("v2c")).toBeTruthy();
      expect(screen.getByPlaceholderText("public").value).toBe("public");
      fireEvent.change(screen.getByDisplayValue("v2c"), {
        target: { value: "v3" },
      });
      await flush();
      expect(screen.queryByPlaceholderText("public")).toBeNull();
      expect(screen.getByPlaceholderText("SNMPv3 username")).toBeTruthy();
      expect(screen.getByDisplayValue("SHA")).toBeTruthy();
      const auth = screen.getByPlaceholderText("Auth passphrase");
      expect(auth.getAttribute("type")).toBe("password");
      expect(screen.getByDisplayValue("None (authNoPriv)")).toBeTruthy();
      expect(screen.queryByPlaceholderText("Privacy passphrase")).toBeNull();
      fireEvent.change(screen.getByDisplayValue("None (authNoPriv)"), {
        target: { value: "AES128" },
      });
      await flush();
      const priv = screen.getByPlaceholderText("Privacy passphrase");
      expect(priv.getAttribute("type")).toBe("password");
      expect(screen.getByPlaceholderText("e.g. vlan-100")).toBeTruthy();
      fireEvent.change(auth, { target: { value: "notreal" } });
      fireEvent.change(priv, { target: { value: "notreal" } });
      await flush();
      expect(bodyText()).not.toContain("notreal");
      expect(
        [
          ...document.querySelectorAll("[title], [aria-label], [data-value]"),
        ].some((el) =>
          ["title", "aria-label", "data-value"].some((a) =>
            (el.getAttribute(a) || "").includes("notreal"),
          ),
        ),
      ).toBe(false);
    });
  });

  describe("setup: a target list from a file", () => {
    it("the picker accepts .txt and .csv, and Upload File opens it", async () => {
      await mount();
      expect(fileInput().getAttribute("accept")).toBe(".txt,.csv");
      const click = vi.spyOn(fileInput(), "click").mockImplementation(() => {});
      fireEvent.click(screen.getByRole("button", { name: /Upload File/ }));
      expect(click).toHaveBeenCalledTimes(1);
    });

    it("reads one target per line — IPs, CIDRs and ranges — skipping headers and counting duplicates and invalid entries", async () => {
      await mount();
      await upload(textFile("targets.txt", TARGET_FILE));
      await waitFor(() => expect(targetInput().value).toBe(TARGETS_READ));
      expect(stored("cc_target")).toBe(TARGETS_READ);
      expect(bodyText()).toMatch(/Total:\s*6/);
      expect(bodyText()).toMatch(/Valid:\s*4/);
      expect(bodyText()).toMatch(/Invalid:\s*1/);
      expect(bodyText()).toMatch(/Duplicates:\s*1/);
      expect(bodyText()).toContain("Some invalid entries were ignored.");
      expect(bodyText()).toContain("Target List Preview");
      const table = tableOf();
      expect(headersOf(table)).toEqual([
        "#",
        "Target Value",
        "Type",
        "Actions",
      ]);
      const rows = rowsOf(table);
      expect(rows.map((r) => r.slice(0, 3))).toEqual([
        ["1", "10.60.1.10", "IP"],
        ["2", "10.60.1.0/28", "CIDR"],
        ["3", "10.60.1.20-10.60.1.30", "Range"],
        ["4", "10.60.1.40-45", "Range"],
      ]);
      for (const r of rows) expect(r[3]).toMatch(/Remove/);
    });

    it.each([
      [
        "targets.zip",
        "x",
        undefined,
        "Unsupported file format: targets.zip. Upload a .txt or .csv file with one target per line.",
      ],
      [
        "empty.txt",
        "",
        undefined,
        "empty.txt is empty — no targets to import.",
      ],
      [
        "big.csv",
        "x",
        6 * 1024 * 1024,
        "big.csv is 6.0 MB, above the 5 MB limit for a target list.",
      ],
    ])(
      "refuses %s without reading it",
      async (name, content, size, message) => {
        const read = vi.spyOn(FileReader.prototype, "readAsText");
        await mount();
        const file = textFile(name, content);
        if (size) Object.defineProperty(file, "size", { value: size });
        await upload(file);
        expect(bodyText()).toContain(message);
        expect(read).not.toHaveBeenCalled();
        expect(targetInput().value).toBe("");
        read.mockRestore();
      },
    );

    it("a file with nothing usable says so", async () => {
      await mount();
      await upload(textFile("junk.txt", "!!!\n###\n"));
      await waitFor(() =>
        expect(bodyText()).toContain(
          "No valid targets found in junk.txt. Expected one IP, CIDR or range per line.",
        ),
      );
      expect(targetInput().value).toBe("");
    });

    it("a file dropped on the target field is read the same way", async () => {
      await mount();
      fireEvent.dragOver(targetInput());
      fireEvent.drop(targetInput(), {
        dataTransfer: { files: [textFile("targets.csv", TARGET_FILE)] },
      });
      await waitFor(() => expect(targetInput().value).toBe(TARGETS_READ));
    });

    it("a target can be removed, the list cleared, and the summary dismissed", async () => {
      await mount();
      await upload(textFile("targets.txt", TARGET_FILE));
      await waitFor(() => expect(tableOf()).not.toBeNull());
      const row2 = tableOf().querySelectorAll("tbody tr")[1];
      fireEvent.click(within(row2).getByRole("button"));
      await flush();
      expect(targetInput().value).toBe(
        "10.60.1.10, 10.60.1.20-10.60.1.30, 10.60.1.40-45",
      );
      expect(bodyText()).toMatch(/Total:\s*5/);
      expect(bodyText()).toMatch(/Valid:\s*3/);
      fireEvent.click(screen.getByRole("button", { name: /Clear Targets/ }));
      await flush();
      expect(targetInput().value).toBe("");
      expect(tableOf()).toBeNull();
      expect(bodyText()).not.toMatch(/Total:/);

      await upload(textFile("targets.txt", TARGET_FILE));
      await waitFor(() => expect(tableOf()).not.toBeNull());
      fireEvent.click(
        screen.queryByRole("button", { name: /Dismiss import summary/i }) ||
          screen.getByRole("button", { name: "×" }),
      );
      await flush();
      expect(bodyText()).not.toMatch(/Total:/);
      expect(tableOf()).toBeNull();
      expect(targetInput().value).toBe(TARGETS_READ);
    });

    it("typing a target hides the summary and the list", async () => {
      await mount();
      await upload(textFile("targets.txt", TARGET_FILE));
      await waitFor(() => expect(tableOf()).not.toBeNull());
      typeTarget("10.60.1.50");
      await flush();
      expect(bodyText()).not.toMatch(/Total:/);
      expect(tableOf()).toBeNull();
    });

    it("exports the ignored entries as a text file", async () => {
      await mount();
      await upload(textFile("targets.txt", "10.60.1.10\nbad_host!\nx_y\n"));
      await waitFor(() => expect(bodyText()).toMatch(/Invalid:\s*2/));
      const blobs = [];
      vi.stubGlobal(
        "Blob",
        class {
          constructor(parts, options) {
            this.parts = parts;
            this.options = options;
            blobs.push(this);
          }
        },
      );
      const create = vi.fn(() => "blob:ns-invalid");
      const revoke = vi.fn();
      vi.stubGlobal("URL", {
        createObjectURL: create,
        revokeObjectURL: revoke,
      });
      const clicked = [];
      const click = vi
        .spyOn(HTMLAnchorElement.prototype, "click")
        .mockImplementation(function () {
          clicked.push({
            href: this.getAttribute("href"),
            download: this.download,
          });
        });
      fireEvent.click(screen.getByRole("button", { name: /Export Invalid/ }));
      expect(blobs).toHaveLength(1);
      expect(blobs[0].parts).toEqual(["bad_host\nx_y"]);
      expect(blobs[0].options).toEqual({ type: "text/plain" });
      expect(create).toHaveBeenCalledWith(blobs[0]);
      expect(clicked).toEqual([
        { href: "blob:ns-invalid", download: "invalid_targets.txt" },
      ]);
      expect(revoke).toHaveBeenCalledWith("blob:ns-invalid");
      click.mockRestore();
    });
  });

  describe("dispatch", () => {
    const ready = async (session = {}) => {
      fakeTimers();
      await mount("/scan/new", { cc_target: "10.60.1.10", ...session });
    };

    it("basic: one POST /scan/host-discovery with the targets and nothing chosen", async () => {
      await ready({ cc_target: " 10.60.1.10 , 10.60.1.0/28 ,, " });
      await startScan();
      expect(posts("/scan/host-discovery")).toHaveLength(1);
      expect(posts("/scan/host-discovery")[0]).toHaveLength(2);
      expect(dispatchBody()).toEqual({
        phases: [1],
        pipeline_mode: "basic",
        targets: ["10.60.1.10", "10.60.1.0/28"],
        scan_type: "adaptive",
        execution_mode: "automatic",
      });
    });

    it("then follows the scan it started, handing the route what it needs", async () => {
      await ready({ cc_target: "10.60.1.0/28" });
      await startScan();
      expect(stored("cc_pipelineState")).toBe("DISCOVERY");
      const handover = visited(MISSION).find((l) => l.state?.missionMode);
      expect(handover).toEqual({
        path: MISSION,
        type: "REPLACE",
        state: {
          missionMode: true,
          scanId: SCAN,
          scanNo: 4501,
          target: "10.60.1.0/28",
          pipelineMode: "basic",
        },
      });
      expect(here()).toEqual({ path: MISSION, type: "REPLACE", state: {} });
      expect(calls).toEqual([
        "POST /scan/host-discovery",
        "POST /auth/ticket",
        `WS ${TICKET_URL}`,
      ]);
      expect(stored("cc_scanId")).toBe(SCAN);
      expect(stored("cc_scanNo")).toBe(4501);
      expect(layoutTitle()).toBe("Active Scan Mission");
    });

    it("uses the display id when there is no scan number", async () => {
      postReply = (url) =>
        url === "/auth/ticket"
          ? { data: { ticket: "tk+1" } }
          : { data: { success: true, scan_id: SCAN, display_id: "S-77" } };
      await ready();
      await startScan();
      expect(
        visited(MISSION).find((l) => l.state?.missionMode).state.scanNo,
      ).toBe("S-77");
      expect(stored("cc_scanNo")).toBe("S-77");
    });

    it("asset: discovery and port intensities and OS detection", async () => {
      await ready({ cc_pipelineMode: "asset", cc_discoveryIntensity: "deep" });
      await startScan();
      expect(dispatchBody()).toEqual({
        phases: [1, 2],
        pipeline_mode: "asset",
        targets: ["10.60.1.10"],
        scan_type: "adaptive",
        execution_mode: "automatic",
        discovery_intensity: "deep",
        port_scan_intensity: "normal",
        os_detection: true,
      });
    });

    it.each([
      ["web", "", WEB_PORTS],
      ["custom", "22, 80,443", "22, 80,443"],
    ])(
      "asset, port-based (%s): custom intensity and the port list",
      async (profile, custom, sent) => {
        await ready({
          cc_pipelineMode: "asset",
          cc_portScanMode: "port",
          cc_portProfile: profile,
          cc_customPorts: custom,
          cc_osDetection: false,
          cc_executionMode: "interactive",
        });
        await startScan();
        expect(dispatchBody()).toEqual({
          phases: [1, 2],
          pipeline_mode: "asset",
          targets: ["10.60.1.10"],
          scan_type: "adaptive",
          execution_mode: "interactive",
          discovery_intensity: "normal",
          port_scan_intensity: "custom",
          custom_ports: sent,
          os_detection: false,
        });
      },
    );

    it("audit: the phases and OS detection", async () => {
      await ready({ cc_pipelineMode: "vulnerability_audit" });
      await startScan();
      expect(dispatchBody()).toEqual({
        phases: [1, 2, 3],
        pipeline_mode: "vulnerability_audit",
        targets: ["10.60.1.10"],
        scan_type: "adaptive",
        execution_mode: "automatic",
        os_detection: true,
      });
    });

    it("exclusions are trimmed and the rate limit is a number", async () => {
      await ready({
        cc_excludePorts: "  80,443 ",
        cc_excludeIps: " 10.60.1.99 ",
      });
      await openSettings();
      fireEvent.change(screen.getByPlaceholderText("e.g. 500"), {
        target: { value: "250" },
      });
      await flush();
      fireEvent.click(screen.getByRole("button", { name: /Save & Close/ }));
      await flush();
      await startScan();
      expect(dispatchBody()).toEqual({
        phases: [1],
        pipeline_mode: "basic",
        targets: ["10.60.1.10"],
        scan_type: "adaptive",
        execution_mode: "automatic",
        exclude_ports: "80,443",
        exclude_ips: "10.60.1.99",
        rate_limit: 250,
      });
    });

    it.each(["v1", "v2c"])(
      "SNMP %s sends its version and community under options",
      async (version) => {
        await ready();
        await openSettings();
        fireEvent.click(switchNear(/Network Topology \(SNMP\)/i));
        await flush();
        fireEvent.change(screen.getByDisplayValue("v2c"), {
          target: { value: version },
        });
        fireEvent.change(screen.getByPlaceholderText("public"), {
          target: { value: "notreal" },
        });
        await flush();
        fireEvent.click(screen.getByRole("button", { name: /Save & Close/ }));
        await flush();
        await startScan();
        expect(dispatchBody().options).toEqual({
          snmp: { version, community: "notreal" },
        });
      },
    );

    it("SNMP v3 and stored credentials share one options object", async () => {
      await ready({ cc_pipelineMode: "vulnerability_audit" });
      await openSettings();
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      fireEvent.click(screen.getByRole("checkbox", { name: /Linux fleet/ }));
      fireEvent.click(switchNear(/Network Topology \(SNMP\)/i));
      await flush();
      fireEvent.change(screen.getByDisplayValue("v2c"), {
        target: { value: "v3" },
      });
      await flush();
      fireEvent.change(screen.getByPlaceholderText("SNMPv3 username"), {
        target: { value: "snmp-ro" },
      });
      fireEvent.change(screen.getByDisplayValue("SHA"), {
        target: { value: "SHA256" },
      });
      fireEvent.change(screen.getByPlaceholderText("Auth passphrase"), {
        target: { value: "notreal" },
      });
      fireEvent.change(screen.getByDisplayValue("None (authNoPriv)"), {
        target: { value: "AES128" },
      });
      await flush();
      fireEvent.change(screen.getByPlaceholderText("Privacy passphrase"), {
        target: { value: "notreal" },
      });
      fireEvent.change(screen.getByPlaceholderText("e.g. vlan-100"), {
        target: { value: "vlan-7" },
      });
      await flush();
      fireEvent.keyDown(document, { key: "Escape" });
      await flush();
      await startScan();
      expect(dispatchBody().options).toEqual({
        snmp: {
          version: "v3",
          username: "snmp-ro",
          auth_protocol: "SHA256",
          auth_passphrase: "notreal",
          priv_protocol: "AES128",
          priv_passphrase: "notreal",
          context_name: "vlan-7",
        },
        credentials: [{ credential_id: "cred-1" }],
      });
    });

    it("SNMP v3 without privacy or a context sends neither; credentials switched on with none chosen send nothing", async () => {
      await ready({ cc_pipelineMode: "vulnerability_audit" });
      await openSettings();
      fireEvent.click(switchNear(/Authenticated Checks/i));
      await flush();
      fireEvent.click(switchNear(/Network Topology \(SNMP\)/i));
      await flush();
      fireEvent.change(screen.getByDisplayValue("v2c"), {
        target: { value: "v3" },
      });
      await flush();
      fireEvent.keyDown(document, { key: "Escape" });
      await flush();
      await startScan();
      expect(dispatchBody().options).toEqual({
        snmp: {
          version: "v3",
          username: "",
          auth_protocol: "SHA",
          auth_passphrase: "",
        },
      });
    });

    it("Enter in the target field starts the scan", async () => {
      await ready();
      fireEvent.keyDown(targetInput(), { key: "Enter" });
      await flush();
      expect(posts("/scan/host-discovery")).toHaveLength(1);
    });

    it("a second click cannot start a second scan", async () => {
      await ready();
      const button = startButton();
      fireEvent.click(button);
      fireEvent.click(button);
      await flush();
      expect(posts("/scan/host-discovery")).toHaveLength(1);
    });

    it("while the request is out, the mission view is already showing", async () => {
      const pending = deferred();
      postReply = (url) =>
        url === "/scan/host-discovery"
          ? pending.promise
          : { data: { ticket: "tk+1" } };
      await ready();
      await startScan();
      expect(layoutTitle()).toBe("Active Scan Mission");
      expect(bodyText()).toContain("Live Scanning");
      expect(bodyText()).toContain("5%");
      expect(posts("/auth/ticket")).toHaveLength(0);
      expect(here().path).toBe("/scan/new");
    });

    it.each([
      [
        "a rejected request",
        () => Promise.reject({ message: "Invalid target specified" }),
        "Invalid target specified",
      ],
      [
        "success: false with an error",
        () => ({ data: { success: false, error: "Quota exceeded" } }),
        "Quota exceeded",
      ],
      [
        "success: false alone",
        () => ({ data: { success: false } }),
        "The scan stopped before it finished. Check that the scanner worker is running.",
      ],
    ])(
      "%s is reported in the mission view, and Try Again returns to setup",
      async (_, reply, message) => {
        postReply = reply;
        await ready();
        await startScan();
        expect(bodyText()).toContain("Failed");
        expect(bodyText()).toContain(message);
        expect(posts("/auth/ticket")).toHaveLength(0);
        expect(here().path).toBe("/scan/new");
        expect(screen.queryByRole("button", { name: /Stop Scan/ })).toBeNull();
        fireEvent.click(screen.getByRole("button", { name: /Try Again/ }));
        await flush();
        expect(startButton()).toBeTruthy();
        expect(here()).toMatchObject({ path: "/scan/new", type: "PUSH" });
      },
    );

    it.each([
      [
        "an empty port list",
        {
          cc_pipelineMode: "asset",
          cc_portScanMode: "port",
          cc_portProfile: "custom",
          cc_customPorts: "",
        },
        "Ports list cannot be empty.",
      ],
      [
        "an invalid port list",
        {
          cc_pipelineMode: "asset",
          cc_portScanMode: "port",
          cc_portProfile: "custom",
          cc_customPorts: "22,22",
        },
        "Duplicate port detected: 22",
      ],
      [
        "invalid excluded ports",
        { cc_excludePorts: "80,abc" },
        "Exclude ports error: Invalid characters. Only numbers, commas, and hyphens are allowed.",
      ],
      [
        "invalid excluded IPs",
        { cc_excludeIps: "bad!" },
        'Exclude IPs error: Invalid IP, range, or CIDR format: "bad!"',
      ],
    ])(
      "%s stops the scan before anything is sent",
      async (_, session, message) => {
        await ready(session);
        await startScan();
        expect(api.post).not.toHaveBeenCalled();
        expect(layoutTitle()).toBe("New Scan");
        expect(bodyText()).toContain(message);
      },
    );
  });

  describe("a start requested by the route", () => {
    it("starts the scan once, 100 ms after load, and drops the request from the route", async () => {
      fakeTimers();
      await mount(
        { pathname: "/scan/new", state: { autoRun: true } },
        { cc_target: "10.60.1.10" },
      );
      expect(here()).toEqual({ path: "/scan/new", type: "REPLACE", state: {} });
      await advance(99);
      expect(posts("/scan/host-discovery")).toHaveLength(0);
      await advance(1);
      expect(posts("/scan/host-discovery")).toHaveLength(1);
      await advance(5000);
      expect(posts("/scan/host-discovery")).toHaveLength(1);
    });

    it.each([
      ["without scans:execute", VIEWER, "10.60.1.10"],
      ["without a target", EXECUTOR, ""],
    ])("does nothing %s", async (_, who, target) => {
      user = who;
      fakeTimers();
      await mount(
        { pathname: "/scan/new", state: { autoRun: true } },
        { cc_target: target },
      );
      await advance(1000);
      expect(api.post).not.toHaveBeenCalled();
    });
  });

  describe("mission: following the scan", () => {
    it("one ticket with no body, one socket, and the record every 2.5 s", async () => {
      await startMission();
      expect(layoutTitle()).toBe("Active Scan Mission");
      expect(posts("/auth/ticket")).toEqual([["/auth/ticket"]]);
      expect(sockets).toHaveLength(1);
      expect(sockets[0].url).toBe(TICKET_URL);
      expect(stored("cc_scanId")).toBe(SCAN);
      for (const text of [
        "Active Mission",
        "Host Discovery",
        "10.60.1.0/28",
        "Live Scanning",
        "10%",
        "Scanning subnet… waiting for active hosts.",
      ])
        expect(bodyText()).toContain(text);
      // The scan number comes only from route state, never from the context.
      expect(bodyText()).not.toContain("#4501");
      await advance(2499);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(0);
      await advance(1);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
      await advance(2500);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(2);
    });

    it("under StrictMode, still one ticket, one socket and one poll", async () => {
      await startMission({}, MISSION, true);
      expect(posts("/auth/ticket")).toHaveLength(1);
      expect(sockets).toHaveLength(1);
      await advance(2500);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
    });

    it("a scan handed over in route state is taken into the scan context, and the state dropped", async () => {
      await startMission(
        { cc_target: "", cc_scanNo: null, cc_pipelineMode: "basic" },
        {
          pathname: MISSION,
          state: {
            missionMode: true,
            scanId: SCAN,
            scanNo: 4602,
            target: "10.60.1.11",
            pipelineMode: "asset",
          },
        },
      );
      expect(stored("cc_target")).toBe("10.60.1.11");
      expect(stored("cc_pipelineMode")).toBe("asset");
      expect(stored("cc_scanNo")).toBe(4602);
      expect(here()).toEqual({ path: MISSION, type: "REPLACE", state: {} });
      expect(bodyText()).toContain("#4602");
      expect(bodyText()).toContain("Asset Discovery");
      expect(bodyText()).toContain("10.60.1.11");
    });

    it("progress frames set the totals, never move progress back, and list and enrich hosts", async () => {
      await startMission();
      await frame({
        status: "running",
        total_ips: 16,
        discovered: 4,
        hosts: [HOSTS[0], HOSTS[1]],
      });
      expect(bodyText()).toMatch(/16\s*Total IPs/);
      expect(bodyText()).toContain("21%");
      expect(rowText("10.60.1.11")).toContain("db-01");
      expect(rowText("10.60.1.11")).toContain("00:1A:2B:3C:6D:11");
      expect(rowText("10.60.1.12").match(/Resolving…/g)).toHaveLength(2);
      await frame({
        status: "running",
        total_ips: 16,
        discovered: 1,
        hosts: [HOSTS[0], HOSTS[1]],
      });
      expect(bodyText()).toContain("21%");
      await frame({
        status: "enriching",
        hosts: [
          {
            ip_address: "10.60.1.12",
            hostname: "cam-02",
            mac_address: "00:1A:2B:3C:6D:12",
          },
          { ip_address: "10.60.1.14", hostname: "new-04" },
        ],
      });
      expect(rowText("10.60.1.12")).toContain("cam-02");
      expect(rowText("10.60.1.12")).toContain("00:1A:2B:3C:6D:12");
      expect(rowText("10.60.1.12")).not.toContain("Resolving…");
      expect(rowText("10.60.1.14")).toContain("new-04");
      expect(rowText("10.60.1.14")).not.toContain("Resolving…");
    });

    it("polling lists live hosts while the socket is quiet", async () => {
      getReply = () => ({ data: record("running") });
      await startMission();
      await advance(2500);
      expect(rowText("10.60.1.11")).toContain("db-01");
      expect(rowText("10.60.1.12")).toContain("Resolving…");
      expect(screen.queryByText("10.60.1.13")).toBeNull();
    });

    it("a complete frame closes the socket, stops polling, reads the record once and stores discovery", async () => {
      getReply = () => ({ data: record("completed") });
      await startMission();
      await frame({ status: "complete", total_ips: 16, discovered: 2 });
      expect(sockets[0].closeCalls).toBe(1);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
      expect(stored("cc_phase1Hosts")).toEqual(HOSTS);
      expect(stored("cc_phase1Summary")).toEqual(SUMMARY);
      for (const text of ["Complete", "100%", "Scan complete"])
        expect(bodyText()).toContain(text);
      expect(screen.getByRole("button", { name: /View Results/ })).toBeTruthy();
      expect(screen.queryByRole("button", { name: /Stop Scan/ })).toBeNull();
      expect(
        screen.queryByRole("button", { name: /Run in Background/ }),
      ).toBeNull();
      expect(screen.queryByText("10.60.1.13")).toBeNull();
      await advance(10000);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
      expect(here().path).toBe(MISSION);
    });

    it("without results in the record, discovery is what the socket delivered", async () => {
      getReply = () => ({
        data: { id: SCAN, status: "completed", pipeline_mode: "basic" },
      });
      await startMission();
      await frame({
        status: "running",
        total_ips: 4,
        discovered: 1,
        hosts: [HOSTS[0]],
      });
      await frame({ status: "complete" });
      expect(stored("cc_phase1Hosts").map((h) => h.ip_address)).toEqual([
        "10.60.1.11",
      ]);
      expect(stored("cc_phase1Summary")).toEqual({});
    });

    it.each([
      [{ cc_pipelineMode: "basic" }, "/scan/host-discovery", null],
      [{ cc_pipelineMode: "asset" }, "/scan/asset-discovery", null],
      [
        { cc_pipelineMode: "asset", cc_executionMode: "interactive" },
        "/scan/host-discovery",
        null,
      ],
      [
        { cc_pipelineMode: "vulnerability_audit" },
        "/scan/vulnerability-audit",
        null,
      ],
      [
        { cc_pipelineMode: "advanced", cc_autoRunAdvancedSingleTarget: true },
        "/scan/vulnerability-audit",
        { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" },
      ],
    ])(
      "View Results follows the context's pipeline: %j → %s",
      async (session, target, state) => {
        getReply = () => ({ data: record("completed") });
        await startMission(session);
        await frame({ status: "complete" });
        fireEvent.click(screen.getByRole("button", { name: /View Results/ }));
        await flush();
        expect(here()).toEqual({ path: target, type: "PUSH", state });
      },
    );

    it.each([
      ["asset", {}, HOSTS, "/scan/asset-discovery", null],
      [
        "asset",
        { cc_executionMode: "interactive" },
        HOSTS,
        "/scan/host-discovery",
        null,
      ],
      [
        "vulnerability_audit",
        {},
        [HOSTS[0], HOSTS[2]],
        "/scan/vulnerability-audit",
        { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" },
      ],
      [
        "advanced",
        {},
        [HOSTS[0], HOSTS[2]],
        "/scan/vulnerability-audit",
        { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" },
      ],
      ["advanced", {}, HOSTS, "/scan/asset-discovery", null],
      [
        "vulnerability_audit",
        { cc_executionMode: "interactive" },
        HOSTS,
        "/scan/host-discovery",
        null,
      ],
    ])(
      "a completed %s scan hands over by itself (%j)",
      async (mode, session, hosts, target, state) => {
        getReply = () => ({
          data: record("completed", {
            pipeline_mode: mode,
            results: { phase1: { data: hosts, summary: SUMMARY } },
          }),
        });
        await startMission(session);
        await frame({ status: "complete" });
        expect(here()).toEqual({ path: target, type: "REPLACE", state });
      },
    );

    it("the pipeline mode handed over in the route outranks the record's", async () => {
      getReply = () => ({
        data: record("completed", {
          results: { phase1: { data: [HOSTS[0]], summary: SUMMARY } },
        }),
      });
      await startMission(
        {},
        {
          pathname: MISSION,
          state: {
            missionMode: true,
            scanId: SCAN,
            scanNo: 4501,
            target: "10.60.1.11",
            pipelineMode: "vulnerability_audit",
          },
        },
      );
      await frame({ status: "complete" });
      expect(here()).toEqual({
        path: "/scan/vulnerability-audit",
        type: "REPLACE",
        state: { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" },
      });
    });

    it("a basic scan that found nothing reads unreachable", async () => {
      getReply = () => ({
        data: record("completed", {
          results: { phase1: { data: [HOSTS[2]], summary: SUMMARY } },
        }),
      });
      await startMission();
      await frame({ status: "complete" });
      for (const text of [
        "Unreachable",
        "Target Unreachable",
        "No host responded on 10.60.1.0/28. The target may be powered off, on a different network, or blocking discovery probes (ARP, ICMP and TCP connect were all tried).",
        "Scan complete",
      ])
        expect(bodyText()).toContain(text);
      expect(screen.getByRole("button", { name: /Try Again/ })).toBeTruthy();
      expect(
        screen.queryByRole("button", { name: /Run in Background/ }),
      ).toBeNull();
      // Settled as complete, so View Results is still offered.
      expect(screen.getByRole("button", { name: /View Results/ })).toBeTruthy();
      expect(here().path).toBe(MISSION);
    });

    it("an asset scan that found nothing still hands over", async () => {
      getReply = () => ({
        data: record("completed", {
          pipeline_mode: "asset",
          results: { phase1: { data: [HOSTS[2]], summary: SUMMARY } },
        }),
      });
      await startMission();
      await frame({ status: "complete" });
      expect(here()).toEqual({
        path: "/scan/asset-discovery",
        type: "REPLACE",
        state: null,
      });
    });

    it.each([
      [
        "complete",
        { status: "failed", failure_reason: "Worker died" },
        "Failed",
        "Worker died",
      ],
      [
        "failed",
        { status: "running" },
        "Failed",
        "The scan stopped before it finished. Check that the scanner worker is running.",
      ],
      [
        "complete",
        { status: "canceled" },
        "Cancelled",
        "Scan cancelled. Any results collected before you stopped it are kept.",
      ],
      [
        "unreachable",
        { status: "running" },
        "Unreachable",
        "No host responded on 10.60.1.0/28.",
      ],
      ["complete", { status: "running" }, "Complete", "Scan complete"],
    ])(
      "socket %s, record %j: reads %s",
      async (wsStatus, fields, badge, message) => {
        getReply = () => ({ data: { ...record("running"), ...fields } });
        await startMission();
        await frame({ status: wsStatus });
        expect(bodyText()).toContain(badge);
        expect(bodyText()).toContain(message);
      },
    );

    it("polling that finds a finished scan settles it and leaves the socket open", async () => {
      getReply = () => ({
        data: record("failed", {
          failure_reason: "Timed out after 90 minutes",
        }),
      });
      await startMission();
      await advance(2500);
      expect(bodyText()).toContain("Failed");
      expect(bodyText()).toContain("Timed out after 90 minutes");
      expect(bodyText()).toContain("100%");
      expect(sockets[0].closeCalls).toBe(0);
      await advance(7500);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
    });

    it("polling reads completed as complete", async () => {
      getReply = () => ({ data: record("completed") });
      await startMission();
      await advance(2500);
      expect(bodyText()).toContain("Complete");
      expect(sockets[0].closeCalls).toBe(0);
    });

    it("a socket error closes it and lets the record decide", async () => {
      getReply = () => ({ data: record("completed") });
      await startMission();
      await act(async () => sockets[0].onerror?.(new Event("error")));
      await flush();
      expect(sockets[0].closeCalls).toBe(1);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
      expect(bodyText()).toContain("Complete");
      await advance(5000);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
    });

    it("a refused ticket opens no socket, stops polling at once, and reads a running record as complete", async () => {
      postReply = (url) =>
        url === "/auth/ticket"
          ? Promise.reject(new Error("ticket refused"))
          : { data: {} };
      getReply = () => ({ data: record("running") });
      await startMission();
      expect(sockets).toHaveLength(0);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
      expect(bodyText()).toContain("Complete");
      await advance(5000);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
    });

    it("a socket silent for ten minutes is closed, and a running record then reads complete", async () => {
      getReply = () => ({ data: record("running") });
      await startMission();
      await advance(599999);
      expect(sockets[0].closeCalls).toBe(0);
      await advance(1);
      expect(sockets[0].closeCalls).toBe(1);
      expect(bodyText()).toContain("Complete");
      const polls = gets(`/scans/${SCAN}`).length;
      await advance(5000);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(polls);
    });

    it("a frame for a later phase ends the socket", async () => {
      await startMission();
      await frame({ status: "running" }, 2);
      expect(sockets[0].closeCalls).toBe(1);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
    });

    it("a frame that is not JSON is ignored", async () => {
      await startMission();
      await act(async () => sockets[0].onmessage?.({ data: "not json" }));
      await flush();
      expect(sockets[0].closeCalls).toBe(0);
      expect(bodyText()).toContain("Live Scanning");
    });

    it("elapsed time counts while the scan runs", async () => {
      await startMission();
      await advance(5000);
      expect(bodyText()).toContain("Elapsed: 5s");
      await advance(60000);
      expect(bodyText()).toContain("Elapsed: 1m 5s");
    });

    it("unmounting leaves polling running and the socket open", async () => {
      const view = await startMission();
      view.unmount();
      await advance(2500);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
      expect(sockets[0].closeCalls).toBe(0);
    });
  });

  describe("mission: controls", () => {
    it("Stop Scan stops the scan once and reads it cancelled", async () => {
      const pending = deferred();
      postReply = (url) =>
        url === `/scans/${SCAN}/stop`
          ? pending.promise
          : { data: { ticket: "tk+1" } };
      await startMission();
      expect(
        screen.getAllByRole("button", { name: /Run in Background/ }).length,
      ).toBeGreaterThan(0);
      fireEvent.click(screen.getByRole("button", { name: /Stop Scan/ }));
      await flush();
      const busy = screen.getByRole("button", { name: /Stopping…/ });
      expect(busy).toBeDisabled();
      fireEvent.click(busy);
      await act(async () => pending.resolve({ data: { success: true } }));
      await flush();
      expect(posts(`/scans/${SCAN}/stop`)).toEqual([[`/scans/${SCAN}/stop`]]);
      for (const text of [
        "Cancelled",
        "Scan cancelled by user.",
        "Scan cancelled",
      ])
        expect(bodyText()).toContain(text);
      expect(screen.queryByRole("button", { name: /Stop Scan/ })).toBeNull();
      expect(screen.getByRole("button", { name: /Try Again/ })).toBeTruthy();
      await advance(5000);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(0);
      expect(sockets[0].closeCalls).toBe(0);
    });

    it.each([
      [
        {
          response: { data: { detail: "Scan is already in a terminal state" } },
        },
        "Scan is already in a terminal state",
      ],
      [{}, "Could not cancel the scan. It may have already finished."],
    ])(
      "a refused stop explains and leaves the scan running",
      async (failure, message) => {
        postReply = (url) =>
          url === `/scans/${SCAN}/stop`
            ? Promise.reject(failure)
            : { data: { ticket: "tk+1" } };
        await startMission();
        fireEvent.click(screen.getByRole("button", { name: /Stop Scan/ }));
        await flush();
        expect(bodyText()).toContain(message);
        expect(bodyText()).toContain("Live Scanning");
        expect(screen.getByRole("button", { name: /Stop Scan/ })).toBeEnabled();
      },
    );

    it("Run in Background leaves for scan history", async () => {
      await startMission();
      fireEvent.click(
        screen.getAllByRole("button", { name: /Run in Background/ })[0],
      );
      await flush();
      expect(here().path).toBe("/scan-history");
    });

    it("New Scan returns to setup and stops polling", async () => {
      await startMission();
      await advance(2500);
      fireEvent.click(screen.getByRole("button", { name: /New Scan/ }));
      await flush();
      expect(startButton()).toBeTruthy();
      expect(here()).toMatchObject({ path: "/scan/new", type: "PUSH" });
      await advance(10000);
      expect(gets(`/scans/${SCAN}`)).toHaveLength(1);
      expect(sockets[0].closeCalls).toBe(0);
    });
  });

  describe("routes", () => {
    it("App.jsx mounts both routes behind the base sign-in check only", () => {
      const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
      const baseAt = app.indexOf("<Route element={<PrivateRoute />}>");
      const firstGate = app.indexOf("requiredPermission", baseAt);
      for (const re of [
        /<Route path="\/scan\/new" element=\{<NewScan \/>\} \/>/,
        /<Route path="\/scan\/active\/:scanId" element=\{<NewScan \/>\} \/>/,
      ]) {
        const at = app.search(re);
        expect(at).toBeGreaterThan(baseAt);
        expect(at).toBeLessThan(firstGate);
      }
      expect(app.match(/<NewScan\b/g)).toHaveLength(2);
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 25 — the migration's specification. Each test fails on the legacy
   page.
   ════════════════════════════════════════════════════════════════════════════ */
const nameOf = (el) => {
  const label = el.getAttribute("aria-label");
  if (label) return label.trim();
  const by = el.getAttribute("aria-labelledby");
  if (by)
    return by
      .split(/\s+/)
      .map((id) => squash(document.getElementById(id)))
      .join(" ")
      .trim();
  if (el.id) {
    const forLabel = [...document.querySelectorAll("label")].find(
      (l) => l.htmlFor === el.id,
    );
    if (forLabel) return squash(forLabel);
  }
  const wrapping = el.closest("label");
  return wrapping ? squash(wrapping) : "";
};
const describedText = (el) =>
  (el.getAttribute("aria-describedby") || "")
    .split(/\s+/)
    .filter(Boolean)
    .map((id) => squash(document.getElementById(id)))
    .join(" ");
const GLYPHS = /[⚡⚖🔬🏃🔭🎯📂📥❌⚙🔌🚫⏱🔐🗺🔑👤🔒📋⚠✕←↩⏹→🖥📡×]/u;
const exposedGlyphs = () => {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const out = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (
      GLYPHS.test(n.textContent) &&
      !n.parentElement.closest("[aria-hidden=true]")
    )
      out.push(n.textContent.trim());
  }
  return out;
};
const styled = () =>
  [...document.body.querySelectorAll("[style]")].filter(
    (el) => !el.classList.contains("cc-progress__bar"),
  );

describe("NewScan — batch 25", () => {
  it("setup: one level-one heading, a labelled target field, a named file input and grouped choices", async () => {
    await mount("/scan/new", { cc_pipelineMode: "asset" });
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    const target = screen.getByRole("textbox", { name: "Target" });
    expect(target).toBe(targetInput());
    expect(describedText(target)).toContain("IP, CIDR, or range");
    expect(nameOf(fileInput())).toBe("Target list file");
    expect(
      within(screen.getByRole("group", { name: "Quick targets" })).getAllByRole(
        "button",
      ),
    ).toHaveLength(4);
    // Groups are named by their visible label.
    const profile = screen.getByRole("group", { name: "Discovery Profile" });
    const pressed = () =>
      within(profile)
        .getAllByRole("button")
        .map((b) => [
          squash(b).replace(/[^A-Za-z]/g, ""),
          b.getAttribute("aria-pressed"),
        ]);
    expect(pressed()).toEqual([
      ["Light", "false"],
      ["Normal", "true"],
      ["Deep", "false"],
    ]);
    fireEvent.click(within(profile).getByRole("button", { name: "Deep" }));
    expect(pressed()[2]).toEqual(["Deep", "true"]);
    cleanup();
    sessionStorage.clear();
    await mount("/scan/new", { cc_pipelineMode: "vulnerability_audit" });
    expect(screen.getByRole("group", { name: "Scan Profile" })).toBeTruthy();
  });

  it("advanced settings is a named modal dialog, absent while closed", async () => {
    await mount("/scan/new", { cc_pipelineMode: "asset" });
    expect(screen.queryByRole("dialog")).toBeNull();
    await openSettings();
    const d = screen.getByRole("dialog", { name: "Advanced Settings" });
    expect(d.getAttribute("aria-modal")).toBe("true");
    expect(
      within(d).getByRole("button", { name: "Close settings" }),
    ).toBeTruthy();
    expect(
      within(d).getByRole("group", { name: "Port Scan Intensity" }),
    ).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    await flush();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("every settings control has a name; switches are switches; the scan model is a radio group", async () => {
    await mount("/scan/new", {
      cc_pipelineMode: "asset",
      cc_portScanMode: "port",
      cc_portProfile: "custom",
      cc_excludePorts: "22",
      cc_excludeIps: "10.60.1.99",
    });
    await openSettings();
    let d = screen.getByRole("dialog");
    for (const re of [
      /Exclude Specific Ports/i,
      /Exclude Specific IPs/i,
      /OS Detection/i,
    ])
      expect(within(d).getByRole("switch", { name: re }).checked).toBe(true);
    const model = within(d).getByRole("radiogroup", {
      name: "Scan Configuration Model",
    });
    expect(
      within(model).getByRole("radio", { name: /Port-Based Scan/ }).checked,
    ).toBe(true);
    fireEvent.click(
      within(model).getByRole("radio", { name: /Intensity-Based Scan/ }),
    );
    await flush();
    expect(stored("cc_portScanMode")).toBe("intensity");
    fireEvent.click(
      within(model).getByRole("radio", { name: /Port-Based Scan/ }),
    );
    await flush();
    for (const el of d.querySelectorAll("input, select"))
      expect(nameOf(el), el.outerHTML).not.toBe("");
    expect(
      within(d).getByRole("combobox", { name: "Port Profile" }),
    ).toBeTruthy();
    expect(
      within(d).getByRole("combobox", { name: "Execution Mode" }),
    ).toBeTruthy();
    cleanup();
    sessionStorage.clear();

    await mount("/scan/new", { cc_pipelineMode: "vulnerability_audit" });
    await openSettings();
    d = screen.getByRole("dialog");
    fireEvent.click(
      within(d).getByRole("switch", { name: /Authenticated Checks/i }),
    );
    fireEvent.click(
      within(d).getByRole("switch", { name: /Network Topology \(SNMP\)/i }),
    );
    await flush();
    fireEvent.change(
      within(d).getByRole("combobox", { name: "SNMP Version" }),
      {
        target: { value: "v3" },
      },
    );
    await flush();
    fireEvent.change(
      within(d).getByRole("combobox", { name: "Privacy Protocol" }),
      {
        target: { value: "DES" },
      },
    );
    await flush();
    const creds = within(d).getByRole("group", { name: "Stored credentials" });
    expect(within(creds).getAllByRole("checkbox")).toHaveLength(2);
    expect(
      within(d).getByLabelText("Auth Passphrase").getAttribute("type"),
    ).toBe("password");
    expect(
      within(d).getByLabelText("Privacy Passphrase").getAttribute("type"),
    ).toBe("password");
    for (const el of d.querySelectorAll("input, select"))
      expect(nameOf(el), el.outerHTML).not.toBe("");
  });

  it("field errors are tied to their fields, and a setup error is an alert", async () => {
    await mount("/scan/new", {
      cc_pipelineMode: "asset",
      cc_portScanMode: "port",
      cc_portProfile: "custom",
      cc_excludePorts: "80,abc",
      cc_excludeIps: "bad!",
    });
    await openSettings();
    const custom = screen.getByRole("textbox", { name: /Custom Ports/i });
    fireEvent.change(custom, { target: { value: "22,22" } });
    await flush();
    expect(custom.getAttribute("aria-invalid")).toBe("true");
    expect(describedText(custom)).toContain("Duplicate port detected: 22");
    const ports = screen.getByRole("textbox", { name: /Ports to exclude/i });
    expect(ports.getAttribute("aria-invalid")).toBe("true");
    expect(describedText(ports)).toContain("Invalid characters.");
    const ips = screen.getByRole("textbox", { name: /IPs to exclude/i });
    expect(ips.getAttribute("aria-invalid")).toBe("true");
    expect(describedText(ips)).toContain(
      'Invalid IP, range, or CIDR format: "bad!"',
    );
    fireEvent.keyDown(document, { key: "Escape" });
    await flush();
    await upload(textFile("targets.zip", "x"));
    expect(squash(screen.getByRole("alert"))).toContain(
      "Unsupported file format",
    );
  });

  it("the imported list is a captioned table with named row actions; excluded ports and included ports are named lists", async () => {
    await mount("/scan/new", {
      cc_pipelineMode: "asset",
      cc_portScanMode: "port",
      cc_portProfile: "it",
      cc_excludePorts: "80, 443",
    });
    await upload(textFile("targets.txt", TARGET_FILE));
    await waitFor(() => expect(tableOf()).not.toBeNull());
    expect(squash(tableOf().querySelector("caption"))).toBe("Imported targets");
    for (const th of tableOf().querySelectorAll("thead th"))
      expect(th.getAttribute("scope")).toBe("col");
    expect(
      screen.getByRole("button", { name: "Remove 10.60.1.0/28" }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Dismiss import summary" }),
    ).toBeTruthy();
    await openSettings();
    expect(
      screen.getByRole("button", { name: "Remove excluded port 443" }),
    ).toBeTruthy();
    const included = screen.getByRole("list", { name: "Included ports" });
    const items = within(included).getAllByRole("listitem");
    expect(items).toHaveLength(IT_PORTS.split(",").length);
    expect(squash(items.find((i) => /^2375/.test(squash(i))))).toMatch(
      /sensitive/i,
    );
    expect(squash(items.find((i) => /^22\b/.test(squash(i))))).not.toMatch(
      /sensitive/i,
    );
  });

  it("mission: headings, a named progress bar, a named hosts list, and one announced outcome", async () => {
    getReply = () => ({
      data: record("failed", { failure_reason: "Worker died" }),
    });
    await startMission();
    expect(
      screen.getByRole("heading", { level: 1, name: /Active Mission/ }),
    ).toBeTruthy();
    expect(
      screen.getByRole("heading", { level: 2, name: "Discovered Systems" }),
    ).toBeTruthy();
    const bar = screen.getByRole("progressbar", { name: "Scan progress" });
    expect(bar.getAttribute("aria-valuenow")).toBe("10");
    await frame({
      status: "running",
      total_ips: 16,
      discovered: 4,
      hosts: [HOSTS[0], HOSTS[1]],
    });
    const list = screen.getByRole("list", { name: "Discovered Systems" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.queryAllByRole("alert")).toHaveLength(0);
    await frame({ status: "complete" });
    const alerts = screen.getAllByRole("alert");
    expect(alerts).toHaveLength(1);
    expect(squash(alerts[0])).toContain("Worker died");
  });

  it("mission: an unreachable target is announced once; Stop Scan reports that it is busy", async () => {
    getReply = () => ({
      data: record("completed", {
        results: { phase1: { data: [HOSTS[2]], summary: SUMMARY } },
      }),
    });
    await startMission();
    await frame({ status: "complete" });
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(
      screen
        .getByRole("progressbar", { name: "Scan progress" })
        .getAttribute("aria-valuenow"),
    ).toBe("100");
    cleanup();
    vi.useRealTimers();
    sockets = [];
    const pending = deferred();
    postReply = (url) =>
      url === `/scans/${SCAN}/stop`
        ? pending.promise
        : { data: { ticket: "tk+1" } };
    getReply = () => ({ data: record("running", { results: {} }) });
    await startMission();
    fireEvent.click(screen.getByRole("button", { name: "Stop Scan" }));
    await flush();
    const busy = screen.getByRole("button", { name: /Stopping/ });
    expect(busy.getAttribute("aria-busy")).toBe("true");
  });

  it("hides decorative glyphs from assistive technology", async () => {
    await mount("/scan/new", {
      cc_pipelineMode: "asset",
      cc_excludePorts: "80, 443",
    });
    await upload(textFile("targets.txt", TARGET_FILE));
    await waitFor(() => expect(tableOf()).not.toBeNull());
    expect(exposedGlyphs()).toEqual([]);
    await openSettings();
    expect(exposedGlyphs()).toEqual([]);
    cleanup();
    sessionStorage.clear();

    await mount("/scan/new", { cc_pipelineMode: "vulnerability_audit" });
    await openSettings();
    fireEvent.click(switchNear(/Authenticated Checks/i));
    fireEvent.click(switchNear(/Network Topology \(SNMP\)/i));
    await flush();
    expect(exposedGlyphs()).toEqual([]);
    cleanup();
    sessionStorage.clear();

    getReply = () => ({
      data: record("completed", {
        results: { phase1: { data: [HOSTS[2]], summary: SUMMARY } },
      }),
    });
    await startMission();
    await frame({
      status: "running",
      total_ips: 4,
      discovered: 1,
      hosts: [HOSTS[0]],
    });
    expect(exposedGlyphs()).toEqual([]);
    await frame({ status: "complete" });
    expect(exposedGlyphs()).toEqual([]);
  });

  it("renders no inline style of its own", async () => {
    await mount("/scan/new", {
      cc_pipelineMode: "asset",
      cc_portScanMode: "port",
      cc_portProfile: "custom",
      cc_customPorts: "22,6443",
      cc_excludePorts: "80,abc",
    });
    await upload(textFile("targets.txt", TARGET_FILE));
    await waitFor(() => expect(tableOf()).not.toBeNull());
    await openSettings();
    expect(styled()).toEqual([]);
    cleanup();
    sessionStorage.clear();
    await startMission();
    await frame({
      status: "running",
      total_ips: 4,
      discovered: 1,
      hosts: [HOSTS[0]],
    });
    expect(styled()).toEqual([]);
  });

  it("carries no colour literals, inline styles or classes from outside its stylesheet and the design system, and styles itself from tokens", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/scan/NewScan.jsx"),
      "utf8",
    );
    expect(source).toMatch(/import\s+["']\.\.\/\.\.\/styles\/NewScan\.css["']/);
    expect(source).toMatch(/from\s+["'](?:\.\.\/)+design-system["']/);
    expect(source).not.toMatch(/style=\{/);
    expect(source).not.toMatch(/onMouse(Enter|Leave|Down|Up)/);
    expect(source).not.toMatch(/dangerouslySetInnerHTML/);
    expect(source).not.toMatch(/console\.log/);
    expect(source.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(source).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(source).not.toMatch(/var\(--/);
    const classes = [
      ...source.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g),
    ].flatMap((m) =>
      // Interpolations are expressions, not class names: drop them first.
      (m[1] ?? m[2])
        .replace(/\$\{[^}]*\}/g, " ")
        .split(/\s+/)
        .filter(Boolean),
    );
    const foreign = classes.filter((c) => !/^(ns-|cc-)/.test(c));
    expect(foreign).toEqual([]);
    const cssPath = path.join(AUDIT_SRC, "styles/NewScan.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)[a-z0-9-]+/g) || []).toEqual([]);
    expect(css).not.toMatch(/prefers-color-scheme|ux4g/i);
    expect(css).toMatch(/:focus-visible/);
    expect(css).toMatch(/\.ns-card\s*\{[^}]*max-width:\s*680px;/);
  });
});
