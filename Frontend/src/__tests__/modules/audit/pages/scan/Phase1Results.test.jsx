/**
 * Phase1Results (`/scan/host-discovery`, `/scan/:scanId/phase1`) —
 * Checkpoint 3C batch 19 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 19 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The page shows host-discovery results held in the scan context, or loads
 * the scan named in the URL (GET /scans/{id}) and records it there.
 *
 * Its one write is "Run Port Scan": POST /scan/asset-discovery, offered only
 * in interactive mode on a pipeline with a phase 2. The request decides what
 * gets port-scanned, so its payload, its conditional keys, the parsers behind
 * them and the order its guards run in are pinned here exactly:
 *
 *   permission → a selected host → custom ports present → custom ports valid
 *   → excluded ports valid → excluded IPs valid → POST
 *
 * In automatic mode, while the port scan still has to run, the page waits
 * 4 seconds and then polls GET /scans/{id} every 4 seconds until phase 2 data
 * arrives or the scan completes or fails. It never navigates on its own.
 *
 * Unlike Phase 2, nothing here passes navigation state: every way to Phase 2
 * is a bare navigation to /scan/asset-discovery.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useState } from "react";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readFileSync } from "node:fs";
import path from "node:path";

import Phase1Results from "@audit/pages/scan/Phase1Results";
import { ScanProvider } from "@audit/context/ScanContext";
import api from "@shell/api/axiosInstance";
import { AUDIT_SRC } from "../../../../testPaths";
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
  default: ({ children }) => <div data-testid="app-layout">{children}</div>,
}));

vi.mock("@audit/components/layout/ScanStepper", () => ({
  default: ({ current }) => (
    <div data-testid="scan-stepper" data-current={current} />
  ),
}));

let exportProps = null;
vi.mock("@audit/components/scan/ExportPanel", () => ({
  default: (props) => {
    exportProps = props;
    return <div data-testid="export-panel" />;
  },
}));

const navigate = vi.fn();
let params = {};
let search = "";
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useParams: () => params,
    useSearchParams: () => [new URLSearchParams(search), vi.fn()],
    Link: ({ children, to, ...rest }) => (
      <a href={typeof to === "string" ? to : "#"} {...rest}>
        {children}
      </a>
    ),
  };
});

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

/* Field names are the page's reads, checked against the host-discovery phase
   the orchestrator stores (`to_basic_dict()` hosts and the phase summary). */
const HOSTS = [
  {
    ip_address: "10.20.0.11",
    hostname: "files-01",
    mac_address: "00:1A:2B:3C:4D:11",
    vendor: "Dell Inc.",
    discovery_method: "ARP",
    response_time_ms: 0.84,
    is_active: true,
  },
  {
    ip_address: "10.20.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    mac_address: "00:1A:2B:3C:4D:12",
    vendor: "HP",
    discovery_method: "ICMP",
    response_time_ms: 3.27,
    is_active: true,
  },
  {
    ip_address: "10.20.0.13",
    hostname: "Unknown",
    netbios_names: [{ name: "KIOSK-07" }],
    discovery_method: "TCP",
    response_time_ms: 12.5,
    is_active: true,
  },
  {
    ip_address: "10.20.0.14",
    hostname: "Unknown",
    discovery_method: "ICMP",
    is_active: false,
  },
  {
    ip_address: "10.20.0.15",
    hostname: "Unknown",
    mac_address: "00:1A:2B:3C:4D:15",
    vendor: "Raspberry Pi Trading",
    discovery_method: "ARP",
    response_time_ms: 1.9,
    is_active: true,
  },
];
const ACTIVE_HOSTS = HOSTS.filter((h) => h.is_active);
const ACTIVE = ACTIVE_HOSTS.map((h) => h.ip_address);

const SUMMARY = {
  total_hosts: 5,
  active_hosts: 4,
  inactive_hosts: 1,
  scan_duration: 12.84,
  phase: 1,
  discovery_profile: "BALANCED",
  discovery_intensity: "normal",
  fallback_targets_count: 2,
  fallback_active_hosts: 1,
};

const scanPayload = (overrides = {}) => ({
  id: "scan-41",
  scan_no: 1041,
  target: "10.20.0.0/28",
  status: "complete",
  pipeline_mode: "basic",
  results: { phase1: { data: HOSTS, summary: SUMMARY } },
  ...overrides,
});

const RUNNING = {
  id: "scan-41",
  status: "running",
  results: { phase1: { data: HOSTS, summary: SUMMARY }, phase2: {} },
};

const PHASE2_DATA = [
  {
    ip_address: "10.20.0.11",
    is_active: true,
    open_ports: [{ port: 22, service: "ssh" }],
  },
];

/* The real ScanProvider, seeded the way the pipeline leaves sessionStorage. */
const seed = (entries) => {
  for (const [key, value] of Object.entries(entries))
    sessionStorage.setItem(key, JSON.stringify(value));
};
const stored = (key) => JSON.parse(sessionStorage.getItem(key));

const context = ({
  mode = "basic",
  execution = "automatic",
  hosts = HOSTS,
  summary = SUMMARY,
  ...extra
} = {}) => ({
  cc_scanId: "scan-41",
  cc_scanNo: 1041,
  cc_target: "10.20.0.0/28",
  cc_pipelineMode: mode,
  cc_executionMode: execution,
  ...(hosts ? { cc_phase1Hosts: hosts } : {}),
  ...(summary ? { cc_phase1Summary: summary } : {}),
  ...extra,
});

const interactive = (extra = {}) =>
  context({ mode: "vulnerability_audit", execution: "interactive", ...extra });

/* Navigating unmounts the page, as the router does. */
let leavePage = () => {};
function RoutedPage() {
  const [left, setLeft] = useState(false);
  leavePage = () => setLeft(true);
  return left ? <div data-testid="navigated-away" /> : <Phase1Results />;
}

const renderPage = () =>
  render(
    <ScanProvider>
      <RoutedPage />
    </ScanProvider>,
  );

/* The page's only write is the dispatch, and only tests that press "Run Port
   Scan" may see it. */
let dispatchAllowed = false;
const dispatches = () =>
  api.post.mock.calls.filter(([url]) => url === "/scan/asset-discovery");
const otherWrites = () => [
  ...api.post.mock.calls.filter(([url]) => url !== "/scan/asset-discovery"),
  ...api.put.mock.calls,
  ...api.patch.mock.calls,
  ...api.delete.mock.calls,
];
const scanGets = (id = "scan-41") =>
  api.get.mock.calls.filter(([url]) => url === `/scans/${id}`).length;

const esc = (s) => s.replace(/\./g, "\\.");
const ipName = (ip) => new RegExp(`${esc(ip)}(?!\\d)`);

const checkboxes = () => [
  ...screen.queryAllByRole("checkbox"),
  ...screen.queryAllByRole("switch"),
];
const hostCheckbox = (ip) =>
  checkboxes().find(
    (cb) =>
      cb.closest("tbody tr") && ipName(ip).test(cb.closest("tr").textContent),
  );
const selectAll = () => checkboxes().find((cb) => cb.closest("thead"));

/* The nearest ancestor that names one exclusion and not the other. */
const near = (el, label, other) => {
  for (let n = el, i = 0; n && i < 6; n = n.parentElement, i += 1) {
    const t = n.textContent || "";
    if (label.test(t)) return !other.test(t);
  }
  return false;
};
const portsSwitch = () =>
  checkboxes().find(
    (cb) =>
      !cb.closest("table") &&
      near(cb, /Exclude Specific Ports/i, /Exclude Specific IPs/i),
  );
const ipsSwitch = () =>
  checkboxes().find(
    (cb) =>
      !cb.closest("table") &&
      near(cb, /Exclude Specific IPs/i, /Exclude Specific Ports/i),
  );

const CUSTOM_PLACEHOLDER = "e.g. 22,80,443,8000-8100";
const EXCLUDE_PORTS_PLACEHOLDER = "e.g. 2375,2376,6443,10250 or 80-90";
const EXCLUDE_IPS_PLACEHOLDER = "e.g. 10.180.12.10,10.190.0.0/16";

const runButton = () =>
  screen.getByRole("button", { name: /Run Port Scan on Selected Hosts/ });
const removeToken = (token) =>
  screen
    .getAllByRole("button")
    .find(
      (b) =>
        /×|Remove/.test(
          `${b.textContent} ${b.getAttribute("aria-label") || ""}`,
        ) && (b.closest("span, li")?.textContent || "").includes(token),
    );

const control = (name) =>
  screen.queryByRole("link", { name }) || screen.getByRole("button", { name });

/* Text split across elements, matched on the innermost element that holds all
   of it. A leading "⚠" glyph is ignored: the legacy page prints one, the
   design system's alert carries its own icon. */
const squash = (el) =>
  (el?.textContent || "")
    .replace(/\s+/g, " ")
    .replace(/^⚠\s*/, "")
    .trim();
const innermost = (test) =>
  screen.queryAllByText(
    (_, el) =>
      test(squash(el)) &&
      ![...(el?.children || [])].some((c) => test(squash(c))),
  );
const textShown = (text) => innermost((t) => t === text).length > 0;
const selectedCount = () => {
  const [el] = innermost((t) => /\d+ hosts? selected\.$/.test(t));
  return Number(squash(el).match(/(\d+) hosts? selected\.$/)[1]);
};

const expectLeadsTo = async (el, to) => {
  if (el.tagName === "A") {
    expect(el).toHaveAttribute("href", to);
    return;
  }
  await userEvent.click(el);
  expect(navigate).toHaveBeenCalledWith(to);
};

const flush = async (ms = 0) => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
};

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  params = {};
  search = "";
  user = EXECUTOR;
  exportProps = null;
  dispatchAllowed = false;
  navigate.mockImplementation(() => leavePage());
  api.get.mockResolvedValue({ data: scanPayload() });
  api.post.mockResolvedValue({ data: { success: true } });
});

afterEach(() => {
  expect(otherWrites()).toEqual([]);
  if (!dispatchAllowed) expect(dispatches()).toEqual([]);
});

/* ════════════════════════════════════════════════════════════════════════════
   Contract — passes on the legacy page and must keep passing
   ════════════════════════════════════════════════════════════════════════════ */
describe("Phase1Results — contract", () => {
  describe("loading", () => {
    it("shows the discovery held in the scan context without a request", async () => {
      seed(context());
      renderPage();
      expect(screen.getByText("10.20.0.11")).toBeInTheDocument();
      expect(api.get).not.toHaveBeenCalled();
      expect(navigate).not.toHaveBeenCalled();
    });

    it("loads the scan named in the URL once and records it in the scan context", async () => {
      params = { scanId: "scan-88" };
      api.get.mockResolvedValue({
        data: scanPayload({
          id: "scan-88",
          scan_no: 1088,
          target: "10.9.0.0/24",
          pipeline_mode: undefined,
        }),
      });
      renderPage();
      expect(screen.getByText(/Loading scan results/)).toBeInTheDocument();
      expect(await screen.findByText("10.20.0.11")).toBeInTheDocument();
      await act(async () => {
        await new Promise((r) => setTimeout(r, 30));
      });

      expect(api.get.mock.calls).toEqual([["/scans/scan-88"]]);
      expect(stored("cc_scanId")).toBe("scan-88");
      expect(stored("cc_scanNo")).toBe(1088);
      expect(stored("cc_target")).toBe("10.9.0.0/24");
      expect(stored("cc_pipelineMode")).toBe("basic");
      expect(stored("cc_phase1Hosts")).toEqual(HOSTS);
      expect(stored("cc_phase1Summary")).toEqual(SUMMARY);
      expect(navigate).not.toHaveBeenCalled();
    });

    it("also loads the scan named by ?scan_id=", async () => {
      search = "?scan_id=scan-89";
      // The response must carry the id that was asked for: the page re-loads
      // for as long as the id in context differs from the one requested.
      api.get.mockResolvedValue({ data: scanPayload({ id: "scan-89" }) });
      renderPage();
      expect(await screen.findByText("10.20.0.11")).toBeInTheDocument();
      expect(api.get).toHaveBeenCalledWith("/scans/scan-89");
    });

    it("reads phase1.hosts and the scan's own summary when phase1 carries neither data nor summary", async () => {
      params = { scanId: "scan-90" };
      api.get.mockResolvedValue({
        data: scanPayload({
          id: "scan-90",
          summary: { total_hosts: 2, active_hosts: 2 },
          results: { phase1: { hosts: HOSTS.slice(0, 2) } },
        }),
      });
      renderPage();
      expect(await screen.findByText("10.20.0.11")).toBeInTheDocument();
      expect(stored("cc_phase1Hosts")).toEqual(HOSTS.slice(0, 2));
      expect(stored("cc_phase1Summary")).toEqual({
        total_hosts: 2,
        active_hosts: 2,
      });
    });

    it("explains a scan with no discovery results instead of redirecting", async () => {
      params = { scanId: "scan-92" };
      api.get.mockResolvedValue({
        data: {
          id: "scan-92",
          status: "failed",
          failure_reason: "Host discovery did not complete.",
          results: { phase1: {} },
        },
      });
      renderPage();
      expect(
        await screen.findByText(/Host discovery did not complete\./),
      ).toBeInTheDocument();
      await expectLeadsTo(control(/Back to Scan History/), "/history");
      expect(navigate).not.toHaveBeenCalledWith("/scan", expect.anything());
    });

    it("uses a default explanation when the scan gives none", async () => {
      params = { scanId: "scan-93" };
      api.get.mockResolvedValue({ data: { id: "scan-93", results: {} } });
      renderPage();
      expect(
        await screen.findByText(
          /This scan has no host-discovery results to display\./,
        ),
      ).toBeInTheDocument();
    });

    it("shows the API's reason, or a default, when the scan cannot be loaded", async () => {
      params = { scanId: "scan-94" };
      api.get.mockRejectedValue({
        response: { data: { detail: "Scan not found" } },
      });
      const { unmount } = renderPage();
      expect(await screen.findByText(/Scan not found/)).toBeInTheDocument();
      unmount();

      params = { scanId: "scan-95" };
      api.get.mockRejectedValue(new Error("network"));
      renderPage();
      expect(
        await screen.findByText(/Could not load this scan's results\./),
      ).toBeInTheDocument();
      expect(navigate).not.toHaveBeenCalled();
    });

    it("returns to the scan picker when there are no discovered hosts", () => {
      renderPage();
      expect(navigate).toHaveBeenCalledWith("/scan", { replace: true });
      expect(api.get).not.toHaveBeenCalled();
    });

    it("a scan loaded from the URL starts with no host selected", async () => {
      params = { scanId: "scan-96" };
      seed({ cc_executionMode: "interactive" });
      api.get.mockResolvedValue({
        data: scanPayload({
          id: "scan-96",
          pipeline_mode: "vulnerability_audit",
        }),
      });
      renderPage();
      expect(
        await screen.findByText(/Configure & Run Port Scan/),
      ).toBeInTheDocument();
      expect(selectedCount()).toBe(0);
      expect(runButton()).toBeDisabled();
    });
  });

  describe("dispatching the port scan", () => {
    beforeEach(() => {
      dispatchAllowed = true;
    });

    it("offers the port-scan controls only in interactive mode on a pipeline with a phase 2", () => {
      seed(context({ mode: "basic", execution: "interactive" }));
      const { unmount } = renderPage();
      expect(screen.queryByText(/Configure & Run Port Scan/)).toBeNull();
      expect(checkboxes()).toHaveLength(0);
      unmount();

      sessionStorage.clear();
      seed(context({ mode: "asset", execution: "automatic" }));
      renderPage();
      expect(screen.queryByText(/Configure & Run Port Scan/)).toBeNull();
      expect(checkboxes()).toHaveLength(0);
    });

    it("selects every active host by default", () => {
      seed(interactive());
      renderPage();
      expect(selectedCount()).toBe(4);
      for (const ip of ACTIVE) expect(hostCheckbox(ip)).toBeChecked();
    });

    it("sends exactly the selected hosts, intensity and scan settings, then moves to phase 2", async () => {
      seed(
        interactive({ cc_portScanIntensity: "deep", cc_osDetection: false }),
      );
      renderPage();
      await userEvent.click(runButton());

      expect(api.post).toHaveBeenCalledTimes(1);
      expect(api.post.mock.calls[0]).toEqual([
        "/scan/asset-discovery",
        {
          hosts: ACTIVE_HOSTS,
          intensity: "deep",
          scan_id: "scan-41",
          pipeline_mode: "vulnerability_audit",
          os_detection: false,
          phases: [1, 2],
        },
      ]);
      expect(stored("cc_pipelineState")).toBe("PORT_SCAN");
      expect(navigate.mock.calls).toEqual([["/scan/asset-discovery"]]);
    });

    it("falls back to normal intensity when none is recorded", async () => {
      seed(interactive({ cc_portScanIntensity: "" }));
      renderPage();
      await userEvent.click(runButton());
      expect(api.post.mock.calls[0][1].intensity).toBe("normal");
      expect(api.post.mock.calls[0][1].os_detection).toBe(true);
    });

    it("in custom mode sends intensity custom and the port list as written", async () => {
      seed(
        interactive({
          cc_portScanMode: "custom",
          cc_customPorts: "22, 80,8000-8010",
        }),
      );
      renderPage();
      await userEvent.click(runButton());
      const body = api.post.mock.calls[0][1];
      expect(body.intensity).toBe("custom");
      expect(body.custom_ports).toBe("22, 80,8000-8010");
      expect(Object.keys(body).sort()).toEqual(
        [
          "custom_ports",
          "hosts",
          "intensity",
          "os_detection",
          "phases",
          "pipeline_mode",
          "scan_id",
        ].sort(),
      );
    });

    it("sends exclusions trimmed, and only when they are set", async () => {
      seed(
        interactive({
          cc_excludePorts: " 2375,6443 ",
          cc_excludeIps: " 10.20.0.13 ",
        }),
      );
      renderPage();
      await userEvent.click(runButton());
      const body = api.post.mock.calls[0][1];
      expect(body.exclude_ports).toBe("2375,6443");
      expect(body.exclude_ips).toBe("10.20.0.13");
      expect("custom_ports" in body).toBe(false);
    });

    it("turning an exclusion off clears it, so it is not sent", async () => {
      seed(
        interactive({ cc_excludePorts: "2375", cc_excludeIps: "10.20.0.13" }),
      );
      renderPage();
      await userEvent.click(portsSwitch());
      await userEvent.click(ipsSwitch());
      expect(stored("cc_excludePorts")).toBe("");
      expect(stored("cc_excludeIps")).toBe("");
      await userEvent.click(runButton());
      const body = api.post.mock.calls[0][1];
      expect("exclude_ports" in body).toBe(false);
      expect("exclude_ips" in body).toBe(false);
    });

    it("sends only the hosts left selected; select-all selects or clears every active host", async () => {
      seed(interactive());
      renderPage();
      await userEvent.click(hostCheckbox("10.20.0.12"));
      expect(selectedCount()).toBe(3);

      await userEvent.click(selectAll());
      expect(selectedCount()).toBe(4);
      await userEvent.click(selectAll());
      expect(selectedCount()).toBe(0);
      expect(runButton()).toBeDisabled();

      await userEvent.click(hostCheckbox("10.20.0.11"));
      await userEvent.click(hostCheckbox("10.20.0.15"));
      await userEvent.click(runButton());
      expect(api.post.mock.calls[0][1].hosts.map((h) => h.ip_address)).toEqual([
        "10.20.0.11",
        "10.20.0.15",
      ]);
    });

    it("an inactive host cannot be selected", async () => {
      seed(interactive());
      renderPage();
      await userEvent.click(
        screen.getByRole("button", { name: /^All \(5\)$/ }),
      );
      expect(hostCheckbox("10.20.0.14")).toBeDisabled();
      expect(hostCheckbox("10.20.0.14")).not.toBeChecked();
    });

    it("shows a refusal and stays on the page", async () => {
      seed(interactive());
      api.post.mockResolvedValueOnce({
        data: { success: false, error: "Quota exceeded" },
      });
      const { unmount } = renderPage();
      await userEvent.click(runButton());
      expect(await screen.findByText(/Quota exceeded/)).toBeInTheDocument();
      expect(navigate).not.toHaveBeenCalled();
      expect(stored("cc_pipelineState")).not.toBe("PORT_SCAN");
      unmount();

      api.post.mockResolvedValueOnce({ data: { success: false } });
      renderPage();
      await userEvent.click(runButton());
      expect(
        await screen.findByText(/Port scan failed to start\./),
      ).toBeInTheDocument();
    });

    it("shows a failed request's message, or a default", async () => {
      seed(interactive());
      api.post.mockRejectedValueOnce(new Error("Network Error"));
      const { unmount } = renderPage();
      await userEvent.click(runButton());
      expect(await screen.findByText(/Network Error/)).toBeInTheDocument();
      unmount();

      api.post.mockRejectedValueOnce({});
      renderPage();
      await userEvent.click(runButton());
      expect(
        await screen.findByText(/Failed to start Port Scan/),
      ).toBeInTheDocument();
      expect(navigate).not.toHaveBeenCalled();
    });
  });

  describe("validation before dispatch", () => {
    it("refuses custom mode with no ports", async () => {
      seed(interactive({ cc_portScanMode: "custom", cc_customPorts: "" }));
      renderPage();
      await userEvent.click(runButton());
      expect(
        screen.getByText(
          /Custom ports list cannot be empty when custom ports mode is active\./,
        ),
      ).toBeInTheDocument();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("checks custom ports before exclusions, excluded ports before excluded IPs", async () => {
      seed(
        interactive({
          cc_portScanMode: "custom",
          cc_customPorts: "22,abc",
          cc_excludePorts: "80-70",
          cc_excludeIps: "10.20.0.0/33",
        }),
      );
      const first = renderPage();
      await userEvent.click(runButton());
      expect(
        textShown(
          "Invalid characters. Only numbers, commas, and hyphens are allowed.",
        ),
      ).toBe(true);
      expect(screen.queryByText(/Exclude ports error/)).toBeNull();
      first.unmount();

      sessionStorage.clear();
      seed(
        interactive({
          cc_excludePorts: "80-70",
          cc_excludeIps: "10.20.0.0/33",
        }),
      );
      const second = renderPage();
      await userEvent.click(runButton());
      expect(
        screen.getByText(
          /Exclude ports error: Range start must be <= end: "80-70"/,
        ),
      ).toBeInTheDocument();
      second.unmount();

      sessionStorage.clear();
      seed(interactive({ cc_excludeIps: "10.20.0.0/33" }));
      renderPage();
      await userEvent.click(runButton());
      expect(
        screen.getByText(
          /Exclude IPs error: Invalid IP, range, or CIDR format: "10\.20\.0\.0\/33"/,
        ),
      ).toBeInTheDocument();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("shows an invalid excluded IP as soon as it is known", () => {
      seed(interactive({ cc_excludeIps: "10.20.0.13,bad_host!" }));
      renderPage();
      expect(
        screen.getByText(/Invalid IP, range, or CIDR format: "bad_host!"/),
      ).toBeInTheDocument();
    });

    it.each([
      [
        "22,abc",
        "Invalid characters. Only numbers, commas, and hyphens are allowed.",
      ],
      ["80-90-100", 'Invalid range format: "80-90-100"'],
      ["-5", 'Invalid range bounds: "-5"'],
      ["90-80", 'Range start must be <= end: "90-80"'],
      ["0-10", 'Ports must be between 1 and 65535: "0-10"'],
      ["70000", "Port must be between 1 and 65535: 70000"],
      ["22,22", "Duplicate port detected: 22"],
      ["20-25,22", "Duplicate port detected: 22"],
    ])(
      "parses custom ports %j as %j and blocks the scan",
      async (value, message) => {
        seed(interactive({ cc_portScanMode: "custom" }));
        renderPage();
        const input = screen.getByPlaceholderText(CUSTOM_PLACEHOLDER);
        await userEvent.type(input, value);
        expect(textShown(message)).toBe(true);
        expect(runButton()).toBeDisabled();
      },
    );

    it("accepts a valid list, and switching mode clears a custom-ports error", async () => {
      seed(interactive({ cc_portScanMode: "custom" }));
      renderPage();
      const input = screen.getByPlaceholderText(CUSTOM_PLACEHOLDER);
      await userEvent.type(input, "22,abc");
      expect(screen.getByText(/Invalid characters/)).toBeInTheDocument();

      await userEvent.click(
        screen.getByRole("button", { name: "Intensity Profile" }),
      );
      await userEvent.click(
        screen.getByRole("button", { name: "Custom Ports" }),
      );
      expect(screen.queryByText(/Invalid characters/)).toBeNull();
      expect(runButton()).toBeEnabled();
      // The value is still invalid; the guard at dispatch still catches it.
      await userEvent.click(runButton());
      expect(screen.getByText(/Invalid characters/)).toBeInTheDocument();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("quick-select fills the custom port list and clears its error", async () => {
      seed(interactive({ cc_portScanMode: "custom" }));
      renderPage();
      const input = screen.getByPlaceholderText(CUSTOM_PLACEHOLDER);
      await userEvent.type(input, "22,abc");
      for (const label of ["IT", "SCADA", "Web", "Database", "Remote"])
        expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: "Web" }));
      expect(input).toHaveValue(
        "80,443,3000,5000,8000,8080,8443,8888,9000,9090,9443",
      );
      expect(screen.queryByText(/Invalid characters/)).toBeNull();
      expect(stored("cc_customPorts")).toBe(
        "80,443,3000,5000,8000,8080,8443,8888,9000,9090,9443",
      );
    });

    it("warns about sensitive ports only in custom mode", async () => {
      seed(interactive({ cc_customPorts: "22,2375" }));
      const { unmount } = renderPage();
      expect(screen.queryByText(/Sensitive Ports Detected/)).toBeNull();
      unmount();

      sessionStorage.clear();
      seed(interactive({ cc_portScanMode: "custom", cc_customPorts: "22,80" }));
      renderPage();
      expect(screen.queryByText(/Sensitive Ports Detected/)).toBeNull();
      await userEvent.click(screen.getByRole("button", { name: "IT" }));
      expect(screen.getByText(/Sensitive Ports Detected/)).toBeInTheDocument();
    });

    it.each([[2375], [2376], [6443], [10250]])(
      "treats port %i as sensitive",
      (port) => {
        seed(
          interactive({
            cc_portScanMode: "custom",
            cc_customPorts: `22,${port}`,
          }),
        );
        renderPage();
        expect(
          screen.getByText(/Sensitive Ports Detected/),
        ).toBeInTheDocument();
      },
    );

    it("excluded ports: the quick option, tags and tag removal", async () => {
      seed(interactive());
      renderPage();
      expect(
        screen.queryByPlaceholderText(EXCLUDE_PORTS_PLACEHOLDER),
      ).toBeNull();
      await userEvent.click(portsSwitch());
      await userEvent.click(
        screen.getByRole("button", { name: "Sensitive Ports" }),
      );
      expect(stored("cc_excludePorts")).toBe("2375,2376,6443,10250");
      expect(
        screen.getByPlaceholderText(EXCLUDE_PORTS_PLACEHOLDER),
      ).toHaveValue("2375,2376,6443,10250");
      await userEvent.click(removeToken("6443"));
      expect(stored("cc_excludePorts")).toBe("2375, 2376, 10250");
    });

    it("excluded IPs: the switch reveals the field", async () => {
      seed(interactive());
      renderPage();
      expect(screen.queryByPlaceholderText(EXCLUDE_IPS_PLACEHOLDER)).toBeNull();
      await userEvent.click(ipsSwitch());
      expect(
        screen.getByPlaceholderText(EXCLUDE_IPS_PLACEHOLDER),
      ).toBeInTheDocument();
    });
  });

  describe("permission", () => {
    it("without scans:execute the scan cannot be started or scoped, as before", async () => {
      user = VIEWER;
      seed(
        interactive({
          cc_excludePorts: "2375, 6443",
          cc_excludeIps: "10.20.0.13",
        }),
      );
      renderPage();
      expect(runButton()).toBeDisabled();
      expect(selectAll()).toBeDisabled();
      for (const ip of ACTIVE) expect(hostCheckbox(ip)).toBeDisabled();
      expect(
        screen.getByPlaceholderText(EXCLUDE_PORTS_PLACEHOLDER),
      ).toBeDisabled();
      expect(
        screen.getByPlaceholderText(EXCLUDE_IPS_PLACEHOLDER),
      ).toBeDisabled();
      expect(
        screen.getByRole("button", { name: "Sensitive Ports" }),
      ).toBeDisabled();
      expect(removeToken("2375")).toBeDisabled();

      // Pinned as found: these were never gated.
      expect(
        screen.getByRole("button", { name: "Custom Ports" }),
      ).toBeEnabled();
      expect(portsSwitch()).toBeEnabled();
      expect(ipsSwitch()).toBeEnabled();

      await userEvent.click(runButton());
      expect(api.post).not.toHaveBeenCalled();
    });
  });

  describe("automatic mode", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      api.get.mockResolvedValue({ data: RUNNING });
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it("waits 4 seconds, polls every 4 seconds, and stops when phase 2 data arrives", async () => {
      seed(context({ mode: "asset" }));
      renderPage();
      await flush();
      expect(scanGets()).toBe(0);
      expect(screen.getByText(/Port Scan Running/)).toBeInTheDocument();
      expect(stored("cc_pipelineState")).toBe("PORT_SCAN");

      await flush(3999);
      expect(scanGets()).toBe(0);
      await flush(1);
      expect(scanGets()).toBe(1);
      await flush(4000);
      expect(scanGets()).toBe(2);

      api.get.mockResolvedValue({
        data: {
          ...RUNNING,
          results: {
            phase1: RUNNING.results.phase1,
            phase2: { data: PHASE2_DATA, summary: { hosts_with_ports: 1 } },
          },
        },
      });
      await flush(4000);
      expect(scanGets()).toBe(3);
      expect(stored("cc_phase2Results")).toEqual(PHASE2_DATA);
      expect(stored("cc_phase2Summary")).toEqual({ hosts_with_ports: 1 });
      expect(screen.getByText(/Port Scan Complete/)).toBeInTheDocument();
      expect(stored("cc_pipelineState")).toBe("REPORT_READY");
      await flush(20000);
      expect(scanGets()).toBe(3);
      expect(navigate).not.toHaveBeenCalled();
    });

    it.each(["complete", "failed"])(
      "stops when the scan is %s without phase 2 data",
      async (status) => {
        seed(context({ mode: "asset" }));
        api.get.mockResolvedValue({ data: { ...RUNNING, status } });
        renderPage();
        await flush(4000);
        expect(scanGets()).toBe(1);
        await flush(20000);
        expect(scanGets()).toBe(1);
        expect(screen.queryByText(/Port Scan Complete/)).toBeNull();
      },
    );

    it("keeps polling through a failed request and stops when the page is left", async () => {
      seed(context({ mode: "asset" }));
      api.get.mockRejectedValueOnce(new Error("network"));
      const { unmount } = renderPage();
      await flush(4000);
      expect(scanGets()).toBe(1);
      await flush(4000);
      expect(scanGets()).toBe(2);
      unmount();
      await flush(12000);
      expect(scanGets()).toBe(2);
    });

    it("never navigates on its own, even on a pipeline with a phase 3", async () => {
      seed(context({ mode: "vulnerability_audit" }));
      api.get.mockResolvedValue({
        data: {
          ...RUNNING,
          results: {
            phase1: RUNNING.results.phase1,
            phase2: { data: PHASE2_DATA },
          },
        },
      });
      renderPage();
      await flush(4000);
      expect(scanGets()).toBe(1);
      expect(screen.getByText(/Port Scan Complete/)).toBeInTheDocument();
      expect(stored("cc_pipelineState")).toBe("PORT_SCAN");
      await flush(20000);
      expect(navigate).not.toHaveBeenCalled();
    });

    it("does not poll in interactive mode, on a basic scan, when unreachable, or when phase 2 is done", async () => {
      const cases = [
        context({ mode: "asset", execution: "interactive" }),
        context({ mode: "basic" }),
        context({
          mode: "asset",
          summary: { ...SUMMARY, active_hosts: 0 },
        }),
        context({ mode: "asset", cc_phase2Results: PHASE2_DATA }),
      ];
      for (const entries of cases) {
        sessionStorage.clear();
        seed(entries);
        const { unmount } = renderPage();
        await flush(12000);
        unmount();
      }
      expect(scanGets()).toBe(0);
    });
  });

  describe("navigation and pipeline state", () => {
    it("links the finished port scan to its results", async () => {
      seed(context({ mode: "asset", cc_phase2Results: PHASE2_DATA }));
      renderPage();
      expect(screen.getByText(/Port Scan Complete/)).toBeInTheDocument();
      await expectLeadsTo(
        control(/View Port Scan Results/),
        "/scan/asset-discovery",
      );
      expect(navigate.mock.calls.every((c) => c.length === 1)).toBe(true);
    });

    it("continues to the port scan outside automatic and interactive modes", async () => {
      seed(context({ mode: "vulnerability_audit", execution: "manual" }));
      const { unmount } = renderPage();
      await userEvent.click(
        screen.getByRole("button", { name: "Continue to Port Scan" }),
      );
      expect(navigate.mock.calls).toEqual([["/scan/asset-discovery"]]);
      unmount();

      navigate.mockClear();
      user = VIEWER;
      sessionStorage.clear();
      seed(context({ mode: "vulnerability_audit", execution: "manual" }));
      renderPage();
      expect(
        screen.getByRole("button", { name: "Continue to Port Scan" }),
      ).toBeDisabled();
    });

    it("has no continue action on an asset pipeline or in automatic mode", () => {
      seed(context({ mode: "asset", execution: "manual" }));
      const { unmount } = renderPage();
      expect(
        screen.queryByRole("button", { name: "Continue to Port Scan" }),
      ).toBeNull();
      unmount();
      sessionStorage.clear();
      seed(context({ mode: "vulnerability_audit" }));
      renderPage();
      expect(
        screen.queryByRole("button", { name: "Continue to Port Scan" }),
      ).toBeNull();
    });

    it.each([
      ["basic", "automatic", {}, "PORT_SCAN", "1"],
      ["asset", "automatic", {}, "PORT_SCAN", "2"],
      ["asset", "interactive", {}, "IDLE", "1"],
      [
        "asset",
        "automatic",
        { cc_phase2Results: PHASE2_DATA },
        "REPORT_READY",
        "3",
      ],
      [
        "vulnerability_audit",
        "automatic",
        { cc_phase2Results: PHASE2_DATA },
        "PORT_SCAN",
        "2",
      ],
    ])(
      "%s / %s %j: pipeline state %s, stepper step %s",
      (mode, execution, extra, state, step) => {
        vi.useFakeTimers();
        try {
          seed(context({ mode, execution, ...extra }));
          renderPage();
          expect(stored("cc_pipelineState")).toBe(state);
          expect(screen.getByTestId("scan-stepper")).toHaveAttribute(
            "data-current",
            step,
          );
        } finally {
          vi.useRealTimers();
        }
      },
    );

    it("leads to a new scan", async () => {
      seed(context());
      renderPage();
      await expectLeadsTo(control(/New Scan$/), "/audit-dashboard");
    });
  });

  describe("presentation", () => {
    it("a basic scan shows completion and hands the export panel the discovery", () => {
      seed(context());
      renderPage();
      expect(
        screen.getByText(/Scan completed\. Export report available below\./),
      ).toBeInTheDocument();
      expect(exportProps).toEqual({
        results: HOSTS,
        summary: SUMMARY,
        scanId: "scan-41",
        scanNo: 1041,
        target: "10.20.0.0/28",
        pipelineMode: "basic",
      });
    });

    it("a pipeline with a phase 2 has no export panel unless the target was unreachable", () => {
      vi.useFakeTimers();
      try {
        seed(context({ mode: "asset" }));
        const { unmount } = renderPage();
        expect(screen.queryByTestId("export-panel")).toBeNull();
        unmount();

        sessionStorage.clear();
        seed(
          context({ mode: "asset", summary: { ...SUMMARY, active_hosts: 0 } }),
        );
        renderPage();
        expect(screen.getByTestId("export-panel")).toBeInTheDocument();
        expect(
          screen.getByText("Host is unavailable/down/unreachable"),
        ).toBeInTheDocument();
        expect(screen.queryByText(/Port Scan Running/)).toBeNull();
      } finally {
        vi.useRealTimers();
      }
    });

    it("summarises the discovery, with the profile and fallback only on asset discovery", () => {
      vi.useFakeTimers();
      try {
        seed(context());
        const { unmount } = renderPage();
        expect(screen.getByText("12.8s")).toBeInTheDocument();
        /* Scoped to the summary strip since P2-4. The chip rule this test
           protects is unchanged — the profile chip belongs to asset discovery
           only — but the scan-parameters block below the results now states
           the profile on every discovery, because a reader cannot tell a
           clean range from an unscanned one without it. */
        const strip = () => document.querySelector(".p1-summary");
        expect(within(strip()).queryByText("BALANCED")).toBeNull();
        expect(screen.queryByText(/Fallback:/)).toBeNull();
        unmount();

        sessionStorage.clear();
        seed(context({ mode: "asset" }));
        renderPage();
        expect(within(strip()).getByText("BALANCED")).toBeInTheDocument();
        expect(textShown("Fallback: 1/2 resolved")).toBe(true);
      } finally {
        vi.useRealTimers();
      }
    });

    it("filters hosts on scans other than asset discovery; asset discovery lists active hosts", async () => {
      seed(context());
      const { unmount } = renderPage();
      expect(screen.queryByText("10.20.0.14")).toBeNull();
      await userEvent.click(
        screen.getByRole("button", { name: /^All \(5\)$/ }),
      );
      expect(screen.getByText("10.20.0.14")).toBeInTheDocument();
      unmount();

      vi.useFakeTimers();
      try {
        sessionStorage.clear();
        seed(context({ mode: "asset" }));
        renderPage();
        expect(
          screen.queryByRole("button", { name: /^All \(5\)$/ }),
        ).toBeNull();
        expect(screen.queryByText("10.20.0.14")).toBeNull();
        expect(screen.getByText("10.20.0.15")).toBeInTheDocument();
      } finally {
        vi.useRealTimers();
      }
    });

    it("shows response times except on a basic scan", () => {
      vi.useFakeTimers();
      try {
        seed(context());
        const { unmount } = renderPage();
        expect(screen.queryByText("0.8 ms")).toBeNull();
        unmount();
        sessionStorage.clear();
        seed(context({ mode: "asset" }));
        renderPage();
        expect(screen.getByText("0.8 ms")).toBeInTheDocument();
      } finally {
        vi.useRealTimers();
      }
    });

    it("shows the recorded intensity in intensity mode", () => {
      seed(interactive({ cc_portScanIntensity: "deep" }));
      renderPage();
      expect(screen.getByText("DEEP")).toBeInTheDocument();
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 19 — fails on the legacy page, each for the reason in its name
   ════════════════════════════════════════════════════════════════════════════ */
describe("Phase1Results — batch 19", () => {
  it("has one level-one heading", () => {
    seed(context());
    renderPage();
    expect(
      screen.getByRole("heading", { level: 1, name: "Discovery Results" }),
    ).toBeInTheDocument();
  });

  it("names every host-selection control", async () => {
    seed(interactive());
    renderPage();
    expect(
      screen.getByRole("checkbox", { name: /select all active hosts/i }),
    ).toBeInTheDocument();
    for (const ip of ACTIVE)
      expect(
        screen.getByRole("checkbox", { name: ipName(ip) }),
      ).toBeInTheDocument();
  });

  it("labels the port and address fields and the exclusion switches", async () => {
    seed(
      interactive({
        cc_portScanMode: "custom",
        cc_excludePorts: "2375",
        cc_excludeIps: "10.20.0.13",
      }),
    );
    renderPage();
    expect(screen.getByLabelText(/custom ports/i)).toBe(
      screen.getByPlaceholderText(CUSTOM_PLACEHOLDER),
    );
    expect(screen.getByLabelText(/ports to exclude/i)).toBe(
      screen.getByPlaceholderText(EXCLUDE_PORTS_PLACEHOLDER),
    );
    expect(screen.getByLabelText(/addresses or subnets to exclude/i)).toBe(
      screen.getByPlaceholderText(EXCLUDE_IPS_PLACEHOLDER),
    );
    expect(
      screen.getByRole("switch", { name: /exclude specific ports/i }),
    ).toBeChecked();
    expect(
      screen.getByRole("switch", { name: /exclude specific ips/i }),
    ).toBeChecked();
  });

  it("ties each validation message to its field", async () => {
    seed(
      interactive({ cc_portScanMode: "custom", cc_excludeIps: "bad_host!" }),
    );
    renderPage();
    const ips = screen.getByPlaceholderText(EXCLUDE_IPS_PLACEHOLDER);
    expect(ips).toHaveAttribute("aria-invalid", "true");
    expect(
      document.getElementById(ips.getAttribute("aria-describedby")),
    ).toHaveTextContent(/Invalid IP, range, or CIDR format/);

    const ports = screen.getByPlaceholderText(CUSTOM_PLACEHOLDER);
    expect(ports).not.toHaveAttribute("aria-invalid", "true");
    await userEvent.type(ports, "22,abc");
    expect(ports).toHaveAttribute("aria-invalid", "true");
    expect(
      document.getElementById(ports.getAttribute("aria-describedby")),
    ).toHaveTextContent(/Invalid characters/);
  });

  it("exposes the state of the port-scan mode and the host filter", () => {
    seed(interactive());
    renderPage();
    expect(
      screen.getByRole("button", { name: "Intensity Profile" }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.getByRole("button", { name: "Custom Ports" }),
    ).toHaveAttribute("aria-pressed", "false");
    expect(
      screen.getByRole("button", { name: /^Active \(4\)$/ }),
    ).toHaveAttribute("aria-pressed", "true");
  });

  it("names each excluded-port remove control", () => {
    seed(interactive({ cc_excludePorts: "2375, 6443" }));
    renderPage();
    expect(
      screen.getByRole("button", { name: /remove 6443/i }),
    ).toBeInTheDocument();
  });

  it("gives the host table a caption and scoped column headers", () => {
    seed(interactive());
    renderPage();
    const table = document.querySelector("table");
    expect(table.firstElementChild?.tagName).toBe("CAPTION");
    for (const th of table.querySelectorAll("thead th"))
      expect(th).toHaveAttribute("scope", "col");
  });

  it("announces warnings, errors and the running scan", async () => {
    seed(interactive({ cc_portScanMode: "custom", cc_customPorts: "" }));
    const { unmount } = renderPage();
    await userEvent.click(screen.getByRole("button", { name: "IT" }));
    expect(
      screen
        .getAllByRole("alert")
        .some((el) => /Sensitive Ports Detected/.test(el.textContent)),
    ).toBe(true);
    unmount();

    sessionStorage.clear();
    seed(interactive({ cc_portScanMode: "custom", cc_customPorts: "" }));
    const second = renderPage();
    await userEvent.click(runButton());
    expect(
      screen
        .getAllByRole("alert")
        .some((el) => /Custom ports list cannot be empty/.test(el.textContent)),
    ).toBe(true);
    second.unmount();

    vi.useFakeTimers();
    try {
      sessionStorage.clear();
      api.get.mockResolvedValue({ data: RUNNING });
      seed(context({ mode: "asset" }));
      renderPage();
      expect(
        screen
          .getAllByRole("status")
          .some((el) => /Port Scan Running/.test(el.textContent)),
      ).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("announces loading", () => {
    params = { scanId: "scan-88" };
    api.get.mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(
      screen
        .getAllByRole("status")
        .some((el) => /Loading scan results/.test(el.textContent)),
    ).toBe(true);
  });

  it("uses links for navigation that needs no permission", () => {
    seed(context({ mode: "asset", cc_phase2Results: PHASE2_DATA }));
    renderPage();
    expect(screen.getByRole("link", { name: /New Scan$/ })).toHaveAttribute(
      "href",
      "/audit-dashboard",
    );
    expect(
      screen.getByRole("link", { name: /View Port Scan Results/ }),
    ).toHaveAttribute("href", "/scan/asset-discovery");
  });

  it("renders no inline style", () => {
    seed(
      interactive({
        cc_portScanMode: "custom",
        cc_customPorts: "22,2375",
        cc_excludePorts: "2375",
        cc_excludeIps: "bad_host!",
      }),
    );
    renderPage();
    expect(document.querySelectorAll("[style]")).toHaveLength(0);
  });

  it("styles the page from its own token stylesheet, not the global sheets", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/scan/Phase1Results.jsx"),
      "utf8",
    );
    expect(source).toMatch(/import\s+["'][^"']*\/phase1-results\.css["']/);
    expect(source).not.toMatch(
      /\b(page-inner|page-title|results-table|filter-tabs?|summary-bar|summary-item|alert alert--|btn btn--|btn-spinner|ip-code|status-dot|app-progress[\w-]*|asset-pipeline-progress|phase-action-bar|ns-[a-z-]+|muted)\b/,
    );
    expect(source).not.toMatch(/#[0-9a-fA-F]{3,8}\b|rgba?\(/);
  });
});
