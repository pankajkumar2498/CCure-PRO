/**
 * Phase2Results (`/scan/asset-discovery`, `/scan/:scanId/phase2`) —
 * Checkpoint 3C batch 18 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 18 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The page reads and never writes. It shows the port scan held in the scan
 * context, or loads the scan named in the URL (GET /scans/{id}) and records it
 * there. While the port scan is still running it polls GET /scans/{id} every
 * 4 seconds until results arrive, or the scan completes or fails.
 *
 * It decides which hosts the vulnerability audit will scan, which is why the
 * selection rules are pinned here in detail:
 *
 *   automatic mode — every active host with a detected TCP or UDP service is
 *                    queued, and the page moves straight on to the audit as
 *                    soon as results exist, if the pipeline has a phase 3
 *   interactive    — the same hosts are selected by default; the operator may
 *                    change the selection and the audit profile, and "Run
 *                    Vulnerability Audit" hands both to phase 3
 *
 * `scans:execute` gates choosing and starting. It does not gate the automatic
 * hand-off; phase 3 checks the permission itself before it dispatches.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useState } from "react";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readFileSync } from "node:fs";
import path from "node:path";

import Phase2Results from "@audit/pages/scan/Phase2Results";
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
  role: { name: "analyst" },
  permissionKeys: ["audit.scan.read", "audit.scan.run"],
};
const VIEWER = {
  id: 2,
  username: "viewer",
  role: { name: "viewer" },
  permissionKeys: ["audit.scan.read"],
};

/* Field names are the page's own reads, checked against the port scan the
   orchestrator stores (`_format_host`, summary in `run_port_scan`). */
const PHASE1_HOSTS = [
  {
    ip_address: "10.20.0.11",
    hostname: "files-01",
    mac_address: "00:1A:2B:3C:4D:11",
    vendor: "Dell Inc.",
    discovery_method: "ARP",
    is_active: true,
  },
  {
    ip_address: "10.20.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    mac_address: "00:1A:2B:3C:4D:12",
    vendor: "HP",
    discovery_method: "ICMP",
    is_active: true,
  },
  {
    ip_address: "10.20.0.13",
    hostname: "Unknown",
    netbios_names: [{ name: "KIOSK-07" }],
    discovery_method: "TCP",
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
    discovery_method: "ARP",
    is_active: true,
  },
];

const PHASE2_HOSTS = [
  {
    ip_address: "10.20.0.11",
    hostname: "files-01",
    is_active: true,
    os_fingerprint_full: {
      os: "Windows Server 2022",
      confidence: "High",
      match_score: 42,
    },
    netbios_names: [{ name: "FILES-01" }],
    netbios_workgroup: "CORP",
    device_category: "server",
    firewall_likely: true,
    firewall_confidence: "Medium",
    open_ports: [
      { port: 22, service: "ssh", version: "OpenSSH 9.6", risk: "Low" },
      {
        port: 445,
        service: "microsoft-ds",
        risk: "High",
        cves: ["CVE-2026-2001", "CVE-2026-2002"],
      },
      {
        port: 3389,
        service: "ms-wbt-server",
        banner: "Remote Desktop",
        risk: "Critical",
        cves: ["CVE-2026-3001"],
      },
    ],
  },
  {
    ip_address: "10.20.0.12",
    hostname: "Unknown",
    mdns_name: "printer-2f.local",
    mdns_services: ["_ipp._tcp.local"],
    is_active: true,
    os_guess: "Embedded",
    os_confidence: "Medium",
    snmp_device_type: "Printer",
    open_ports: [{ port: 9100, service: "jetdirect", risk: "Medium" }],
    udp_services: [
      {
        port: 161,
        service: "snmp",
        state: "open",
        risk: "High",
        banner: "public community",
      },
    ],
    snmp_info: {
      sys_name: "PRN-2F",
      sys_location: "Floor 2",
      vendor: "HP",
      interfaces: [
        {
          index: 1,
          description: "eth0",
          type: "ethernetCsmacd",
          mac: "00:1A:2B:3C:4D:12",
          admin_up: true,
          oper_up: true,
        },
      ],
      ip_addresses: [{ address: "10.20.0.12", netmask: "255.255.255.0" }],
    },
  },
  // Detected only over UDP: still a host with detected services.
  {
    ip_address: "10.20.0.13",
    hostname: "KIOSK-07",
    is_active: true,
    udp_services: [
      { port: 137, service: "netbios-ns", state: "open|filtered", risk: "Low" },
    ],
  },
  // Active, nothing detected: never queued by default.
  { ip_address: "10.20.0.15", hostname: "Unknown", is_active: true },
  { ip_address: "10.20.0.14", hostname: "Unknown", is_active: false },
];

const SUMMARY = {
  total_hosts: 5,
  active_hosts: 4,
  inactive_hosts: 1,
  hosts_with_ports: 2,
  scan_duration: 84.37,
  phase: 2,
  custom_ports: "22,80,161,443,445,3389,9100,8000-8100",
};

const WITH_SERVICES = ["10.20.0.11", "10.20.0.12", "10.20.0.13"];
const ACTIVE = ["10.20.0.11", "10.20.0.12", "10.20.0.13", "10.20.0.15"];

const scanPayload = (overrides = {}) => ({
  id: "scan-77",
  scan_no: 1042,
  target: "10.20.0.0/28",
  status: "complete",
  pipeline_mode: "asset",
  results: {
    phase1: { data: PHASE1_HOSTS },
    phase2: { data: PHASE2_HOSTS, summary: SUMMARY },
  },
  ...overrides,
});

const RUNNING = {
  id: "scan-77",
  status: "running",
  results: { phase1: { data: PHASE1_HOSTS }, phase2: {} },
};

/* The real ScanProvider, seeded the way the pipeline leaves sessionStorage. */
const seed = (entries) => {
  for (const [key, value] of Object.entries(entries))
    sessionStorage.setItem(key, JSON.stringify(value));
};
const stored = (key) => JSON.parse(sessionStorage.getItem(key));

const context = ({
  mode = "asset",
  execution = "automatic",
  phase2 = PHASE2_HOSTS,
  summary = SUMMARY,
} = {}) => ({
  cc_scanId: "scan-77",
  cc_scanNo: 1042,
  cc_target: "10.20.0.0/28",
  cc_pipelineMode: mode,
  cc_executionMode: execution,
  cc_phase1Hosts: PHASE1_HOSTS,
  ...(phase2 ? { cc_phase2Results: phase2 } : {}),
  ...(summary ? { cc_phase2Summary: summary } : {}),
});

/* Navigating unmounts the page, as the router does. Left mounted, a page that
   hands off from an effect would hand off again on every render of the scan
   context — its setters are new functions each render — which the
   application never does, because the route has already changed. */
let leavePage = () => {};
function RoutedPage() {
  const [left, setLeft] = useState(false);
  leavePage = () => setLeft(true);
  return left ? <div data-testid="navigated-away" /> : <Phase2Results />;
}

const renderPage = () =>
  render(
    <ScanProvider>
      <RoutedPage />
    </ScanProvider>,
  );

const writes = () =>
  [api.post, api.put, api.patch, api.delete].flatMap((fn) => fn.mock.calls);

const scanGets = (id = "scan-77") =>
  api.get.mock.calls.filter(([url]) => url === `/scans/${id}`).length;

const esc = (s) => s.replace(/\./g, "\\.");
const ipName = (ip) => new RegExp(`${esc(ip)}(?!\\d)`);

/* A checkbox belongs to the row or host card that shows its address. */
const checkboxFor = (ip, where) =>
  screen.getAllByRole("checkbox").find((cb) => {
    const inTable = Boolean(cb.closest("table"));
    if ((where === "table") !== inTable) return false;
    const scope =
      where === "table"
        ? cb.closest("tr")
        : cb.closest("article, section, li, .host-card");
    return Boolean(scope) && ipName(ip).test(scope.textContent);
  });
const selectAll = () =>
  screen.getAllByRole("checkbox").find((cb) => cb.closest("thead"));

const queueOf = () =>
  (stored("cc_phase3Results") || []).map((h) => h.ip_address);

const runAudit = () =>
  screen.getByRole("button", { name: /Run Vulnerability Audit/ });

/* The card heading for a host, whether the header or its toggle is clicked. */
const cardAddress = (ip) =>
  screen.getAllByText(ip).find((el) => !el.closest("table"));

const control = (name) =>
  screen.queryByRole("link", { name }) || screen.getByRole("button", { name });

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
  navigate.mockImplementation(() => leavePage());
  api.get.mockResolvedValue({ data: scanPayload() });
});

afterEach(() => {
  // The page never writes, in any state, under any mode.
  expect(writes()).toEqual([]);
});

/* ════════════════════════════════════════════════════════════════════════════
   Contract — passes on the legacy page and must keep passing
   ════════════════════════════════════════════════════════════════════════════ */
describe("Phase2Results — contract", () => {
  describe("loading", () => {
    it("shows the port scan held in the scan context without a request", async () => {
      seed(context());
      renderPage();
      expect(await screen.findAllByText("10.20.0.11")).not.toHaveLength(0);
      expect(api.get).not.toHaveBeenCalled();
      expect(navigate).not.toHaveBeenCalled();
    });

    it("loads the scan named in the URL and records it in the scan context", async () => {
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
      expect(await screen.findAllByText("10.20.0.11")).not.toHaveLength(0);
      await act(async () => {
        await new Promise((r) => setTimeout(r, 30));
      });

      // Twice, and pinned as found. The load effect lists the scan context's
      // setters, which are new functions on every provider render; the page's
      // own pipeline-state update re-renders the provider before the first
      // response arrives, so the effect is cancelled and re-run. The first
      // response is discarded. Measured in the browser too (batch 18 §7).
      expect(api.get.mock.calls).toEqual([
        ["/scans/scan-88"],
        ["/scans/scan-88"],
      ]);
      expect(stored("cc_scanId")).toBe("scan-88");
      expect(stored("cc_scanNo")).toBe(1088);
      expect(stored("cc_target")).toBe("10.9.0.0/24");
      expect(stored("cc_pipelineMode")).toBe("asset");
      expect(stored("cc_phase1Hosts")).toEqual(PHASE1_HOSTS);
      expect(stored("cc_phase2Results")).toEqual(PHASE2_HOSTS);
      expect(stored("cc_phase2Summary")).toEqual(SUMMARY);
      expect(navigate).not.toHaveBeenCalled();
    });

    it("also loads the scan named by ?scan_id=", async () => {
      search = "?scan_id=scan-89";
      renderPage();
      expect(await screen.findAllByText("10.20.0.11")).not.toHaveLength(0);
      expect(api.get).toHaveBeenCalledWith("/scans/scan-89");
    });

    it("falls back to phase 1 hosts, then to the port-scan hosts themselves", async () => {
      params = { scanId: "scan-90" };
      api.get.mockResolvedValue({
        data: scanPayload({
          id: "scan-90",
          results: {
            phase1: { hosts: PHASE1_HOSTS.slice(0, 2) },
            phase2: { data: PHASE2_HOSTS, summary: SUMMARY },
          },
        }),
      });
      const { unmount } = renderPage();
      expect(await screen.findAllByText("10.20.0.11")).not.toHaveLength(0);
      expect(stored("cc_phase1Hosts")).toEqual(PHASE1_HOSTS.slice(0, 2));
      unmount();

      sessionStorage.clear();
      params = { scanId: "scan-91" };
      api.get.mockResolvedValue({
        data: scanPayload({
          id: "scan-91",
          results: { phase2: { data: PHASE2_HOSTS, summary: SUMMARY } },
        }),
      });
      renderPage();
      expect(await screen.findAllByText("10.20.0.11")).not.toHaveLength(0);
      expect(stored("cc_phase1Hosts")).toEqual(PHASE2_HOSTS);
    });

    it("explains a scan with no port-scan results instead of redirecting", async () => {
      params = { scanId: "scan-92" };
      api.get.mockResolvedValue({
        data: {
          id: "scan-92",
          status: "failed",
          failure_reason:
            "Port scan did not complete: the scanner worker was stopped.",
          results: { phase1: { data: PHASE1_HOSTS }, phase2: {} },
        },
      });
      renderPage();
      expect(
        await screen.findByText(/the scanner worker was stopped/),
      ).toBeInTheDocument();
      await expectLeadsTo(control(/Back to Scan History/), "/history");
      expect(navigate).not.toHaveBeenCalledWith(
        "/scan/host-discovery",
        expect.anything(),
      );
    });

    it("uses a default explanation when the scan gives none", async () => {
      params = { scanId: "scan-93" };
      api.get.mockResolvedValue({
        data: { id: "scan-93", results: { phase2: { data: [] } } },
      });
      renderPage();
      expect(
        await screen.findByText(
          /This scan has no port-scan results to display\./,
        ),
      ).toBeInTheDocument();
    });

    it("shows the API's reason when the scan cannot be loaded", async () => {
      params = { scanId: "scan-94" };
      api.get.mockRejectedValue({
        response: { data: { detail: "Scan not found" } },
      });
      renderPage();
      expect(await screen.findByText(/Scan not found/)).toBeInTheDocument();
      expect(navigate).not.toHaveBeenCalled();
    });

    it("uses a default reason when the API gives none", async () => {
      params = { scanId: "scan-95" };
      api.get.mockRejectedValue(new Error("network"));
      renderPage();
      expect(
        await screen.findByText(/Could not load this scan's results\./),
      ).toBeInTheDocument();
    });

    it("returns to host discovery when there are no discovered hosts", async () => {
      renderPage();
      expect(navigate).toHaveBeenCalledWith("/scan/host-discovery", {
        replace: true,
      });
      expect(api.get).not.toHaveBeenCalled();
    });
  });

  describe("automatic mode", () => {
    it.each(["vulnerability_audit", "advanced"])(
      "with a phase 3 (%s), queues every active host with a detected service and moves on",
      async (mode) => {
        seed(context({ mode }));
        renderPage();
        expect(navigate).toHaveBeenCalledTimes(1);
        expect(navigate.mock.calls[0]).toEqual(["/scan/vulnerability-audit"]);
        expect(queueOf()).toEqual(WITH_SERVICES);
      },
    );

    it("hands off even without scans:execute — phase 3 checks the permission", async () => {
      user = VIEWER;
      seed(context({ mode: "vulnerability_audit" }));
      renderPage();
      expect(navigate).toHaveBeenCalledWith("/scan/vulnerability-audit");
      expect(queueOf()).toEqual(WITH_SERVICES);
    });

    it("without a phase 3, stays and completes the pipeline", async () => {
      seed(context({ mode: "asset" }));
      renderPage();
      await screen.findAllByText("10.20.0.11");
      expect(navigate).not.toHaveBeenCalled();
      expect(
        screen.queryByRole("button", { name: /Run Vulnerability Audit/ }),
      ).toBeNull();
      // Nothing is queued: the audit queue is never written.
      expect(stored("cc_phase3Results")).toBeNull();
      expect(stored("cc_pipelineState")).toBe("COMPLETE");
    });
  });

  describe("interactive mode", () => {
    beforeEach(() => {
      seed(context({ mode: "vulnerability_audit", execution: "interactive" }));
    });

    it("selects active hosts with detected services by default and hands them over", async () => {
      renderPage();
      expect(
        screen.getByText("3 hosts queued for vulnerability audit."),
      ).toBeInTheDocument();
      expect(navigate).not.toHaveBeenCalled();

      await userEvent.click(runAudit());
      expect(navigate).toHaveBeenCalledTimes(1);
      expect(navigate).toHaveBeenCalledWith("/scan/vulnerability-audit", {
        state: { vulnerabilityProfile: "recommended", startPhase: "VULN_SCAN" },
      });
      expect(queueOf()).toEqual(WITH_SERVICES);
      expect(stored("cc_pipelineState")).toBe("IDLE");
    });

    it("audits exactly the hosts the operator leaves selected, from the table or the cards", async () => {
      renderPage();
      await userEvent.click(checkboxFor("10.20.0.12", "table"));
      expect(
        screen.getByText("2 hosts queued for vulnerability audit."),
      ).toBeInTheDocument();
      expect(checkboxFor("10.20.0.12", "card")).not.toBeChecked();

      await userEvent.click(checkboxFor("10.20.0.13", "card"));
      expect(
        screen.getByText("1 host queued for vulnerability audit."),
      ).toBeInTheDocument();

      await userEvent.click(runAudit());
      expect(queueOf()).toEqual(["10.20.0.11"]);
    });

    it("select-all queues every active host, services or not; clearing it queues none", async () => {
      renderPage();
      // Default selection is not "every active host", so the box starts clear.
      expect(selectAll()).not.toBeChecked();
      await userEvent.click(selectAll());
      expect(
        screen.getByText("4 hosts queued for vulnerability audit."),
      ).toBeInTheDocument();

      await userEvent.click(selectAll());
      expect(
        screen.getByText(
          "No active hosts with open ports found to run vulnerability audit.",
        ),
      ).toBeInTheDocument();
      expect(runAudit()).toBeDisabled();

      await userEvent.click(selectAll());
      await userEvent.click(runAudit());
      expect(queueOf()).toEqual(ACTIVE);
    });

    it("an inactive host cannot be selected", async () => {
      renderPage();
      // Inactive hosts are listed only under "All".
      await userEvent.click(
        screen.getByRole("button", { name: /^All \(5\)$/ }),
      );
      expect(checkboxFor("10.20.0.14", "table")).toBeDisabled();
      expect(checkboxFor("10.20.0.11", "table")).toBeEnabled();
    });

    // F4: the backend never read the profile and now refuses anything but
    // `recommended`, so the unimplemented ones cannot be chosen — and they say
    // why, rather than silently running Recommended under a different name.
    it.each([["Deep"], ["Conservative"]])(
      "does not let the unimplemented %s profile be chosen",
      async (label) => {
        renderPage();
        const button = screen.getByRole("button", { name: label });
        expect(button).toBeDisabled();
        expect(button).toHaveAccessibleDescription(/not yet available/i);
        await userEvent.click(button);
        await userEvent.click(runAudit());
        expect(navigate).toHaveBeenCalledWith("/scan/vulnerability-audit", {
          state: {
            vulnerabilityProfile: "recommended",
            startPhase: "VULN_SCAN",
          },
        });
      },
    );

    it("without scans:execute nothing can be chosen or started", async () => {
      user = VIEWER;
      renderPage();
      for (const cb of screen.getAllByRole("checkbox"))
        expect(cb).toBeDisabled();
      for (const label of ["Recommended", "Conservative", "Deep"])
        expect(screen.getByRole("button", { name: label })).toBeDisabled();
      expect(runAudit()).toBeDisabled();
      await userEvent.click(runAudit());
      expect(navigate).not.toHaveBeenCalled();
      expect(
        screen.getByText("3 hosts queued for vulnerability audit."),
      ).toBeInTheDocument();
    });
  });

  describe("polling a running port scan", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      api.get.mockResolvedValue({ data: RUNNING });
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    const running = (mode = "asset") =>
      seed(context({ mode, phase2: null, summary: null }));

    it("checks at once, then every 4 seconds, and stops when results arrive", async () => {
      running();
      renderPage();
      await flush();
      expect(scanGets()).toBe(1);
      expect(screen.getByText(/Port Scan Running/)).toBeInTheDocument();
      expect(screen.getByTestId("scan-stepper")).toHaveAttribute(
        "data-current",
        "2",
      );
      expect(stored("cc_pipelineState")).toBe("PORT_SCAN");

      await flush(3999);
      expect(scanGets()).toBe(1);
      await flush(1);
      expect(scanGets()).toBe(2);
      await flush(4000);
      expect(scanGets()).toBe(3);

      api.get.mockResolvedValue({ data: scanPayload() });
      await flush(4000);
      expect(scanGets()).toBe(4);
      expect(screen.queryByText(/Port Scan Running/)).toBeNull();
      expect(screen.getAllByText("10.20.0.11")).not.toHaveLength(0);
      expect(stored("cc_phase2Results")).toEqual(PHASE2_HOSTS);
      expect(stored("cc_phase2Summary")).toEqual(SUMMARY);
      expect(screen.getByTestId("scan-stepper")).toHaveAttribute(
        "data-current",
        "3",
      );

      await flush(20000);
      expect(scanGets()).toBe(4);
    });

    it("stops without an error when the scan completes with no results", async () => {
      running();
      api.get.mockResolvedValue({
        data: { ...RUNNING, status: "complete" },
      });
      renderPage();
      await flush();
      expect(scanGets()).toBe(1);
      await flush(4000);
      expect(scanGets()).toBe(2);
      expect(screen.queryByText(/Port Scan Running/)).toBeNull();
      expect(screen.queryByText(/Port scan failed on the backend/)).toBeNull();
      await flush(20000);
      expect(scanGets()).toBe(2);
    });

    it("stops with an error when the scan fails", async () => {
      running();
      api.get.mockResolvedValue({ data: { ...RUNNING, status: "failed" } });
      renderPage();
      await flush();
      await flush(4000);
      expect(scanGets()).toBe(2);
      expect(
        screen.getByText(/Port scan failed on the backend\./),
      ).toBeInTheDocument();
      expect(stored("cc_pipelineState")).toBe("ERROR");
      await flush(20000);
      expect(scanGets()).toBe(2);
    });

    it("keeps polling through a failed request", async () => {
      running();
      api.get.mockRejectedValueOnce(new Error("network"));
      renderPage();
      await flush();
      expect(scanGets()).toBe(1);
      await flush(4000);
      expect(scanGets()).toBe(2);
      await flush(4000);
      expect(scanGets()).toBe(3);
    });

    it("stops when the page is left", async () => {
      running();
      const { unmount } = renderPage();
      await flush();
      expect(scanGets()).toBe(1);
      unmount();
      await flush(12000);
      expect(scanGets()).toBe(1);
    });

    it("in automatic mode with a phase 3, moves on only once results arrive", async () => {
      running("vulnerability_audit");
      renderPage();
      await flush();
      await flush(4000);
      expect(navigate).not.toHaveBeenCalled();

      api.get.mockResolvedValue({ data: scanPayload() });
      await flush(4000);
      expect(navigate).toHaveBeenCalledWith("/scan/vulnerability-audit");
      expect(queueOf()).toEqual(WITH_SERVICES);
    });
  });

  describe("presentation", () => {
    it("hands the export panel the scan it shows", async () => {
      seed(context());
      renderPage();
      expect(screen.getByTestId("export-panel")).toBeInTheDocument();
      expect(exportProps).toEqual({
        results: PHASE2_HOSTS,
        summary: SUMMARY,
        scanId: "scan-77",
        scanNo: 1042,
        target: "10.20.0.0/28",
        pipelineMode: "asset",
      });
    });

    it.each(["vulnerability_audit", "advanced"])(
      "has no export panel for a %s pipeline",
      async (mode) => {
        seed({ ...context({ mode }), cc_executionMode: "interactive" });
        renderPage();
        expect(screen.queryByTestId("export-panel")).toBeNull();
      },
    );

    it("has no export panel without a summary", async () => {
      seed(context({ summary: null }));
      renderPage();
      expect(screen.queryByTestId("export-panel")).toBeNull();
    });

    it("summarises the scan", async () => {
      seed(context());
      renderPage();
      expect(screen.getByText("84.4s")).toBeInTheDocument();
      expect(screen.getByText("22,80,161,443,445,3389...")).toBeInTheDocument();
      expect(screen.getByText(/Scan No\. 1042/)).toBeInTheDocument();
      expect(screen.getAllByText("10.20.0.0/28")).not.toHaveLength(0);
    });

    it("warns when the target did not respond", async () => {
      seed(
        context({
          summary: { ...SUMMARY, status: "unreachable" },
        }),
      );
      renderPage();
      expect(
        screen.getByText("Host is unavailable/down/unreachable"),
      ).toBeInTheDocument();
    });

    it("warns when no discovered host is active", async () => {
      seed(
        context({
          summary: { ...SUMMARY, active_hosts: 0 },
        }),
      );
      renderPage();
      expect(
        screen.getByText("Host is unavailable/down/unreachable"),
      ).toBeInTheDocument();
    });

    it("does not warn about a responsive target", async () => {
      seed(context());
      renderPage();
      expect(
        screen.queryByText("Host is unavailable/down/unreachable"),
      ).toBeNull();
    });

    it("says so when no active host returned open ports", async () => {
      seed(
        context({
          phase2: [{ ip_address: "10.20.0.14", is_active: false }],
        }),
      );
      renderPage();
      expect(
        screen.getByText("No active hosts returned open ports"),
      ).toBeInTheDocument();
    });

    it("filters the discovered hosts between active and all", async () => {
      seed(context());
      renderPage();
      expect(screen.queryByText("10.20.0.14")).toBeNull();
      await userEvent.click(
        screen.getByRole("button", { name: /^All \(5\)$/ }),
      );
      expect(screen.getByText("10.20.0.14")).toBeInTheDocument();
      await userEvent.click(
        screen.getByRole("button", { name: /^Active \(4\)$/ }),
      );
      expect(screen.queryByText("10.20.0.14")).toBeNull();
    });

    it("opens and closes a host's details", async () => {
      seed(context());
      renderPage();
      expect(screen.queryByText(/Target OS Fingerprint/i)).toBeNull();
      await userEvent.click(cardAddress("10.20.0.11"));
      expect(screen.getByText(/Target OS Fingerprint/i)).toBeInTheDocument();
      expect(screen.getByText("Windows Server 2022")).toBeInTheDocument();
      expect(screen.getByText("ms-wbt-server")).toBeInTheDocument();
      await userEvent.click(cardAddress("10.20.0.11"));
      expect(screen.queryByText(/Target OS Fingerprint/i)).toBeNull();
    });

    it("shows UDP services and SNMP interfaces in a host's details", async () => {
      seed(context());
      renderPage();
      await userEvent.click(cardAddress("10.20.0.12"));
      expect(screen.getByText(/UDP Services \(1\)/i)).toBeInTheDocument();
      expect(screen.getByText(/SNMP Interfaces \(1\)/i)).toBeInTheDocument();
      expect(screen.getByText("public community")).toBeInTheDocument();
      expect(screen.getByText("PRN-2F")).toBeInTheDocument();
    });

    it("leads back to host discovery", async () => {
      seed(context());
      renderPage();
      await expectLeadsTo(control(/Back$/), "/scan/host-discovery");
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 18 — fails on the legacy page, each for the reason in its name
   ════════════════════════════════════════════════════════════════════════════ */
describe("Phase2Results — batch 18", () => {
  it("has one level-one heading", () => {
    seed(context());
    renderPage();
    expect(
      screen.getByRole("heading", { level: 1, name: "Port Scan Results" }),
    ).toBeInTheDocument();
  });

  it("opens host details with a named disclosure button inside a heading", async () => {
    seed(context());
    renderPage();
    const toggle = screen.getByRole("button", { name: ipName("10.20.0.11") });
    expect(toggle.closest("h2")).not.toBeNull();
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const body = document.getElementById(toggle.getAttribute("aria-controls"));
    expect(body).toHaveTextContent(/Target OS Fingerprint/i);

    toggle.focus();
    await userEvent.keyboard("{Enter}");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
  });

  it("names every selection checkbox for its host", async () => {
    seed(context({ mode: "vulnerability_audit", execution: "interactive" }));
    renderPage();
    expect(
      screen.getByRole("checkbox", { name: /select all active hosts/i }),
    ).toBeInTheDocument();
    for (const ip of ACTIVE)
      expect(
        screen.getAllByRole("checkbox", { name: ipName(ip) }),
      ).toHaveLength(2);
    // Inactive hosts are listed only under "All", and have no card.
    await userEvent.click(screen.getByRole("button", { name: /^All \(5\)$/ }));
    expect(
      screen.getByRole("checkbox", { name: ipName("10.20.0.14") }),
    ).toBeDisabled();
  });

  it("gives every table a caption and scoped column headers", async () => {
    seed(context());
    renderPage();
    await userEvent.click(cardAddress("10.20.0.11"));
    await userEvent.click(cardAddress("10.20.0.12"));
    const tables = [...document.querySelectorAll("table")];
    expect(tables).toHaveLength(5);
    for (const table of tables) {
      expect(table.firstElementChild?.tagName).toBe("CAPTION");
      expect(table.querySelector("caption").textContent.trim()).not.toBe("");
      for (const th of table.querySelectorAll("thead th"))
        expect(th).toHaveAttribute("scope", "col");
    }
  });

  it("exposes the state of the host filter and the audit profile", () => {
    seed(context({ mode: "vulnerability_audit", execution: "interactive" }));
    renderPage();
    expect(
      screen.getByRole("button", { name: /^Active \(4\)$/ }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /^All \(5\)$/ })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    expect(screen.getByRole("button", { name: "Recommended" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getByRole("button", { name: "Deep" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
  });

  it("renders no inline style", async () => {
    seed(context({ summary: { ...SUMMARY, status: "unreachable" } }));
    renderPage();
    await userEvent.click(cardAddress("10.20.0.11"));
    await userEvent.click(cardAddress("10.20.0.12"));
    expect(document.querySelectorAll("[style]")).toHaveLength(0);
  });

  it("announces a running port scan", async () => {
    vi.useFakeTimers();
    try {
      api.get.mockResolvedValue({ data: RUNNING });
      seed(context({ phase2: null, summary: null }));
      renderPage();
      await flush();
      expect(
        screen
          .getAllByRole("status")
          .some((el) => /Port Scan Running/.test(el.textContent)),
      ).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("announces loading and reports a failed load as an alert", async () => {
    params = { scanId: "scan-94" };
    api.get.mockRejectedValue({
      response: { data: { detail: "Scan not found" } },
    });
    renderPage();
    expect(
      screen
        .getAllByRole("status")
        .some((el) => /Loading scan results/.test(el.textContent)),
    ).toBe(true);
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText(/Scan not found/)).toBeInTheDocument();
  });

  it("leads back to host discovery with a link", () => {
    seed(context());
    renderPage();
    expect(screen.getByRole("link", { name: /Back$/ })).toHaveAttribute(
      "href",
      "/scan/host-discovery",
    );
  });

  it("styles the page from its own token stylesheet, not scan.css", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/scan/Phase2Results.jsx"),
      "utf8",
    );
    expect(source).toMatch(/import\s+["'][^"']*\/phase2-results\.css["']/);
    expect(source).not.toMatch(
      /\b(host-card|results-table|ports-table|filter-tab|summary-bar|summary-item|pipeline-progress|empty-state|ip-code|btn btn--|alert alert--)\b/,
    );
    expect(source).not.toMatch(/#[0-9a-fA-F]{3,8}\b|rgba?\(/);
  });
});
