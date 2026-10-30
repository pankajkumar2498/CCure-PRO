/**
 * Opening a scan's results by URL shows that scan, as the backend has it.
 *
 * Found 13 Oct 2026 on the live installation: opening `/scan/<id>/phase3` for
 * four completed Vulnerability Audits showed one and the same page — "Scan No.
 * 4 … Full pipeline execution from 10.180.6.45", the scan viewed before — and,
 * through Scan History's "Open full results", a completed audit rendered as
 * "Port Scan · Scanning… / Running Port Scan… Phase 2 of 3" with a Cancel
 * button. Phase 3 read the session instead of the URL, Phase 1 hydrated only
 * its own phase and then wrote a live PORT_SCAN pipeline state over a finished
 * scan, and the Phase 3 page's auto-start was one guard away from posting
 * `/scan/asset-discovery` or `/scan/vulnerability-audit` for a finished scan.
 *
 * Each test seeds the session with a *different* scan, mid-pipeline, and then
 * opens a scan by id: the stale state is exactly what the live page held.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";

import Phase1Results from "@audit/pages/scan/Phase1Results";
import Phase2Results from "@audit/pages/scan/Phase2Results";
import Phase3Results from "@audit/pages/scan/Phase3Results";
import { ScanProvider, PIPELINE_STATES } from "@audit/context/ScanContext";
import {
  isTerminalScanStatus,
  pipelineStateForScan,
  scanViewState,
} from "@audit/utils/scanViewState";
import api from "@shell/api/axiosInstance";
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
vi.mock("@audit/components/scan/ScanStepper", () => ({
  default: () => <div data-testid="scan-stepper" />,
}));
vi.mock("@audit/components/scan/ExportPanel", () => ({
  default: () => <div data-testid="export-panel" />,
}));

const navigate = vi.fn();
let params = {};
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useParams: () => params,
    useSearchParams: () => [new URLSearchParams(""), vi.fn()],
    useLocation: () => ({ pathname: "/", search: "", state: null }),
    Link: ({ to, children, ...rest }) => (
      <a href={typeof to === "string" ? to : "#"} {...rest}>
        {children}
      </a>
    ),
  };
});

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({
    user: personaFrom({
      id: 1,
      username: "operator",
      role: { name: "analyst" },
      permissionKeys: ["audit.scan.read", "audit.scan.run"],
    }),
  }),
}));

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const host = (ip, extra = {}) => ({
  ip_address: ip,
  hostname: `h-${ip.split(".").pop()}`,
  is_active: true,
  ...extra,
});

const VIEWED = "scn_viewed_8";
const viewedScan = (overrides = {}) => ({
  id: VIEWED,
  scan_no: 8,
  target: "10.180.6.30",
  status: "complete",
  phase: 3,
  pipeline_mode: "vulnerability_audit",
  failure_reason: null,
  results: {
    phase1: { data: [host("10.180.6.30")], summary: { active_hosts: 1 } },
    phase2: {
      data: [
        host("10.180.6.30", {
          open_ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
        }),
      ],
      summary: { hosts_with_ports: 1 },
    },
    phase3: {
      data: [
        host("10.180.6.30", {
          open_ports: [{ port: 22, protocol: "tcp", service: "ssh" }],
          cves: [{ cve_id: "CVE-2024-6387", severity: "High", port: 22 }],
        }),
      ],
      summary: { total_hosts: 1 },
    },
  },
  ...overrides,
});

/** The session as the live UI left it: another scan, mid-pipeline. */
const STALE = {
  cc_scanId: "scn_other_4",
  cc_scanNo: 4,
  cc_target: "10.180.6.45",
  cc_pipelineMode: "vulnerability_audit",
  cc_executionMode: "automatic",
  cc_pipelineState: "PORT_SCAN",
  cc_phase1Hosts: [host("10.180.6.45")],
  cc_phase2Results: [],
  cc_phase3Results: [host("10.180.6.45")],
  cc_phase3AuditResults: [],
};

const seed = (entries) => {
  for (const [key, value] of Object.entries(entries)) {
    sessionStorage.setItem(key, JSON.stringify(value));
  }
};
const stored = (key) => JSON.parse(sessionStorage.getItem(key));
const flush = async () => {
  for (let i = 0; i < 15; i += 1) {
    await act(async () => {});
  }
};
const renderWith = (Page) =>
  render(
    <ScanProvider>
      <Page />
    </ScanProvider>,
  );

beforeEach(() => {
  sessionStorage.clear();
  navigate.mockReset();
  api.get.mockReset();
  api.post.mockReset();
  params = { scanId: VIEWED };
  seed(STALE);
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

/* ── utils/scanViewState ─────────────────────────────────────────────────── */
describe("scanViewState", () => {
  it("never derives a running state for a finished scan", () => {
    expect(pipelineStateForScan(viewedScan())).toBe(
      PIPELINE_STATES.REPORT_READY,
    );
    expect(
      pipelineStateForScan(viewedScan({ pipeline_mode: "basic", phase: 1 })),
    ).toBe(PIPELINE_STATES.COMPLETE);
    expect(pipelineStateForScan(viewedScan({ status: "failed" }))).toBe(
      PIPELINE_STATES.ERROR,
    );
    expect(pipelineStateForScan(viewedScan({ status: "cancelled" }))).toBe(
      PIPELINE_STATES.CANCELLED,
    );
  });

  it("follows a running scan's own phase", () => {
    expect(
      pipelineStateForScan(viewedScan({ status: "running", phase: 2 })),
    ).toBe(PIPELINE_STATES.PORT_SCAN);
    expect(
      pipelineStateForScan(viewedScan({ status: "running", phase: 3 })),
    ).toBe(PIPELINE_STATES.VULN_SCAN);
  });

  it("carries every phase and the failure reason", () => {
    const view = scanViewState(
      viewedScan({
        status: "failed",
        failure_reason: "Findings could not be saved",
      }),
    );
    expect(view.scanId).toBe(VIEWED);
    expect(view.phase1Hosts).toHaveLength(1);
    expect(view.phase2Results).toHaveLength(1);
    expect(view.phase3AuditResults).toHaveLength(1);
    expect(view.pipelineError).toEqual({
      phase: "VULN_SCAN",
      message: "Findings could not be saved",
    });
    expect(view.terminal).toBe(true);
    expect(isTerminalScanStatus("running")).toBe(false);
  });
});

/* ── Phase 3 ─────────────────────────────────────────────────────────────── */
describe("Phase3Results opened by id", () => {
  it("shows the scan named in the URL, finished, and starts nothing", async () => {
    api.get.mockResolvedValue({ data: viewedScan() });
    renderWith(Phase3Results);
    expect(screen.getByText(/Loading scan results/)).toBeInTheDocument();
    await flush();

    expect(api.get).toHaveBeenCalledWith(`/scans/${VIEWED}`);
    expect(
      screen.getByText("10.180.6.30", { selector: "code" }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/10\.180\.6\.45/)).toBeNull();
    expect(screen.queryByText(/Running Port Scan/)).toBeNull();
    expect(screen.queryByRole("button", { name: /Cancel Scan/ })).toBeNull();
    expect(stored("cc_pipelineState")).toBe("REPORT_READY");
    expect(stored("cc_scanId")).toBe(VIEWED);
    // The stale audit queue is cleared, and nothing was dispatched.
    expect(stored("cc_phase3Results")).toEqual([]);
    expect(api.post).not.toHaveBeenCalled();
  });

  it("reports a failed scan without offering to re-run it", async () => {
    api.get.mockResolvedValue({
      data: viewedScan({
        status: "failed",
        failure_reason: "Findings were collected but could not be saved",
      }),
    });
    renderWith(Phase3Results);
    await flush();

    expect(
      screen.getByText(/Findings were collected but could not be saved/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Retry from/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Restart/ })).toBeNull();
    expect(api.post).not.toHaveBeenCalled();
  });

  it("follows a running scan until the backend says it has finished", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    api.get
      .mockResolvedValueOnce({
        data: viewedScan({ status: "running", phase: 2 }),
      })
      .mockResolvedValue({ data: viewedScan() });
    renderWith(Phase3Results);
    await flush();
    expect(stored("cc_pipelineState")).toBe("PORT_SCAN");

    await act(async () => {
      vi.advanceTimersByTime(5100);
    });
    await flush();
    expect(api.get).toHaveBeenCalledTimes(2);
    expect(stored("cc_pipelineState")).toBe("REPORT_READY");
    expect(api.post).not.toHaveBeenCalled();
  });

  it("says why it cannot show a scan instead of rendering nothing", async () => {
    api.get.mockRejectedValue({
      response: { data: { detail: "Scan not found" } },
    });
    renderWith(Phase3Results);
    await flush();
    expect(screen.getByText("Scan not found")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Back to Scan History/ }),
    ).toBeInTheDocument();
  });
});

describe("Phase3Results on the live route", () => {
  it("does not restart an ended pipeline just because it was mounted", async () => {
    params = {};
    seed({
      cc_pipelineState: "ERROR",
      cc_pipelineError: { phase: "VULN_SCAN", message: "x" },
    });
    renderWith(Phase3Results);
    await flush();
    expect(api.post).not.toHaveBeenCalled();
  });
});

/* ── Phase 1 ─────────────────────────────────────────────────────────────── */
describe("Phase1Results opened by id", () => {
  it("never writes a live pipeline state over a finished scan", async () => {
    api.get.mockResolvedValue({ data: viewedScan() });
    renderWith(Phase1Results);
    await flush();

    expect(screen.queryByText(/Port Scan Running/)).toBeNull();
    expect(screen.getByText("Port Scan Complete")).toBeInTheDocument();
    expect(stored("cc_pipelineState")).toBe("REPORT_READY");
    expect(
      screen.getByRole("link", { name: /View Port Scan Results/ }),
    ).toHaveAttribute("href", `/scan/${VIEWED}/phase2`);
    expect(api.post).not.toHaveBeenCalled();
  });

  it("says a finished scan has no port scan rather than that one is running", async () => {
    const scan = viewedScan({ status: "failed", phase: 1 });
    scan.results = { phase1: scan.results.phase1 };
    api.get.mockResolvedValue({ data: scan });
    renderWith(Phase1Results);
    await flush();

    expect(screen.queryByText(/Port Scan Running/)).toBeNull();
    expect(screen.getByText("No port scan results")).toBeInTheDocument();
  });

  it("reloads the scan even when the session already holds its id", async () => {
    seed({ cc_scanId: VIEWED, cc_pipelineState: "PORT_SCAN" });
    api.get.mockResolvedValue({ data: viewedScan() });
    renderWith(Phase1Results);
    await flush();
    expect(api.get).toHaveBeenCalledWith(`/scans/${VIEWED}`);
    expect(stored("cc_pipelineState")).toBe("REPORT_READY");
  });
});

/* ── Phase 2 ─────────────────────────────────────────────────────────────── */
describe("Phase2Results opened by id", () => {
  it("does not hand a viewed scan to the live Phase 3 page", async () => {
    api.get.mockResolvedValue({ data: viewedScan() });
    renderWith(Phase2Results);
    await flush();

    expect(navigate).not.toHaveBeenCalledWith("/scan/vulnerability-audit");
    expect(stored("cc_phase3Results")).toEqual([]);
    expect(api.post).not.toHaveBeenCalled();
  });
});
