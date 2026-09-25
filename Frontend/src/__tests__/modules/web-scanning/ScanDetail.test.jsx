/**
 * ScanDetail — Checkpoint 3C batch 8 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Why this page is alone ─────────────────────────────────────────────────
 * It is the only live surface in the web-scanning module. `useScanPolling`
 * opens a WebSocket, falls back to timed polling when that fails, and stops
 * both at a terminal state — and the page renders continuously while all of
 * that happens. A presentation migration here can break things no static page
 * can break: a timer that multiplies, a socket that reconnects twice, a
 * skeleton that flashes back over settled results every five seconds.
 *
 * ── What the polling contract actually is ──────────────────────────────────
 * NOT a plain 5-second interval, which is the easy thing to assume and get
 * wrong. Measured from the hook:
 *
 *   * one `getScan` on mount, immediately;
 *   * a WebSocket is the primary channel — while it is healthy there is **no
 *     polling at all**;
 *   * `startPollingFallback` runs only after the socket errors, closes, or the
 *     ticket request fails;
 *   * the fallback re-arms only while status is running / pending / queued;
 *   * a terminal status over the socket triggers one final `getScan` and
 *     closes the socket;
 *   * unmount clears both timers and closes the socket.
 *
 * Every one of those is asserted below over simulated time, by request count.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, act, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ScanDetail from "../../../modules/web-scanning/pages/ScanDetail";
import { webScansApi } from "../../../modules/web-scanning/api/webScansApi";

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useParams: () => ({ id: "ws-42" }),
    Link: ({ to, children, ...rest }) => (
      <a href={to} {...rest}>
        {children}
      </a>
    ),
  };
});

vi.mock("../../../modules/web-scanning/api/webScansApi", () => ({
  webScansApi: {
    getScan: vi.fn(),
    getProgressTicket: vi.fn(),
    getProgressSocketUrl: vi.fn(),
    cancelScan: vi.fn(),
    downloadReport: vi.fn(),
  },
  webDashboardApi: {},
}));

/* ── Permissions (Phase 1, finding F2) ───────────────────────────────────────
   The API now requires scans:execute to launch or cancel a web scan,
   findings:update to triage and findings:accept_risk to accept a risk, and the
   page no longer offers what the API would refuse. Every test runs as a user
   holding all of them unless it swaps `authState.user` — the deny-path tests
   at the end of this file do, and restore it afterwards. */
const FULL_PERMISSION_USER = {
  role: {
    name: "analyst",
    permissions: [
      "scans:read",
      "scans:execute",
      "findings:read",
      "findings:update",
      "findings:accept_risk",
    ],
  },
};
const VIEWER_USER = {
  role: { name: "viewer", permissions: ["scans:read", "findings:read"] },
};
const authState = vi.hoisted(() => ({ user: null }));
vi.mock("../../../context/AuthContext", () => ({
  useAuth: () => ({ user: authState.user }),
}));
authState.user = FULL_PERMISSION_USER;

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

/* ── A controllable WebSocket ───────────────────────────────────────────────
   Every instance is recorded, so "was a second socket opened?" is answerable
   rather than assumed. */
let sockets = [];
class FakeSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.closed = false;
    sockets.push(this);
  }
  close() {
    this.closed = true;
    this.readyState = 3;
    this.onclose?.({});
  }
  /* Helpers used by the tests, not part of the WebSocket API. */
  open() {
    this.readyState = 1;
    this.onopen?.({});
  }
  emit(payload) {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }
  fail() {
    this.onerror?.({});
  }
}

const SCAN = (over = {}) => ({
  id: "ws-42",
  scan_name: "Corporate portal",
  target_url: "https://portal.example.test",
  status: "running",
  pipeline_phase: "CRAWL",
  total_endpoints: 128,
  total_findings: 9,
  critical_count: 2,
  high_count: 3,
  ...over,
});

const settle = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

beforeEach(() => {
  vi.clearAllMocks();
  sockets = [];
  vi.stubGlobal("WebSocket", FakeSocket);
  webScansApi.getScan.mockResolvedValue({ data: SCAN() });
  webScansApi.getProgressTicket.mockResolvedValue({
    data: { ticket: "tkt-1" },
  });
  webScansApi.getProgressSocketUrl.mockImplementation(
    (id, ticket) => `ws://host/api/web-scans/${id}/progress?ticket=${ticket}`,
  );
  webScansApi.cancelScan.mockResolvedValue({});
  webScansApi.downloadReport.mockResolvedValue({ data: new ArrayBuffer(8) });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

/* ══════════════════════════════════════════════════════════════════════════
   NETWORK AND LIFECYCLE CONTRACT
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanDetail — network and lifecycle contract", () => {
  it("issues exactly one scan request on mount", async () => {
    render(<ScanDetail />);
    await waitFor(() => expect(webScansApi.getScan).toHaveBeenCalledTimes(1));
    expect(webScansApi.getScan).toHaveBeenCalledWith("ws-42");
  });

  it("requests a progress ticket exactly once", async () => {
    render(<ScanDetail />);
    await waitFor(() =>
      expect(webScansApi.getProgressTicket).toHaveBeenCalledTimes(1),
    );
  });

  it("opens exactly one websocket, built from the ticket", async () => {
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    expect(webScansApi.getProgressSocketUrl).toHaveBeenCalledWith(
      "ws-42",
      "tkt-1",
    );
    expect(sockets[0].url).toContain("ticket=tkt-1");
  });

  it("does NOT poll while the websocket is healthy", async () => {
    /* The easy assumption about this page is "it polls every 5 seconds". It
       does not: the socket is the primary channel and polling is a fallback.
       Thirty seconds of simulated time must produce no extra request. */
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].open();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000);
    });
    expect(webScansApi.getScan).toHaveBeenCalledTimes(1);
  });

  it("starts fallback polling when the socket errors", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].fail();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    await waitFor(() =>
      expect(webScansApi.getScan.mock.calls.length).toBeGreaterThan(1),
    );
  });

  it("polls at the 5-second interval, not faster", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].fail();
    });
    const before = webScansApi.getScan.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000);
    });
    expect(webScansApi.getScan.mock.calls.length).toBe(before);
  });

  it("stops polling once the scan reaches a terminal status", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({ status: "complete" }),
    });
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].fail();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });
    const after = webScansApi.getScan.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000);
    });
    expect(webScansApi.getScan.mock.calls.length).toBe(after);
  });

  it("makes no request at all after unmount", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { unmount } = render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].fail();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    const atUnmount = webScansApi.getScan.mock.calls.length;
    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000);
    });
    expect(webScansApi.getScan.mock.calls.length).toBe(atUnmount);
  });

  it("closes the websocket on unmount", async () => {
    const { unmount } = render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    unmount();
    expect(sockets[0].closed).toBe(true);
  });

  it("opens no second socket while one is live", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].open();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000);
    });
    expect(sockets.length).toBe(1);
  });

  it("falls back to polling when the ticket request fails", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    webScansApi.getProgressTicket.mockRejectedValue(new Error("401"));
    render(<ScanDetail />);
    await waitFor(() => expect(webScansApi.getScan).toHaveBeenCalled());
    expect(sockets.length).toBe(0);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    await waitFor(() =>
      expect(webScansApi.getScan.mock.calls.length).toBeGreaterThan(1),
    );
  });

  it("refetches once when the socket reports a terminal status", async () => {
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].open();
    });
    const before = webScansApi.getScan.mock.calls.length;
    await act(async () => {
      sockets[0].emit({ progress: { status: "complete", percentage: 100 } });
    });
    await settle();
    expect(webScansApi.getScan.mock.calls.length).toBe(before + 1);
  });

  it("does not multiply timers across many socket closures", async () => {
    /* A duplicate-timer defect shows up as request count growing faster than
       elapsed time. Three closures then one interval must not produce three
       polls in that interval. */
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].fail();
      sockets[0].fail();
      sockets[0].fail();
    });
    const before = webScansApi.getScan.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(webScansApi.getScan.mock.calls.length).toBeLessThanOrEqual(
      before + 1,
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACTIONS
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanDetail — actions", () => {
  it("offers Cancel only while the scan is active", async () => {
    render(<ScanDetail />);
    expect(
      await screen.findByRole("button", { name: /cancel scan/i }),
    ).toBeInTheDocument();
  });

  it("does not offer Cancel once the scan is complete", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({ status: "complete" }),
    });
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(
      screen.queryByRole("button", { name: /cancel scan/i }),
    ).not.toBeInTheDocument();
  });

  it("offers Download only once the scan is complete", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({ status: "complete" }),
    });
    render(<ScanDetail />);
    expect(
      await screen.findByRole("button", { name: /download report/i }),
    ).toBeInTheDocument();
  });

  it("does not offer Download while the scan is still running", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(
      screen.queryByRole("button", { name: /download report/i }),
    ).not.toBeInTheDocument();
  });

  it("asks for confirmation before cancelling, and sends nothing if refused", async () => {
    const user = userEvent.setup();
    render(<ScanDetail />);
    await user.click(
      await screen.findByRole("button", { name: /cancel scan/i }),
    );
    // The question is the one the native prompt asked, and nothing is sent
    // until it is answered.
    const dlg = await screen.findByRole("dialog");
    expect(
      within(dlg).getByText(/are you sure you want to cancel this scan\?/i),
    ).toBeInTheDocument();
    expect(webScansApi.cancelScan).not.toHaveBeenCalled();

    await user.click(
      within(dlg).getByRole("button", { name: /keep scanning/i }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(webScansApi.cancelScan).not.toHaveBeenCalled();
  });

  it("cancels the scan by id once confirmed, then refreshes", async () => {
    const user = userEvent.setup();
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const before = webScansApi.getScan.mock.calls.length;
    await user.click(screen.getByRole("button", { name: /cancel scan/i }));
    const dlg = await screen.findByRole("dialog");
    await user.click(
      within(dlg).getByRole("button", { name: /^cancel scan$/i }),
    );
    await waitFor(() =>
      expect(webScansApi.cancelScan).toHaveBeenCalledWith("ws-42"),
    );
    await waitFor(() =>
      expect(webScansApi.getScan.mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("downloads the report for this scan id", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({ status: "complete" }),
    });
    const createUrl = vi.fn(() => "blob:report");
    vi.stubGlobal("URL", {
      createObjectURL: createUrl,
      revokeObjectURL: vi.fn(),
    });
    const user = userEvent.setup();
    render(<ScanDetail />);
    await user.click(
      await screen.findByRole("button", { name: /download report/i }),
    );
    await waitFor(() =>
      expect(webScansApi.downloadReport).toHaveBeenCalledWith("ws-42"),
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SCAN-STATE SEMANTICS
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanDetail — scan-state semantics", () => {
  it("shows the loading placeholders before the first response", async () => {
    webScansApi.getScan.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<ScanDetail />);
    await waitFor(() => expect(webScansApi.getScan).toHaveBeenCalled());
    expect(
      container.querySelectorAll(".skeleton-loader, .cc-skeleton").length,
    ).toBeGreaterThan(0);
  });

  it("surfaces a load error", async () => {
    webScansApi.getScan.mockRejectedValue({
      response: { data: { detail: "Scan not found." } },
    });
    render(<ScanDetail />);
    expect(await screen.findByText(/scan not found/i)).toBeInTheDocument();
  });

  it("renders the scan name and target", async () => {
    render(<ScanDetail />);
    expect(await screen.findByText("Corporate portal")).toBeInTheDocument();
    expect(screen.getByText("https://portal.example.test")).toBeInTheDocument();
  });

  it("renders the four headline counters", async () => {
    /* Scoped to each counter's own card. A page-wide getByText("3") is
       ambiguous — the pipeline stepper numbers its phases 1..4, so "3" matches
       a step marker as well as the high-findings count. That was a wrong
       assertion, not a page defect. */
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    /* Climb until the ancestor actually contains both the label and a number.
       `.closest("div")` returns the LABEL's own div — which holds the words and
       not the value — so it compared against text that never contains the
       count. Same shallow-climb mistake as reaching for `.closest("div")` on a
       card heading; the fix is to state the property being climbed to. */
    const counter = (label) => {
      let el = screen.getByText(new RegExp(label, "i"));
      for (let i = 0; i < 6 && el.parentElement; i += 1) {
        if (/\d/.test(el.textContent)) return el.textContent;
        el = el.parentElement;
      }
      return el.textContent;
    };
    expect(counter("discovered assets")).toMatch(/128/);
    expect(counter("critical findings")).toMatch(/2/);
    expect(counter("high findings")).toMatch(/3/);
    expect(counter("total findings")).toMatch(/9/);
    expect(container.textContent).toMatch(/128/);
  });

  it("links to the findings and asset pages for this scan", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(
      screen.getByRole("link", { name: /explore findings/i }),
    ).toHaveAttribute("href", "/web-scans/ws-42/findings");
    expect(
      screen.getByRole("link", { name: /asset inventory/i }),
    ).toHaveAttribute("href", "/web-scans/ws-42/assets");
  });

  it("reports a complete scan as 100 percent", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({ status: "complete" }),
    });
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(screen.getByText(/100%/)).toBeInTheDocument();
  });

  it("does not present a failed scan as successful", async () => {
    webScansApi.getScan.mockResolvedValue({ data: SCAN({ status: "failed" }) });
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(container.textContent).toMatch(/failed/i);
    expect(
      screen.queryByRole("button", { name: /download report/i }),
    ).not.toBeInTheDocument();
  });

  it("does not present an unrecognised status as complete or running", async () => {
    /* An unknown status must not inherit a successful or in-flight treatment.
       The pre-migration badge is a two-way branch — complete or "info" — so any
       unknown value is dressed as an active scan. */
    webScansApi.getScan.mockResolvedValue({ data: SCAN({ status: "reaped" }) });
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(
      screen.queryByRole("button", { name: /download report/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /cancel scan/i }),
    ).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/\bcomplete\b/i);
  });

  it("states the incomplete-assessment caveat when a tool did not run", async () => {
    /* The most security-relevant text on this page: a phase whose detector
       could not run produces an empty result that reads exactly like a clean
       one. */
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({
        status: "complete",
        options: {
          tool_coverage: {
            DETECT: {
              tools: [{ tool: "nuclei", status: "unavailable" }],
              tools_unavailable: ["nuclei"],
              assessment_complete: false,
            },
          },
        },
      }),
    });
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(container.textContent).toMatch(/this assessment is incomplete/i);
    expect(container.textContent).toMatch(/not evidence that nothing else/i);
    expect(container.textContent).toMatch(/nuclei/);
  });

  it("discloses a reduced-depth scan without claiming failure", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({
        status: "complete",
        options: {
          tool_coverage: {
            CRAWL: {
              tools: [{ tool: "ffuf", status: "ran" }],
              scan_depth_label: "Quick pass",
              scan_depth_caveat: "Only the first 50 endpoints were tested.",
            },
          },
        },
      }),
    });
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(container.textContent).toMatch(/reduced depth/i);
    expect(container.textContent).not.toMatch(/assessment is incomplete/i);
  });

  it("shows no caveat when every tool ran at full depth", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({
        status: "complete",
        options: {
          tool_coverage: {
            CRAWL: { tools: [{ tool: "ffuf", status: "ran" }] },
          },
        },
      }),
    });
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(container.textContent).not.toMatch(/assessment is incomplete/i);
    expect(container.textContent).not.toMatch(/reduced depth/i);
  });

  it("renders live activity from socket messages", async () => {
    render(<ScanDetail />);
    await waitFor(() => expect(sockets.length).toBe(1));
    await act(async () => {
      sockets[0].open();
      sockets[0].emit({
        progress: {
          status: "running",
          phase: "DETECT",
          message: "Probing forms",
        },
      });
    });
    /* The message legitimately appears twice: once in the polite status line
       (`scan.live_progress.message`) and once as a Live Activity entry. A
       findBy* query throws on multiple matches, so this asserts presence
       rather than uniqueness — the duplicate is the page's design, and the
       "no duplicate live region" assertion covers the case that would
       actually be a defect. */
    const hits = await screen.findAllByText(/probing forms/i);
    expect(hits.length).toBeGreaterThanOrEqual(1);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanDetail — accessibility", () => {
  it("exposes the progress bar with progressbar semantics", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const bar = screen.getByRole("progressbar");
    expect(bar).toHaveAccessibleName();
  });

  it("announces a load error assertively", async () => {
    webScansApi.getScan.mockRejectedValue({
      response: { data: { detail: "Scan not found." } },
    });
    render(<ScanDetail />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/scan not found/i);
  });

  it("announces the incomplete-assessment caveat", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({
        status: "complete",
        options: {
          tool_coverage: {
            DETECT: {
              tools: [{ tool: "nuclei", status: "unavailable" }],
              tools_unavailable: ["nuclei"],
              assessment_complete: false,
            },
          },
        },
      }),
    });
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const alerts = screen.getAllByRole("alert");
    expect(
      alerts.some((a) => /assessment is incomplete/i.test(a.textContent)),
    ).toBe(true);
  });

  it("keeps the loading placeholders out of the accessibility tree", async () => {
    webScansApi.getScan.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<ScanDetail />);
    await waitFor(() => expect(webScansApi.getScan).toHaveBeenCalled());
    const shimmer = container.querySelectorAll(
      ".skeleton-loader, .cc-skeleton",
    );
    expect(shimmer.length).toBeGreaterThan(0);
    for (const el of shimmer) {
      expect(el.getAttribute("aria-hidden")).toBe("true");
    }
  });

  it("announces that the page updates itself while a scan is active", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const live = [...document.querySelectorAll('[role="status"],[aria-live]')];
    expect(live.some((e) => /updates automatically/i.test(e.textContent))).toBe(
      true,
    );
  });

  it("gives each pipeline phase a text state, not an icon alone", async () => {
    /* The stepper conveys done / active / pending through a tick glyph, a
       spinner and a number, none of which carries text. */
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const crawl = [...container.querySelectorAll("*")].find(
      (el) => el.children.length === 0 && el.textContent.trim() === "CRAWL",
    );
    const step = crawl.closest("li,div");
    expect(step.textContent).toMatch(
      /in progress|current|done|complete|pending/i,
    );
  });

  it("names each headline counter programmatically", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const card = screen
      .getByText(/critical findings/i)
      .closest(".cc-card, .sd-stat, section, article");
    expect(card).toHaveAccessibleName();
  });

  it("does not skip a heading level", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("keeps exactly one top-level heading", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(
      screen.getAllByRole("heading").filter((h) => h.tagName === "H1").length,
    ).toBe(1);
  });

  it("marks the download control busy while generating", async () => {
    webScansApi.getScan.mockResolvedValue({
      data: SCAN({ status: "complete" }),
    });
    webScansApi.downloadReport.mockImplementation(() => new Promise(() => {}));
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn(),
      revokeObjectURL: vi.fn(),
    });
    const user = userEvent.setup();
    render(<ScanDetail />);
    await user.click(
      await screen.findByRole("button", { name: /download report/i }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /generating|download report/i }),
      ).toHaveAttribute("aria-busy", "true"),
    );
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   POLLING AND RENDERING STABILITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanDetail — polling and rendering stability", () => {
  it("never replaces settled results with the loading placeholders", async () => {
    /* `loading` goes true on every refetch inside the hook. If the page keyed
       its skeleton branch on `loading` alone, the whole page would flash back
       to placeholders on each poll. It must key on "loading AND nothing yet". */
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    await act(async () => {
      sockets[0].fail();
    });
    await settle();
    expect(screen.getByText("Corporate portal")).toBeInTheDocument();
    expect(
      container.querySelectorAll(".skeleton-loader, .cc-skeleton").length,
    ).toBe(0);
  });

  it("does not grow the DOM across repeated socket updates", async () => {
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    await act(async () => {
      sockets[0].open();
    });
    for (let i = 0; i < 6; i += 1) {
      await act(async () => {
        sockets[0].emit({
          progress: { status: "running", phase: "CRAWL", message: `tick ${i}` },
        });
      });
    }
    const first = container.querySelectorAll("*").length;
    for (let i = 0; i < 6; i += 1) {
      await act(async () => {
        sockets[0].emit({
          progress: { status: "running", phase: "CRAWL", message: `more ${i}` },
        });
      });
    }
    // The live feed is capped at 12 entries by the hook, so the node count
    // must settle rather than grow without bound.
    expect(container.querySelectorAll("*").length).toBeLessThanOrEqual(
      first + 40,
    );
  });

  it("emits no duplicate live region for the same status", async () => {
    render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const live = [...document.querySelectorAll('[role="status"],[aria-live]')];
    const texts = live.map((e) => e.textContent.trim());
    expect(new Set(texts).size).toBe(texts.length);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanDetail — rendered surface", () => {
  it("carries no page-authored inline styles", async () => {
    /* Narrowed, with the reason stated rather than the assertion dropped.
       `CcureProgress` sets the fill's width inline — `width: 33.33%` — and it
       has to: that is a measured per-instance value, not a design decision a
       token can carry, exactly as CcureSkeleton documents for its dimensions.
       It is emitted by an approved design-system component this batch may not
       modify, so an absolute "no inline styles anywhere" assertion would be
       failing the design system rather than the page.

       Everything else must still be zero, and the allowance is deliberately
       narrow: a bare width percentage inside `.cc-progress`, nothing else. */
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    const styled = [...container.querySelectorAll("[style]")]
      .filter(
        (el) =>
          !(
            el.closest(".cc-progress") &&
            /^width:\s*[\d.]+%;?$/.test(el.getAttribute("style").trim())
          ),
      )
      .map((e) => e.getAttribute("style"));
    expect(styled).toEqual([]);
  });

  it("keeps the progress fill's inline width to a bare percentage", async () => {
    // Guards the allowance above: it must not become a place styling hides.
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    for (const el of container.querySelectorAll(".cc-progress [style]")) {
      expect(el.getAttribute("style").trim()).toMatch(/^width:\s*[\d.]+%;?$/);
    }
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("builds no colour value by concatenating onto a CSS variable", async () => {
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(container.innerHTML).not.toMatch(/var\(--[a-z-]+\)[0-9a-f]{2}/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = render(<ScanDetail />);
    await screen.findByText("Corporate portal");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("injects no <style> element into the document", async () => {
    webScansApi.getScan.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<ScanDetail />);
    await waitFor(() => expect(webScansApi.getScan).toHaveBeenCalled());
    expect(container.querySelectorAll("style").length).toBe(0);
  });
});

describe("ScanDetail — permission (F2)", () => {
  afterEach(() => {
    authState.user = FULL_PERMISSION_USER;
  });

  it("does not offer Cancel to a role without scans:execute, even while running", async () => {
    authState.user = VIEWER_USER;
    render(<ScanDetail />);
    await screen.findByText("https://portal.example.test");
    expect(screen.queryByRole("button", { name: /cancel scan/i })).toBeNull();
  });
});
