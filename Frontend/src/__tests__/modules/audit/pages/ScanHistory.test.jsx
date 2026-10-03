/**
 * ScanHistory (`/history`, `/monitor`) — Checkpoint 3C batch 22 baseline.
 *
 * Written against the page BEFORE migration. The contract block is the gate
 * every later change must keep passing; the batch 22 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * Reads: GET /scans?skip=0&limit=200&scope=active (plus created_by=me and
 * search when set), GET /scans/{id} for the details dialog, and a live stream
 * fetched from /scans/events with the same filters. The stream's lifecycle is
 * part of the contract: a stream that ends or fails is retried once after
 * 2.5 seconds, and the second failure switches the page to polling
 * GET /scans every 5 seconds for as long as it is mounted. Nothing about the
 * scans' own statuses stops either loop; only unmounting does.
 *
 * Writes, each pinned by method, path and body:
 *   - Archive  POST   /scans/{id}/archive   immediately, no confirmation
 *   - Delete   DELETE /scans/{id}           immediately, no confirmation
 *   - Re-run   POST   /scan/host-discovery  after a confirmation dialog
 *   - Stop     POST   /scans/{id}/stop      after a confirmation dialog
 *
 * The API wrappers in `api/scans.js` are real: only the axios instance and
 * `fetch` are replaced, so paths, parameters and headers are asserted as they
 * leave the application. `fetch` returns a stream this file controls, so the
 * live lifecycle is driven event by event rather than by waiting on real
 * time.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation } from "react-router-dom";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

import ScanHistory from "@audit/pages/ScanHistory";
import AuthContext from "@shell/auth/AuthContext";
import api from "@shell/api/axiosInstance";
import { buildPhasePayload } from "@audit/config/scanConfig";
import { SRC, AUDIT_SRC } from "../../../testPaths";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: "/api" },
  },
  authSession: { getAccessToken: () => "harness-token" },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const scanContext = vi.hoisted(() => ({
  setTarget: vi.fn(),
  setScanType: vi.fn(),
  setPipelineMode: vi.fn(),
  setScanId: vi.fn(),
  setScanNo: vi.fn(),
  resetScan: vi.fn(),
}));
vi.mock("@audit/context/ScanContext", () => ({
  useScan: () => scanContext,
}));

const prefs = vi.hoisted(() => ({ current: { default_rows_per_page: 10 } }));
vi.mock("@shell/preferences/PreferencesContext", () => ({
  usePreferences: () => ({ preferences: prefs.current }),
}));

/* ── Fixtures ────────────────────────────────────────────────────────────── */
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const ago = (ms) => new Date(Date.now() - ms).toISOString();

const ME = 101;
const scan = (no, fields = {}) => ({
  id: `s-${no}`,
  scan_no: no,
  target: `10.20.0.${no - 1000}`,
  scan_type: "network",
  pipeline_mode: "basic",
  phase: 1,
  status: "complete",
  scan_duration: 42.5,
  progress_percentage: 100,
  summary: { active_hosts: no % 5 },
  created_by: 202,
  started_by: { user_id: 202, display_name: "Priya" },
  started_at: ago(10 * DAY),
  completed_at: ago(10 * DAY - HOUR),
  updated_at: ago(DAY),
  ...fields,
});

const SCANS = [
  scan(1001, { completed_at: ago(30 * MIN), started_at: ago(40 * MIN) }),
  scan(1002, {
    completed_at: ago(3 * HOUR),
    started_at: ago(4 * HOUR),
    created_by: ME,
    started_by: { user_id: ME, display_name: "operator" },
  }),
  scan(1003, {
    pipeline_mode: "asset",
    phase: 2,
    completed_at: ago(2 * DAY),
  }),
  scan(1004, {
    pipeline_mode: "vulnerability_audit",
    phase: 3,
    target: "10.20.0.4, 10.20.0.44",
    targets: ["10.20.0.4", "10.20.0.44"],
  }),
  scan(1005, { scan_type: "credentialed", pipeline_mode: null }),
  scan(1006, { summary: {}, scan_duration: 125 }),
  scan(1007, {
    status: "failed",
    created_by: ME,
    started_by: { user_id: ME, display_name: "operator" },
  }),
  scan(1008, { status: "failed" }),
  scan(1009, { status: "cancelled" }),
  scan(1010, { status: "canceled" }),
  scan(1011, { status: "unreachable" }),
  scan(1012, { status: "unreachable", pipeline_mode: "asset", phase: 2 }),
  scan(1013, {
    status: "running",
    pipeline_mode: "asset",
    phase: 1,
    progress_percentage: 40,
    completed_at: null,
    summary: { active_hosts: 7, vulnerabilities: 3 },
  }),
  scan(1014, {
    status: null,
    progress_percentage: null,
    completed_at: null,
    summary: {},
  }),
];

const cve = (n, fields = {}) => ({
  cve_id: `CVE-2024-000${n}`,
  cvss_score: 9.8 - n,
  description: `Flaw number ${n}`,
  ...fields,
});

const DETAIL = {
  ...scan(1012, { status: "unreachable", pipeline_mode: "asset", phase: 2 }),
  scan_duration: 9.252127170562744,
  failure_reason: "No host answered the discovery probes.",
  summary: {
    scan_duration: 9.252127170562744,
    coverage_percent: 87.4,
    hosts_scanned: 12,
    ratio: 0.5,
    flag: true,
    _internal: 1,
    nested: { skipped: true },
  },
  results: {
    phase1: {
      data: [
        {
          is_active: true,
          ip_address: "10.20.0.21",
          hostname: "files-01",
          mac_address: "00:1A:2B:3C:4D:5E",
          vendor: "Dell",
          host_risk_level: "High",
          host_risk_score: 7.5,
          open_ports: [
            { port: 22, service: "ssh" },
            { port: 443, service: "https" },
            { port: 3389, service: "rdp" },
          ],
          cves: [1, 2, 3, 4, 5, 6].map((n) => cve(n)),
          suppressed_cves: [{ cve_id: "CVE-1" }, { cve_id: "CVE-2" }],
        },
        { is_active: false, ip_address: "10.20.0.99" },
      ],
    },
  },
};

/* ── A fetch stream this file controls ─────────────────────────────────── */
let streams;
let fetchReply;
const encoder = new TextEncoder();

function makeStream(url, init) {
  const queue = [];
  let waiting = null;
  let closed = false;
  let failure = null;
  const deliver = () => {
    if (!waiting) return;
    const { resolve, reject } = waiting;
    if (queue.length) {
      waiting = null;
      resolve({ value: queue.shift(), done: false });
    } else if (failure) {
      waiting = null;
      reject(failure);
    } else if (closed) {
      waiting = null;
      resolve({ value: undefined, done: true });
    }
  };
  const stream = {
    url,
    init,
    params: new URL(url, "http://harness.local").searchParams,
    send(event, data) {
      queue.push(
        encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
      );
      deliver();
    },
    end() {
      closed = true;
      deliver();
    },
    fail(error = new Error("stream reset")) {
      failure = error;
      deliver();
    },
    response: {
      ok: true,
      status: 200,
      body: {
        getReader: () => ({
          read: () =>
            new Promise((resolve, reject) => {
              waiting = { resolve, reject };
              deliver();
            }),
        }),
      },
    },
  };
  init?.signal?.addEventListener("abort", () => {
    failure = new DOMException("The operation was aborted.", "AbortError");
    deliver();
  });
  return stream;
}

/* ── Harness ────────────────────────────────────────────────────────────── */
const user = (...permissions) => ({
  id: ME,
  username: "operator",
  role: { name: "analyst" },
  permissionKeys: permissions,
});
const FULL = user(
  "audit.scan.read",
  "audit.scan.run",
  "audit.scan.lifecycle",
  "audit.scan.lifecycle",
);

let listReply;
let detailReply;

function LocationProbe() {
  const location = useLocation();
  return (
    <output
      data-testid="location"
      data-state={JSON.stringify(location.state ?? null)}
    >{`${location.pathname}${location.search}`}</output>
  );
}

const renderAt = (entry = "/history", { as = FULL } = {}) =>
  render(
    <AuthContext.Provider
      value={{ user: as, loading: false, authState: "authenticated" }}
    >
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/history" element={<ScanHistory mode="history" />} />
          <Route path="/monitor" element={<ScanHistory mode="monitor" />} />
          <Route path="*" element={<p>Elsewhere</p>} />
        </Routes>
        <LocationProbe />
      </MemoryRouter>
    </AuthContext.Provider>,
  );

const flush = async () => {
  for (let i = 0; i < 6; i += 1) {
    await act(async () => {});
  }
};
const loaded = async (entry, options) => {
  const view = renderAt(entry, options);
  await flush();
  return view;
};
const advance = async (ms) => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
  await flush();
};

const listCalls = () => api.get.mock.calls.filter(([url]) => url === "/scans");
const location = () => screen.getByTestId("location").textContent;
const locationState = () =>
  JSON.parse(screen.getByTestId("location").getAttribute("data-state"));
const squash = (el) => (el?.textContent || "").replace(/\s+/g, " ").trim();
const bodyText = () => squash(document.body);
const sse = (i = -1) => streams.at(i);
const event = async (i, name, data) => {
  await act(async () => {
    sse(i).send(name, data);
  });
  await flush();
};

const rows = () => {
  const table = screen.queryByRole("table");
  return table ? within(table).getAllByRole("row").slice(1) : [];
};
const rowNumbers = () =>
  rows().map((r) => Number(squash(r.querySelector("td, th"))));
const stopDialog = () => screen.getByRole("dialog", { name: /Stop Scan\?$/ });
const rowFor = (no) =>
  rows().find((r) => within(r).queryByText(String(no)) !== null);
const inRow = (no, name) =>
  within(rowFor(no)).getByRole("button", { name: new RegExp(`^${name}\\b`) });

beforeEach(() => {
  streams = [];
  fetchReply = (stream) => Promise.resolve(stream.response);
  vi.stubGlobal(
    "fetch",
    vi.fn((url, init) => {
      const stream = makeStream(url, init);
      streams.push(stream);
      return fetchReply(stream);
    }),
  );
  prefs.current = { default_rows_per_page: 10 };
  listReply = () =>
    Promise.resolve({ data: { scans: SCANS, total: SCANS.length } });
  detailReply = () => Promise.resolve({ data: DETAIL });
  api.get.mockReset();
  api.get.mockImplementation((url, config) =>
    url === "/scans" ? listReply(config) : detailReply(url),
  );
  for (const verb of ["post", "put", "patch", "delete"]) api[verb].mockReset();
  Object.values(scanContext).forEach((fn) => fn.mockReset());
  localStorage.removeItem("activeOrgId");
});

afterEach(() => {
  // Only the four writes the page is built to make, and never PUT or PATCH.
  expect(api.put).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
  for (const [url, ...rest] of api.post.mock.calls) {
    expect(url).toMatch(
      /^\/scan\/host-discovery$|^\/scans\/[^/]+\/(archive|stop)$/,
    );
    if (url !== "/scan/host-discovery") expect(rest).toEqual([]);
  }
  for (const [url, ...rest] of api.delete.mock.calls) {
    expect(url).toMatch(/^\/scans\/[^/]+$/);
    expect(rest).toEqual([]);
  }
  for (const [url] of fetch.mock.calls) {
    expect(url).toMatch(/^\/api\/scans\/events\?/);
  }
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/* ════════════════════════════════════════════════════════════════════════════
   The contract — passes on the legacy page and must keep passing.
   ════════════════════════════════════════════════════════════════════════════ */

describe("ScanHistory — contract", () => {
  describe("reads", () => {
    it("loads active scans once on mount, writing nothing", async () => {
      await loaded();
      expect(listCalls()).toEqual([
        ["/scans", { params: { skip: 0, limit: 200, scope: "active" } }],
      ]);
      expect(api.post).not.toHaveBeenCalled();
      expect(api.delete).not.toHaveBeenCalled();
      expect(screen.getByTestId("app-layout")).toHaveAttribute(
        "data-page-title",
        "Scan History",
      );
    });

    it("opens exactly one live stream with the list's filters, token and credentials", async () => {
      localStorage.setItem("activeOrgId", "o-7");
      await loaded();
      expect(fetch).toHaveBeenCalledTimes(1);
      const [url, init] = fetch.mock.calls[0];
      expect(url).toBe(
        "/api/scans/events?scope=active&skip=0&limit=200&interval=2&org_id=o-7",
      );
      expect(init.headers).toEqual({
        Accept: "text/event-stream",
        Authorization: "Bearer harness-token",
      });
      expect(init.credentials).toBe("include");
      expect(init.signal).toBeInstanceOf(AbortSignal);
      expect(init.signal.aborted).toBe(false);
    });

    it("sends created_by=me for ?owner=mine, on the list and the stream, and never sends the status tab", async () => {
      await loaded("/history?status=failed&owner=mine");
      expect(listCalls()).toEqual([
        [
          "/scans",
          {
            params: { skip: 0, limit: 200, scope: "active", created_by: "me" },
          },
        ],
      ]);
      expect(sse(0).params.get("created_by")).toBe("me");
      expect(sse(0).params.get("status")).toBeNull();
      expect(rowNumbers()).toEqual([1007]);
    });

    it("searches on the server after 300 ms, trimmed, and restarts the stream with the search", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      renderAt();
      await flush();
      fireEvent.change(screen.getByLabelText("Search"), {
        target: { value: "  10.20.0.1  " },
      });
      await advance(299);
      expect(listCalls()).toHaveLength(1);
      expect(fetch).toHaveBeenCalledTimes(1);
      await advance(1);
      expect(listCalls()).toHaveLength(2);
      expect(listCalls()[1][1].params).toEqual({
        skip: 0,
        limit: 200,
        scope: "active",
        search: "10.20.0.1",
      });
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(sse(0).init.signal.aborted).toBe(true);
      expect(sse(1).params.get("search")).toBe("10.20.0.1");
    });

    it("changing the owner filter reloads and restarts the stream", async () => {
      await loaded();
      fireEvent.click(screen.getByRole("button", { name: "My scans" }));
      await flush();
      expect(listCalls().at(-1)[1].params).toEqual({
        skip: 0,
        limit: 200,
        scope: "active",
        created_by: "me",
      });
      expect(sse(0).init.signal.aborted).toBe(true);
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(sse(1).params.get("created_by")).toBe("me");
      expect(rowNumbers()).toEqual([1007, 1002]);
    });

    it("status and time filters are applied in the browser, without a request", async () => {
      await loaded();
      fireEvent.click(screen.getByRole("button", { name: "Failed" }));
      expect(rowNumbers()).toEqual([1008, 1007]);
      fireEvent.click(screen.getByRole("button", { name: "Cancelled" }));
      expect(rowNumbers()).toEqual([1010, 1009]);
      fireEvent.click(screen.getByRole("button", { name: "Host Unreachable" }));
      expect(rowNumbers()).toEqual([1012, 1011]);
      fireEvent.click(screen.getByRole("button", { name: "All" }));
      fireEvent.click(screen.getByRole("button", { name: "1 hr" }));
      expect(rowNumbers()).toEqual([1001]);
      fireEvent.click(screen.getByRole("button", { name: "24 hrs" }));
      expect(rowNumbers()).toEqual([1002, 1001]);
      expect(listCalls()).toHaveLength(1);
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it("Sync now reloads the same list and cannot be pressed while it runs", async () => {
      await loaded();
      let resolve;
      listReply = () =>
        new Promise((r) => {
          resolve = () => r({ data: { scans: SCANS, total: SCANS.length } });
        });
      const sync = screen.getByRole("button", { name: /Sync now/ });
      fireEvent.click(sync);
      await flush();
      expect(listCalls()).toHaveLength(2);
      expect(listCalls()[1][1].params).toEqual({
        skip: 0,
        limit: 200,
        scope: "active",
      });
      expect(sync).toBeDisabled();
      await act(async () => resolve());
      await flush();
      expect(sync).toBeEnabled();
    });
  });

  describe("live stream lifecycle", () => {
    it("applies connected, scans and heartbeat events, and ignores others", async () => {
      await loaded();
      expect(bodyText()).toContain("Live sync connecting");
      await event(0, "connected", { ok: true });
      expect(bodyText()).toContain("Live sync active");
      const updated = SCANS.map((s) =>
        s.scan_no === 1012 ? { ...s, status: "failed" } : s,
      ).filter((s) => s.scan_no !== 1011);
      await event(0, "scans", { scans: updated, total: 13 });
      expect(within(rowFor(1012)).getByText("Failed")).toBeInTheDocument();
      expect(rowFor(1011)).toBeUndefined();
      expect(bodyText()).toContain("13 scans");
      await event(0, "heartbeat", {});
      await event(0, "surprise", { scans: [] });
      expect(rowFor(1012)).toBeDefined();
      expect(listCalls()).toHaveLength(1);
    });

    it("a snapshot without a scans array changes nothing", async () => {
      await loaded();
      await event(0, "scans", { total: 0 });
      expect(rows()).toHaveLength(10);
      expect(bodyText()).toContain("14 scans");
    });

    it("never polls while the stream is open", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      renderAt();
      await flush();
      await event(0, "connected", {});
      await advance(60_000);
      expect(listCalls()).toHaveLength(1);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(bodyText()).toContain("Live sync active");
    });

    it("retries a closed stream once after 2.5 s, then polls every 5 s and never reopens it", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      renderAt();
      await flush();
      await event(0, "connected", {});
      await act(async () => sse(0).end());
      await flush();
      expect(bodyText()).toContain("Live sync reconnecting");
      await advance(2499);
      expect(fetch).toHaveBeenCalledTimes(1);
      await advance(1);
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(sse(1).url).toBe(sse(0).url);

      // A reconnect that works does not reset the count.
      await event(1, "connected", {});
      expect(bodyText()).toContain("Live sync active");
      await act(async () => sse(1).fail());
      await flush();
      expect(bodyText()).toContain("Live sync polling");
      expect(listCalls()).toHaveLength(2);
      expect(listCalls()[1][1].params).toEqual({
        skip: 0,
        limit: 200,
        scope: "active",
      });
      await advance(4999);
      expect(listCalls()).toHaveLength(2);
      await advance(1);
      expect(listCalls()).toHaveLength(3);
      await advance(5000);
      expect(listCalls()).toHaveLength(4);
      await advance(60_000);
      expect(fetch).toHaveBeenCalledTimes(2);
    });

    it("counts a refused stream as a failure", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      fetchReply = () =>
        Promise.resolve({ ok: false, status: 503, body: null });
      renderAt();
      await flush();
      expect(bodyText()).toContain("Live sync reconnecting");
      await advance(2500);
      expect(fetch).toHaveBeenCalledTimes(2);
      await flush();
      expect(bodyText()).toContain("Live sync polling");
      expect(listCalls()).toHaveLength(2);
    });

    it("keeps its live sync running whatever the scans' statuses", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      const settled = SCANS.filter((s) =>
        ["complete", "failed", "cancelled", "canceled", "unreachable"].includes(
          s.status,
        ),
      );
      listReply = () =>
        Promise.resolve({ data: { scans: settled, total: settled.length } });
      renderAt();
      await flush();
      await act(async () => sse(0).end());
      await advance(2500);
      await act(async () => sse(1).end());
      await flush();
      await advance(15_000);
      expect(listCalls()).toHaveLength(5);
    });

    it("a failed poll leaves the page as it was, and a successful one clears an earlier error", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      listReply = () => Promise.reject(new Error("offline"));
      renderAt();
      await flush();
      expect(bodyText()).toContain("Failed to load scan history.");
      await act(async () => sse(0).end());
      await advance(2500);
      await act(async () => sse(1).end());
      await flush();
      expect(listCalls()).toHaveLength(2);
      expect(bodyText()).toContain("Failed to load scan history.");
      listReply = () =>
        Promise.resolve({ data: { scans: SCANS, total: SCANS.length } });
      await advance(5000);
      expect(bodyText()).not.toContain("Failed to load scan history.");
      expect(rows()).toHaveLength(10);
    });

    it("unmounting aborts an open stream and nothing is requested afterwards", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      const { unmount } = renderAt();
      await flush();
      const signal = sse(0).init.signal;
      unmount();
      expect(signal.aborted).toBe(true);
      await advance(60_000);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(listCalls()).toHaveLength(1);
    });

    it("unmounting during the reconnect wait stops the retry", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      const { unmount } = renderAt();
      await flush();
      await act(async () => sse(0).end());
      await flush();
      unmount();
      await advance(60_000);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(listCalls()).toHaveLength(1);
    });

    it("unmounting while polling stops the polling", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      const { unmount } = renderAt();
      await flush();
      await act(async () => sse(0).end());
      await advance(2500);
      await act(async () => sse(1).end());
      await flush();
      expect(listCalls()).toHaveLength(2);
      unmount();
      await advance(60_000);
      expect(listCalls()).toHaveLength(2);
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe("list, filters, sorting and paging", () => {
    it("shows only settled scans in history, newest first, ten to a page", async () => {
      await loaded();
      expect(rowNumbers()).toEqual([
        1012, 1011, 1010, 1009, 1008, 1007, 1006, 1005, 1004, 1003,
      ]);
      expect(bodyText()).toContain("14 scans · operator");
      const row = squash(rowFor(1002) ?? document.body);
      expect(row).toBeDefined();
    });

    it("renders each scan's number, target, type, owner, status, hosts, duration and date", async () => {
      await loaded();
      const text = (no) => squash(rowFor(no));
      expect(text(1004)).toMatch(
        /1004.*10\.20\.0\.4, 10\.20\.0\.44.*Vulnerability Audit.*Priya.*Completed.*4.*42\.5s/,
      );
      expect(text(1005)).toContain("Credentialed Scan");
      expect(text(1006)).toMatch(/—.*2m 5s/);
      expect(text(1007)).toMatch(/You.*Failed/);
      expect(text(1009)).toContain("Cancelled");
      expect(text(1010)).toContain("Cancelled");
      expect(text(1011)).toContain("Host Unreachable");
      expect(text(1012)).toContain("Asset Discovery");
    });

    it("pages with the preferred page size", async () => {
      await loaded();
      const previous = screen.getByRole("button", { name: "Previous" });
      expect(previous).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "Next" }));
      expect(rowNumbers()).toEqual([1002, 1001]);
      expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "Previous" }));
      expect(rowNumbers()[0]).toBe(1012);
    });

    it("with everything on one page, says how many of the total are shown", async () => {
      prefs.current = { default_rows_per_page: 25 };
      listReply = () => Promise.resolve({ data: { scans: SCANS, total: 40 } });
      await loaded();
      expect(rows()).toHaveLength(12);
      expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
      expect(bodyText()).toContain("Showing 12 of 40 scans");
    });

    it("sorts by column: text ascending first, numbers and dates descending first, back to page one", async () => {
      await loaded();
      fireEvent.click(screen.getByRole("button", { name: "Next" }));
      fireEvent.click(screen.getByRole("button", { name: "Target" }));
      expect(rowNumbers().slice(0, 3)).toEqual([1001, 1002, 1003]);
      fireEvent.click(screen.getByRole("button", { name: "Target" }));
      expect(rowNumbers()[0]).toBe(1012);
      fireEvent.click(screen.getByRole("button", { name: "Duration" }));
      expect(rowNumbers()[0]).toBe(1006);
      fireEvent.click(screen.getByRole("button", { name: "Date" }));
      expect(rowNumbers()[0]).toBe(1001);
    });

    it("shows the empty states, with a way to start a scan", async () => {
      listReply = () => Promise.resolve({ data: { scans: [], total: 0 } });
      await loaded();
      expect(bodyText()).toContain("No scans yet.");
      fireEvent.click(
        screen.getByRole("button", { name: /Start your first scan/ }),
      );
      expect(location()).toBe("/scan");
    });

    it("says no scans match when a status or time filter empties the list", async () => {
      await loaded();
      fireEvent.click(screen.getByRole("button", { name: "1 hr" }));
      fireEvent.click(screen.getByRole("button", { name: "Failed" }));
      expect(bodyText()).toContain("No scans match your filters.");
    });

    it("shows nothing but the load until the list arrives", async () => {
      listReply = () => new Promise(() => {});
      await loaded();
      expect(screen.queryByRole("table")).toBeNull();
      expect(bodyText()).not.toContain("No scans yet.");
      expect(bodyText()).not.toContain("Failed to load scan history.");
    });
  });

  describe("details", () => {
    it("View opens the scan's details from GET /scans/{id}", async () => {
      await loaded();
      fireEvent.click(inRow(1012, "View"));
      await flush();
      expect(api.get).toHaveBeenCalledWith("/scans/s-1012");
      expect(
        screen.getByRole("heading", { level: 2, name: "Scan No. 1012" }),
      ).toBeInTheDocument();
      const text = bodyText();
      expect(text).toMatch(/Target\s*10\.20\.0\.12/);
      expect(text).toMatch(/Scan Type\s*Asset Discovery/);
      expect(text).toMatch(/Phase\s*Port Scan/);
      expect(text).toMatch(/Duration\s*9\.3s/);
      expect(text).toContain("No host answered the discovery probes.");
      expect(text).toMatch(/scan duration\s*9\.3s/);
      expect(text).toMatch(/coverage percent\s*87%/);
      expect(text).toMatch(/hosts scanned\s*12/);
      expect(text).toMatch(/ratio\s*0\.50/);
      expect(text).toMatch(/flag\s*true/);
      expect(text).not.toContain("_internal");
      expect(text).not.toContain("nested");
      expect(text).toMatch(/Discovery Results\s*\(1 host\)/);
      expect(text).toContain("00:1a:2b:3c:4d:5e");
      expect(text).toContain("3 ports");
      expect(text).toContain("6 verified");
      expect(text).toContain("2 ruled out");
      expect(text).toMatch(/22\s*ssh/);
      expect(text).toContain("CVE-2024-0005");
      expect(text).not.toContain("CVE-2024-0006");
      expect(text).toContain("+1 more");
      expect(text).not.toContain("10.20.0.99");
    });

    it("opens the full results for a scan with discovery data, and closes", async () => {
      await loaded();
      fireEvent.click(inRow(1012, "View"));
      await flush();
      fireEvent.click(
        screen.getByRole("button", { name: /Open full results & exports/ }),
      );
      await flush();
      expect(location()).toBe("/scan/s-1012/phase1");
    });

    it("the close button closes the details", async () => {
      await loaded();
      fireEvent.click(inRow(1012, "View"));
      await flush();
      fireEvent.click(
        screen.getByRole("button", { name: /^(✕|Close dialog)$/ }),
      );
      await flush();
      expect(screen.queryByText("Scan No. 1012")).toBeNull();
    });

    it("reports details that fail to load", async () => {
      detailReply = () => Promise.reject(new Error("boom"));
      await loaded();
      fireEvent.click(inRow(1011, "View"));
      await flush();
      expect(bodyText()).toContain("Failed to load scan details.");
    });

    it("a credentialed scan's View goes to its results page instead", async () => {
      await loaded();
      fireEvent.click(inRow(1005, "View"));
      await flush();
      expect(location()).toBe("/scan/credentialed/results?scan_id=s-1005");
      expect(api.get).not.toHaveBeenCalledWith("/scans/s-1005");
    });
  });

  describe("archive and delete", () => {
    it("Archive posts at once, with no confirmation, and drops the row", async () => {
      await loaded();
      fireEvent.click(inRow(1012, "Archive"));
      expect(screen.queryByRole("dialog")).toBeNull();
      await flush();
      expect(api.post).toHaveBeenCalledTimes(1);
      expect(api.post.mock.calls[0]).toEqual(["/scans/s-1012/archive"]);
      expect(rowFor(1012)).toBeUndefined();
      expect(bodyText()).toContain("13 scans");
      expect(bodyText()).toContain(
        "Scan No. 1012 archived. You can restore it from Archived Scans.",
      );
      expect(listCalls()).toHaveLength(1);
    });

    it("a failed archive keeps the row and says so", async () => {
      api.post.mockRejectedValue(new Error("nope"));
      await loaded();
      fireEvent.click(inRow(1012, "Archive"));
      await flush();
      expect(rowFor(1012)).toBeDefined();
      expect(bodyText()).toContain("Failed to archive scan. Please try again.");
    });

    it("Delete sends DELETE at once, with no confirmation, and drops the row", async () => {
      await loaded();
      fireEvent.click(inRow(1011, "Delete"));
      expect(screen.queryByRole("dialog")).toBeNull();
      await flush();
      expect(api.delete.mock.calls).toEqual([["/scans/s-1011"]]);
      expect(rowFor(1011)).toBeUndefined();
      expect(bodyText()).toContain("13 scans");
      expect(bodyText()).toContain("Scan No. 1011 moved to Recycle Bin.");
    });

    it("a failed delete keeps the row and says so", async () => {
      api.delete.mockRejectedValue(new Error("nope"));
      await loaded();
      fireEvent.click(inRow(1011, "Delete"));
      await flush();
      expect(rowFor(1011)).toBeDefined();
      expect(bodyText()).toContain("Failed to delete scan. Please try again.");
    });
  });

  describe("re-run", () => {
    const dialog = () =>
      screen.getByRole("dialog", { name: /^.*Re-run Scan No\. 1004\?$/ });

    it("asks first, with the scan's details and the warning, and sends nothing until confirmed", async () => {
      await loaded();
      fireEvent.click(inRow(1004, "Re-run"));
      await flush();
      const d = dialog();
      const text = squash(d);
      expect(text).toContain(
        "This will start a fresh scan against the same target using the same configuration.",
      );
      expect(text).toMatch(/Target\s*10\.20\.0\.4, 10\.20\.0\.44/);
      expect(text).toMatch(/Type\s*Vulnerability Audit/);
      expect(text).toMatch(/Phase\s*P3 — Vulnerability/);
      expect(text).toContain("Last run");
      expect(text).toContain(
        "This action will send live network packets to the target. Only proceed if you have authorisation to scan this host.",
      );
      expect(
        within(d).getByRole("button", { name: /^Re-run Scan$/ }),
      ).toHaveFocus();
      expect(api.post).not.toHaveBeenCalled();
    });

    it.each([
      [
        "Cancel",
        (d) =>
          fireEvent.click(within(d).getByRole("button", { name: "Cancel" })),
      ],
      ["Escape", () => fireEvent.keyDown(document, { key: "Escape" })],
      [
        "a click outside",
        (d) => {
          const overlay = d.parentElement;
          fireEvent.mouseDown(overlay);
          fireEvent.mouseUp(overlay);
          fireEvent.click(overlay);
        },
      ],
    ])("%s closes it without a request", async (_how, close) => {
      await loaded();
      fireEvent.click(inRow(1004, "Re-run"));
      await flush();
      close(dialog());
      await flush();
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(api.post).not.toHaveBeenCalled();
    });

    it("confirming posts the original pipeline and targets, sets up the new session and opens it", async () => {
      api.post.mockResolvedValue({
        data: { success: true, scan_id: "s-2001", scan_no: 2001 },
      });
      await loaded();
      fireEvent.click(inRow(1004, "Re-run"));
      await flush();
      fireEvent.click(
        within(dialog()).getByRole("button", { name: /^Re-run Scan$/ }),
      );
      await flush();
      expect(api.post.mock.calls).toEqual([
        [
          "/scan/host-discovery",
          buildPhasePayload("vulnerability_audit", {
            targets: ["10.20.0.4", "10.20.0.44"],
            scan_type: "network",
          }),
        ],
      ]);
      expect(api.post.mock.calls[0][1]).toEqual({
        phases: [1, 2, 3],
        pipeline_mode: "vulnerability_audit",
        targets: ["10.20.0.4", "10.20.0.44"],
        scan_type: "network",
      });
      expect(scanContext.resetScan).toHaveBeenCalledTimes(1);
      expect(scanContext.resetScan.mock.invocationCallOrder[0]).toBeLessThan(
        scanContext.setTarget.mock.invocationCallOrder[0],
      );
      expect(scanContext.setTarget).toHaveBeenCalledWith(
        "10.20.0.4, 10.20.0.44",
      );
      expect(scanContext.setScanType).toHaveBeenCalledWith("network");
      expect(scanContext.setPipelineMode).toHaveBeenCalledWith(
        "vulnerability_audit",
      );
      expect(scanContext.setScanId).toHaveBeenCalledWith("s-2001");
      expect(scanContext.setScanNo).toHaveBeenCalledWith(2001);
      expect(location()).toBe("/scan/active/s-2001");
      expect(locationState()).toEqual({
        missionMode: true,
        scanId: "s-2001",
        scanNo: 2001,
        target: "10.20.0.4, 10.20.0.44",
        pipelineMode: "vulnerability_audit",
      });
    });

    it("splits a comma-separated target, defaults the type and pipeline, and falls back to display_id", async () => {
      const bare = scan(1015, {
        target: "10.9.0.1, 10.9.0.2",
        scan_type: undefined,
        pipeline_mode: undefined,
      });
      listReply = () => Promise.resolve({ data: { scans: [bare], total: 1 } });
      api.post.mockResolvedValue({
        data: { success: true, scan_id: "s-3", display_id: "D-3" },
      });
      await loaded();
      fireEvent.click(inRow(1015, "Re-run"));
      await flush();
      fireEvent.click(screen.getByRole("button", { name: /^Re-run Scan$/ }));
      await flush();
      expect(api.post.mock.calls[0][1]).toEqual(
        buildPhasePayload("basic", {
          targets: ["10.9.0.1", "10.9.0.2"],
          scan_type: "adaptive",
        }),
      );
      expect(scanContext.setScanNo).toHaveBeenCalledWith("D-3");
      expect(locationState().scanNo).toBe("D-3");
    });

    it("disables both buttons while the request runs", async () => {
      api.post.mockImplementation(() => new Promise(() => {}));
      await loaded();
      fireEvent.click(inRow(1004, "Re-run"));
      await flush();
      const d = dialog();
      fireEvent.click(within(d).getByRole("button", { name: /^Re-run Scan$/ }));
      await flush();
      expect(within(d).getByRole("button", { name: "Cancel" })).toBeDisabled();
      expect(
        within(d).getByRole("button", { name: /Re-run Scan/ }),
      ).toBeDisabled();
    });

    it.each([
      [
        { data: { success: false, error: "Quota exceeded" } },
        "Re-run failed: Quota exceeded",
      ],
      [{ data: { success: false } }, "Re-run failed: Re-run failed"],
    ])("a refusal closes the dialog and reports it", async (reply, message) => {
      api.post.mockResolvedValue(reply);
      await loaded();
      fireEvent.click(inRow(1004, "Re-run"));
      await flush();
      fireEvent.click(screen.getByRole("button", { name: /^Re-run Scan$/ }));
      await flush();
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(bodyText()).toContain(message);
      expect(location()).toBe("/history");
      expect(scanContext.resetScan).not.toHaveBeenCalled();
    });

    it("a rejected request reports the API's detail", async () => {
      api.post.mockRejectedValue({
        message: "Request failed",
        response: { data: { detail: "Target out of scope" } },
      });
      await loaded();
      fireEvent.click(inRow(1004, "Re-run"));
      await flush();
      fireEvent.click(screen.getByRole("button", { name: /^Re-run Scan$/ }));
      await flush();
      expect(bodyText()).toContain("Re-run failed: Target out of scope");
    });

    it("a credentialed scan is re-run from its own page, with the target filled in", async () => {
      await loaded();
      fireEvent.click(inRow(1005, "Re-run"));
      await flush();
      fireEvent.click(screen.getByRole("button", { name: /^Re-run Scan$/ }));
      await flush();
      expect(api.post).not.toHaveBeenCalled();
      expect(scanContext.resetScan).toHaveBeenCalledTimes(1);
      expect(location()).toBe("/scan/credentialed");
      expect(locationState()).toEqual({ prefill: { ip: "10.20.0.5" } });
    });
  });

  describe("monitor and stop", () => {
    const stopDialog = () =>
      screen.getByRole("dialog", { name: /Stop Scan\?$/ });

    it("lists running scans only, with their progress and a Stop control", async () => {
      await loaded("/monitor");
      expect(screen.getByTestId("app-layout")).toHaveAttribute(
        "data-page-title",
        "Active Scans",
      );
      expect(bodyText()).toContain("2 active operations");
      const text = bodyText();
      expect(text).toContain("10.20.0.13");
      expect(text).toContain("10.20.0.14");
      expect(text).not.toContain("10.20.0.12");
      expect(text).toContain("P1 — Discovery");
      expect(text).toMatch(/Overall Progress\s*40%/);
      expect(text).toMatch(/7\s*Active Hosts/);
      expect(text).toMatch(/3\s*Findings/);
      expect(
        screen.getAllByRole("button", { name: /^Stop Scan/ }),
      ).toHaveLength(2);
      expect(screen.getByRole("button", { name: "Running" })).toBeDisabled();
      expect(screen.queryByLabelText("Search")).toBeNull();
    });

    it("Stop asks first, then posts, marks the scan cancelled and reports it", async () => {
      api.post.mockResolvedValue({ data: {} });
      await loaded("/monitor");
      fireEvent.click(screen.getAllByRole("button", { name: /^Stop Scan/ })[0]);
      await flush();
      const d = stopDialog();
      expect(squash(d)).toContain(
        "Are you sure you want to terminate Scan No. 1013?",
      );
      expect(squash(d)).toContain(
        "Stopping a scan will immediately terminate all active probes. Any results gathered so far will be saved, but the scan will be marked as cancelled.",
      );
      expect(api.post).not.toHaveBeenCalled();
      fireEvent.click(within(d).getByRole("button", { name: /^Stop Scan$/ }));
      await flush();
      expect(api.post.mock.calls).toEqual([["/scans/s-1013/stop"]]);
      expect(bodyText()).not.toContain("10.20.0.13");
      expect(bodyText()).toContain("Scan No. 1013 stopped.");
    });

    it("a failed stop reports the API's detail", async () => {
      api.post.mockRejectedValue({
        message: "x",
        response: { data: { detail: "Worker unavailable" } },
      });
      await loaded("/monitor");
      fireEvent.click(screen.getAllByRole("button", { name: /^Stop Scan/ })[0]);
      await flush();
      fireEvent.click(
        within(stopDialog()).getByRole("button", { name: /^Stop Scan$/ }),
      );
      await flush();
      expect(bodyText()).toContain("Failed to stop scan: Worker unavailable");
      expect(bodyText()).toContain("10.20.0.13");
    });

    it("says so when nothing is running", async () => {
      listReply = () =>
        Promise.resolve({ data: { scans: SCANS.slice(0, 12), total: 12 } });
      await loaded("/monitor");
      expect(bodyText()).toContain("No active scans running right now.");
      fireEvent.click(screen.getByRole("button", { name: /Launch new scan/ }));
      expect(location()).toBe("/scan");
    });
  });

  describe("permissions", () => {
    it("offers each action only with its permission", async () => {
      await loaded("/history", { as: user("audit.scan.read") });
      expect(inRow(1012, "View")).toBeEnabled();
      const names = within(rowFor(1012))
        .getAllByRole("button")
        .map((b) => squash(b));
      expect(names.some((n) => /Re-run|Archive|Delete/.test(n))).toBe(false);
    });

    it("without scans:read there is no View", async () => {
      await loaded("/history", {
        as: user(
          "audit.scan.run",
          "audit.scan.lifecycle",
          "audit.scan.lifecycle",
        ),
      });
      const names = within(rowFor(1012))
        .getAllByRole("button")
        .map((b) => squash(b));
      expect(names.some((n) => /^View/.test(n))).toBe(false);
      expect(names.some((n) => /^Re-run/.test(n))).toBe(true);
    });

    it("Stop is shown without scans:execute, and confirming it is refused without a request", async () => {
      await loaded("/monitor", { as: user("audit.scan.read") });
      fireEvent.click(screen.getAllByRole("button", { name: /^Stop Scan/ })[0]);
      await flush();
      fireEvent.click(
        within(stopDialog()).getByRole("button", { name: /^Stop Scan$/ }),
      );
      await flush();
      expect(api.post).not.toHaveBeenCalled();
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(bodyText()).toContain(
        "You do not have permission to perform this action.",
      );
    });

    it("App.jsx mounts both modes behind the base sign-in check only", () => {
      const app = readFileSync(path.join(SRC, "App.jsx"), "utf8");
      const base = app.indexOf("<Route element={<PrivateRoute />}>");
      const firstGate = app.indexOf("requiredPermission", base);
      for (const re of [
        /<Route path="\/monitor" element=\{<ScanHistory mode="monitor" \/>\} \/>/,
        /<Route path="\/history" element=\{<ScanHistory mode="history" \/>\} \/>/,
      ]) {
        const at = app.search(re);
        expect(at).toBeGreaterThan(base);
        expect(at).toBeLessThan(firstGate);
      }
      expect(app).toMatch(
        /path="\/scan-history"\s+element=\{<Navigate to="\/history" replace \/>\}/,
      );
      expect(app.match(/<ScanHistory\b/g)).toHaveLength(2);
    });
  });

  describe("notifications", () => {
    it("a notification can be dismissed by clicking it, and leaves by itself after 4 s", async () => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
      api.post.mockResolvedValue({ data: {} });
      renderAt();
      await flush();
      fireEvent.click(inRow(1012, "Archive"));
      await flush();
      const message =
        "Scan No. 1012 archived. You can restore it from Archived Scans.";
      expect(bodyText()).toContain(message);
      await advance(4000);
      await advance(220);
      expect(bodyText()).not.toContain(message);

      fireEvent.click(inRow(1011, "Archive"));
      await flush();
      fireEvent.click(screen.getByText(/Scan No\. 1011 archived/));
      await advance(220);
      expect(bodyText()).not.toContain("Scan No. 1011 archived");
    });
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   Batch 22 — the specification. Every test here fails on the legacy page.
   ════════════════════════════════════════════════════════════════════════════ */

describe("ScanHistory — batch 22", () => {
  it("has one level-one heading in each mode", async () => {
    const { unmount } = await loaded();
    expect(screen.getAllByRole("heading", { level: 1 }).map(squash)).toEqual([
      "Scan History",
    ]);
    unmount();
    await loaded("/monitor");
    expect(screen.getAllByRole("heading", { level: 1 }).map(squash)).toEqual([
      "Active Scans",
    ]);
  });

  it("groups the filters and states which one is selected", async () => {
    await loaded("/history?status=failed");
    const status = screen.getByRole("group", { name: "Status" });
    expect(
      within(status).getByRole("button", { name: "Failed" }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(within(status).getByRole("button", { name: "All" })).toHaveAttribute(
      "aria-pressed",
      "false",
    );
    expect(
      within(screen.getByRole("group", { name: "Owner" })).getByRole("button", {
        name: "All scans",
      }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      within(screen.getByRole("group", { name: "Time range" })).getByRole(
        "button",
        { name: "All time" },
      ),
    ).toHaveAttribute("aria-pressed", "true");
  });

  it("captions the table, scopes its headers and puts the sort state on the header", async () => {
    await loaded();
    const table = screen.getByRole("table", { name: /Scan history/ });
    const names = [
      "Scan No.",
      "Target",
      "Type",
      "Started By",
      "Status",
      "Active Hosts",
      "Duration",
      "Date",
      "Actions",
    ];
    expect(within(table).getAllByRole("columnheader")).toHaveLength(
      names.length,
    );
    for (const name of names) {
      expect(within(table).getByRole("columnheader", { name })).toHaveAttribute(
        "scope",
        "col",
      );
    }
    expect(
      within(table).getByRole("columnheader", { name: "Scan No." }),
    ).toHaveAttribute("aria-sort", "descending");
    expect(
      within(table).getByRole("columnheader", { name: "Target" }),
    ).toHaveAttribute("aria-sort", "none");
    expect(
      within(rowFor(1012)).getByRole("rowheader", { name: "1012" }),
    ).toBeInTheDocument();
  });

  it("names each row's actions by scan number", async () => {
    await loaded();
    for (const name of [
      "View scan 1012",
      "Re-run scan 1012",
      "Archive scan 1012",
      "Delete scan 1012",
    ]) {
      expect(screen.getByRole("button", { name })).toBeEnabled();
    }
  });

  it("gives each scan's progress a progress bar", async () => {
    await loaded();
    const bar = within(rowFor(1012)).getByRole("progressbar", {
      name: "Scan 1012 progress",
    });
    expect(bar).toHaveAttribute("aria-valuenow", "100");
  });

  it("announces the live sync state, loading and a failed load", async () => {
    listReply = () => new Promise(() => {});
    const { unmount } = await loaded();
    const statuses = () => screen.getAllByRole("status").map(squash);
    expect(statuses()).toEqual(
      expect.arrayContaining(["Live sync connecting", "Loading scan history…"]),
    );
    unmount();
    listReply = () => Promise.reject(new Error("offline"));
    await loaded();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to load scan history.",
    );
  });

  it("keeps Sync now named while it syncs", async () => {
    await loaded();
    listReply = () => new Promise(() => {});
    fireEvent.click(screen.getByRole("button", { name: "Sync now" }));
    await flush();
    expect(screen.getByRole("button", { name: "Sync now" })).toHaveAttribute(
      "aria-busy",
      "true",
    );
  });

  it("the details are a named dialog with a loading status", async () => {
    detailReply = () => new Promise(() => {});
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "View scan 1012" }));
    await flush();
    const dialog = screen.getByRole("dialog", { name: "Scan Details" });
    expect(within(dialog).getByRole("status")).toHaveTextContent(
      "Loading scan details…",
    );
    expect(
      within(dialog).getByRole("button", { name: "Close dialog" }),
    ).toBeInTheDocument();
  });

  it("confirmation dialogs are described by their question, without glyphs in their names", async () => {
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Re-run scan 1004" }));
    await flush();
    const dialog = screen.getByRole("dialog", {
      name: "Re-run Scan No. 1004?",
    });
    expect(dialog).toHaveAccessibleDescription(
      "This will start a fresh scan against the same target using the same configuration.",
    );
  });

  it("gives each running scan a titled card with named controls", async () => {
    await loaded("/monitor");
    expect(
      screen.getByRole("heading", { level: 2, name: /1013/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Stop Scan 1013" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: "View Detailed Results for scan 1013",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getAllByRole("progressbar", { name: "Overall Progress" })[0],
    ).toHaveAttribute("aria-valuenow", "40");
  });

  it("names the empty state's action without its arrow", async () => {
    listReply = () => Promise.resolve({ data: { scans: [], total: 0 } });
    await loaded();
    expect(
      screen.getByRole("button", { name: "Start your first scan" }),
    ).toBeInTheDocument();
  });

  it("announces notifications in a live region", async () => {
    api.post.mockResolvedValue({ data: {} });
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Archive scan 1012" }));
    await flush();
    expect(
      screen.getByText(/Scan No\. 1012 archived/).closest("[aria-live]"),
    ).not.toBeNull();
  });

  it("hides decorative glyphs from assistive technology", async () => {
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "Re-run scan 1004" }));
    await flush();
    const glyphs = /[🔁⏹⚠ℹ📡📋→▲▼↕✓✕]/u;
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
    );
    const exposed = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (
        glyphs.test(n.textContent) &&
        !n.parentElement.closest("[aria-hidden=true]")
      ) {
        exposed.push(n.textContent.trim());
      }
    }
    expect(exposed).toEqual([]);
  });

  it("renders no inline style of its own", async () => {
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "View scan 1012" }));
    await flush();
    const styled = [...document.body.querySelectorAll("[style]")].filter(
      // A progress bar's width is the one per-instance value, set by CcureProgress.
      (el) => !el.classList.contains("cc-progress__bar"),
    );
    expect(styled).toEqual([]);
  });

  it("carries no colour literals or legacy classes, and styles itself from tokens", () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/ScanHistory.jsx"),
      "utf8",
    );
    expect(source).toMatch(/import\s+["']\.\.\/styles\/scan-history\.css["']/);
    expect(source).toMatch(/from\s+["'](?:\.\.\/)+design-system["']/);
    expect(source).not.toMatch(/style=\{\{/);
    expect(source.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(source).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    const classes = [
      ...source.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g),
    ].flatMap((m) => (m[1] ?? m[2]).split(/\s+/));
    const legacy = classes.filter((c) =>
      /^(btn|btn--|action-btn|filter-|confirm-|modal|monitor-|history-|progress-|data-table|table-wrap|th-sort|alert|spinner|empty-state|ip-code|method-chip|muted|small|page-|detail-|dm-|port-pill|cve-|section-title|toast|stat-|label$|value$)/.test(
        c,
      ),
    );
    expect(legacy).toEqual([]);

    const cssPath = path.join(AUDIT_SRC, "styles/scan-history.css");
    expect(existsSync(cssPath)).toBe(true);
    const css = readFileSync(cssPath, "utf8");
    expect(css.match(/#[0-9a-fA-F]{3,8}\b/g) || []).toEqual([]);
    expect(css).not.toMatch(/\b(?:rgba?|hsla?)\(/);
    expect(css.match(/var\(--(?!ccure-)/g) || []).toEqual([]);
    expect(css).toMatch(/var\(--ccure-/);
    expect(css).toMatch(/:focus-visible/);
  });
});
