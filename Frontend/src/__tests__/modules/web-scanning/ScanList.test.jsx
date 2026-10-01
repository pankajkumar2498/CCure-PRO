/**
 * ScanList — Checkpoint 3C batch 6 migration coverage.
 *
 * Written against the page BEFORE migration. The functional, security and
 * rendered-surface groups record the contract and must pass identically before
 * and after; the accessibility group is the migration's specification and
 * contains assertions that fail against the current implementation.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * This is the index of DAST scans. CLAUDE.md records what `/web-scans` does:
 * it sends ffuf and nuclei at a caller-named target, which is why the route
 * carries its own rate limit. This page starts none of that — it lists — but
 * two properties still matter:
 *
 *   * `getScans({ per_page: 100 })` is the whole request. No filter, no scope
 *     parameter, no org id is added client-side; the API decides what this
 *     account may see. A page that started narrowing server results locally
 *     would be inventing an authorisation boundary in the browser.
 *   * A scan's *status* must be reported as what it is. The pre-migration
 *     `getStatusColor` falls through to `var(--text-muted)` for anything it
 *     does not recognise, which is at least honest — but the badge it builds
 *     is broken (see the rendered-surface group).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ScanList from "../../../modules/web-scanning/pages/ScanList";
import { webScansApi } from "../../../modules/web-scanning/api/webScansApi";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("../../../modules/web-scanning/api/webScansApi", () => ({
  webScansApi: { getScans: vi.fn() },
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
vi.mock("@shell/auth/AuthContext", () => ({
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

const SCANS = [
  {
    id: "ws-1",
    scan_name: "Corporate portal",
    target_url: "https://portal.example.test",
    status: "complete",
    pipeline_phase: "reporting",
    critical_count: 2,
    high_count: 3,
    created_at: "2026-08-01T10:00:00Z",
  },
  {
    id: "ws-2",
    scan_name: "Staging API",
    target_url: "https://api.staging.example.test",
    status: "running",
    pipeline_phase: "fuzzing",
    critical_count: 0,
    high_count: 0,
    created_at: "2026-08-02T11:00:00Z",
  },
  {
    id: "ws-3",
    scan_name: "Legacy intranet",
    target_url: "https://intranet.example.test",
    status: "failed",
    pipeline_phase: null,
    critical_count: 0,
    high_count: 1,
    created_at: "2026-08-03T12:00:00Z",
  },
  {
    id: "ws-4",
    scan_name: "Marketing site",
    target_url: "https://www.example.test",
    // Recognised by neither the local helper nor CcureScanStatus.
    status: "reaped",
    pipeline_phase: null,
    critical_count: 0,
    high_count: 0,
    created_at: "2026-08-04T12:00:00Z",
  },
];

const ok = (scans = SCANS) => Promise.resolve({ data: { data: scans } });

const renderPage = async () => {
  const result = render(<ScanList />);
  await waitFor(() => expect(webScansApi.getScans).toHaveBeenCalled());
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  webScansApi.getScans.mockImplementation(() => ok());
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanList — functional", () => {
  it("requests scans with per_page 100 and nothing else", async () => {
    await renderPage();
    expect(webScansApi.getScans).toHaveBeenCalledWith({ per_page: 100 });
    expect(webScansApi.getScans).toHaveBeenCalledTimes(1);
  });

  it("renders one row per scan", async () => {
    await renderPage();
    expect(await screen.findByText("Corporate portal")).toBeInTheDocument();
    expect(screen.getByText("Staging API")).toBeInTheDocument();
    expect(screen.getByText("Legacy intranet")).toBeInTheDocument();
    expect(screen.getByText("Marketing site")).toBeInTheDocument();
  });

  it("renders each scan's target URL", async () => {
    await renderPage();
    expect(
      await screen.findByText("https://portal.example.test"),
    ).toBeInTheDocument();
  });

  it("accepts the `items` response shape as well as `data`", async () => {
    webScansApi.getScans.mockResolvedValue({ data: { items: SCANS } });
    await renderPage();
    expect(await screen.findByText("Corporate portal")).toBeInTheDocument();
  });

  it("renders an empty state when there are no scans", async () => {
    webScansApi.getScans.mockResolvedValue({ data: { data: [] } });
    await renderPage();
    expect(await screen.findByText(/no web scans found/i)).toBeInTheDocument();
  });

  it("survives a failed load without crashing", async () => {
    webScansApi.getScans.mockRejectedValue(new Error("network"));
    await renderPage();
    expect(await screen.findByText(/no web scans found/i)).toBeInTheDocument();
  });

  it("renders a dash for a scan with no pipeline phase", async () => {
    await renderPage();
    const row = (await screen.findByText("Legacy intranet")).closest("tr");
    expect(within(row).getAllByText("-").length).toBeGreaterThan(0);
  });

  it("navigates to the new-scan form", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /new scan/i }));
    expect(navigate).toHaveBeenCalledWith("/web-scans/new");
  });

  it("navigates to a scan from its name", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("Corporate portal"));
    expect(navigate).toHaveBeenCalledWith("/web-scans/ws-1");
  });

  it("navigates to a scan from its View action", async () => {
    const user = userEvent.setup();
    await renderPage();
    const row = (await screen.findByText("Staging API")).closest("tr");
    await user.click(within(row).getByRole("button", { name: /view/i }));
    expect(navigate).toHaveBeenCalledWith("/web-scans/ws-2");
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<ScanList />);
      await waitFor(() =>
        expect(webScansApi.getScans).toHaveBeenCalledTimes(1),
      );
      await vi.advanceTimersByTimeAsync(120000);
      expect(webScansApi.getScans).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanList — security", () => {
  it("adds no scope, org or filter parameter of its own", async () => {
    await renderPage();
    const [params] = webScansApi.getScans.mock.calls[0];
    expect(Object.keys(params).sort()).toEqual(["per_page"]);
  });

  it("shows the finding counts a scan reported, without inventing any", async () => {
    /* Anchored on the count AND the band name rather than on the old "2 C"
       string. That abbreviation is exactly what the accessibility group
       requires this page to stop using, so an assertion pinned to it would
       have contradicted the migration it was written to specify. Requiring
       both parts is stricter than the original. */
    await renderPage();
    const row = (await screen.findByText("Corporate portal")).closest("tr");
    const cell = row.querySelectorAll("td, th")[4];
    expect(cell.textContent).toMatch(/2/);
    expect(cell.textContent).toMatch(/critical/i);
    expect(cell.textContent).toMatch(/3/);
    expect(cell.textContent).toMatch(/high/i);
  });

  it("does not render a zero count as a finding", async () => {
    await renderPage();
    const row = (await screen.findByText("Staging API")).closest("tr");
    expect(within(row).queryByText(/0 C/)).not.toBeInTheDocument();
    expect(within(row).queryByText(/0 H/)).not.toBeInTheDocument();
  });

  it("renders a high count even when critical is zero", async () => {
    await renderPage();
    const row = (await screen.findByText("Legacy intranet")).closest("tr");
    const cell = row.querySelectorAll("td, th")[4];
    expect(cell.textContent).toMatch(/1/);
    expect(cell.textContent).toMatch(/high/i);
    expect(cell.textContent).not.toMatch(/critical/i);
  });

  it("renders a target URL as text, never as a live link", async () => {
    // The target is attacker-influenced: it is whatever URL someone asked the
    // scanner to hit. Rendering it as a followable link invites a click
    // straight at it from inside the console.
    await renderPage();
    const row = (await screen.findByText("Corporate portal")).closest("tr");
    expect(within(row).queryByRole("link")).not.toBeInTheDocument();
  });

  it("does not present an unrecognised status as a known one", async () => {
    await renderPage();
    const unknown = (await screen.findByText("Marketing site")).closest("tr");
    const running = screen.getByText("Staging API").closest("tr");
    const cellOf = (row) => {
      const cell = row.querySelectorAll("td, th")[2];
      const el = cell.querySelector("span") || cell;
      return `${el.getAttribute("style") || ""}|${el.className || ""}`;
    };
    expect(cellOf(unknown)).not.toBe(cellOf(running));
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanList — accessibility", () => {
  it("gives the table an accessible name", async () => {
    await renderPage();
    expect(await screen.findByRole("table")).toHaveAccessibleName();
  });

  it("scopes every column header", async () => {
    await renderPage();
    await screen.findByText("Corporate portal");
    const headers = document.querySelectorAll("thead th");
    expect(headers.length).toBeGreaterThan(0);
    for (const th of headers) {
      expect(th.getAttribute("scope")).toBe("col");
    }
  });

  it("marks the scan name as its row's header", async () => {
    await renderPage();
    await screen.findByText("Corporate portal");
    expect(document.querySelectorAll('tbody th[scope="row"]').length).toBe(4);
  });

  it("disambiguates the per-row View control", async () => {
    await renderPage();
    await screen.findByText("Corporate portal");
    const names = screen
      .getAllByRole("button", { name: /view/i })
      .map((b) => b.getAttribute("aria-label") || b.textContent.trim());
    expect(new Set(names).size).toBe(names.length);
  });

  it("announces the loading state", async () => {
    let settle;
    webScansApi.getScans.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ data: { data: [] } });
        }),
    );
    render(<ScanList />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading|scan/i);
    settle();
  });

  it("does not expose the loading placeholders to assistive technology", async () => {
    webScansApi.getScans.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<ScanList />);
    await waitFor(() => expect(webScansApi.getScans).toHaveBeenCalled());
    const shimmer = container.querySelectorAll(
      ".skeleton-loader, .cc-skeleton",
    );
    expect(shimmer.length).toBeGreaterThan(0);
    for (const el of shimmer) {
      expect(el.getAttribute("aria-hidden")).toBe("true");
    }
  });

  it("renders the finding counts with a text label, not a letter alone", async () => {
    // "2 C" and "3 H" are announced as "two see" and "three aitch".
    await renderPage();
    const row = (await screen.findByText("Corporate portal")).closest("tr");
    const cell = row.querySelectorAll("td, th")[4];
    expect(cell.textContent).toMatch(/critical/i);
    expect(cell.textContent).toMatch(/high/i);
  });

  it("keeps exactly one page heading", async () => {
    await renderPage();
    expect(
      screen.getAllByRole("heading", { name: /^web scans$/i }).length,
    ).toBe(1);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("ScanList — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("Corporate portal");
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("builds no colour value by concatenating onto a CSS variable", async () => {
    /* `${getStatusColor(s)}40` produces `var(--ok)40`, which is not a colour.
       The browser drops the whole declaration, so the status badge silently
       has no border and no background. It looks like a styling choice and is
       a bug. */
    const { container } = await renderPage();
    await screen.findByText("Corporate portal");
    expect(container.innerHTML).not.toMatch(/var\(--[a-z-]+\)[0-9a-f]{2}/i);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("Corporate portal");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("Corporate portal");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("renders one row per scan and no more", async () => {
    await renderPage();
    await screen.findByText("Corporate portal");
    expect(document.querySelectorAll("tbody tr").length).toBe(4);
  });

  it("injects no <style> element into the document", async () => {
    // The legacy Skeleton ships a <style> block per instance, so a page with
    // four of them carries four copies of the same @keyframes.
    webScansApi.getScans.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<ScanList />);
    await waitFor(() => expect(webScansApi.getScans).toHaveBeenCalled());
    expect(container.querySelectorAll("style").length).toBe(0);
  });
});

describe("ScanList — permission (F2)", () => {
  afterEach(() => {
    authState.user = FULL_PERMISSION_USER;
  });

  it("offers New Scan to a role holding scans:execute", async () => {
    await renderPage();
    expect(
      screen.getByRole("button", { name: /new scan/i }),
    ).toBeInTheDocument();
  });

  it("does not offer New Scan to a role without scans:execute", async () => {
    authState.user = VIEWER_USER;
    await renderPage();
    expect(screen.queryByRole("button", { name: /new scan/i })).toBeNull();
  });
});
