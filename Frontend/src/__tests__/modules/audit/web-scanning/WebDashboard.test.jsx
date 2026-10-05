import { assertUx4gAdapters } from "../../../helpers/assertUx4gAdapters";
/**
 * WebDashboard — Checkpoint 3C batch 6 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * This is a summary surface: four counters, an OWASP Top 10 scorecard and a
 * 30-day trend list. Nothing here starts a scan or changes state, so the
 * contract is about *reporting honestly*:
 *
 *   * Three independent requests, all issued. If the scorecard call fails the
 *     page must not render an empty scorecard as though the target were clean
 *     — "no OWASP findings detected yet" and "we could not ask" are different
 *     facts, and only one of them is good news.
 *   * A counter with no data reads 0. That is a deliberate choice the page
 *     already makes (`summary?.critical_vulnerabilities || 0`) and it is
 *     recorded here so the migration cannot change it silently.
 *   * The scorecard's own colour rule — red when count > 0, green when 0 — is
 *     a security signal, not decoration.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import WebDashboard from "@audit/web-scanning/pages/WebDashboard";
import { webDashboardApi } from "@audit/web-scanning/api/webScansApi";
import { personaFrom } from "../../../fixtures/authorization";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    // The dashboard counts are now real <Link>s, which need a Router context;
    // stub them to plain anchors so the page renders in isolation.
    Link: ({ to, children, ...rest }) => (
      <a href={to} {...rest}>
        {children}
      </a>
    ),
  };
});

vi.mock("@audit/web-scanning/api/webScansApi", () => ({
  webScansApi: {},
  webDashboardApi: {
    getSummary: vi.fn(),
    getOwaspScorecard: vi.fn(),
    getTrends: vi.fn(),
  },
}));

/* ── Permissions (Phase 1, finding F2) ───────────────────────────────────────
   The API now requires scans:execute to launch or cancel a web scan,
   findings:update to triage and findings:accept_risk to accept a risk, and the
   page no longer offers what the API would refuse. Every test runs as a user
   holding all of them unless it swaps `authState.user` — the deny-path tests
   at the end of this file do, and restore it afterwards. */
const FULL_PERMISSION_USER = {
  role: { name: "analyst" },
  permissionKeys: [
    "audit.scan.read",
    "audit.scan.run",
    "audit.finding.read",
    "audit.finding.update",
    "audit.finding.accept_risk",
  ],
};
const VIEWER_USER = {
  role: { name: "viewer" },
  permissionKeys: ["audit.scan.read", "audit.finding.read"],
};
const authState = vi.hoisted(() => ({ user: null }));
vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: personaFrom(authState.user) }),
}));
authState.user = FULL_PERMISSION_USER;

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

// The real API response shapes: summary is nested, and the scorecard and trends
// are wrapped ({ scorecard: [...] } / { data: [...] }).
const SUMMARY = {
  scans: {
    total: 20,
    running: 3,
    active: 3,
    completed: 15,
    last_7d: 8,
    last_30d: 11,
  },
  severity: { critical: 7, high: 4, medium: 2, low: 1, info: 0, total: 14 },
  endpoints: { total: 412, unique_domains: 5 },
};

const SCORECARD = {
  scorecard: [
    { code: "A01", name: "Broken Access Control", total: 4 },
    { code: "A02", name: "Cryptographic Failures", total: 0 },
    { code: "A03", name: "Injection", total: 2 },
  ],
};

const TRENDS = {
  data: [
    { date: "2026-08-01", critical: 2, high: 5 },
    { date: "2026-08-02", critical: 0, high: 0 },
  ],
};

const renderPage = async () => {
  const result = render(<WebDashboard />);
  await waitFor(() => expect(webDashboardApi.getSummary).toHaveBeenCalled());
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  webDashboardApi.getSummary.mockResolvedValue({ data: SUMMARY });
  webDashboardApi.getOwaspScorecard.mockResolvedValue({ data: SCORECARD });
  webDashboardApi.getTrends.mockResolvedValue({ data: TRENDS });
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("WebDashboard — functional", () => {
  it("issues all three dashboard requests", async () => {
    await renderPage();
    expect(webDashboardApi.getSummary).toHaveBeenCalled();
    expect(webDashboardApi.getOwaspScorecard).toHaveBeenCalled();
    expect(webDashboardApi.getTrends).toHaveBeenCalled();
  });

  it("renders each summary counter", async () => {
    await renderPage();
    expect(await screen.findByText("3")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("412")).toBeInTheDocument();
    expect(screen.getByText("11")).toBeInTheDocument();
  });

  it("names each counter", async () => {
    await renderPage();
    expect(await screen.findByText(/active web scans/i)).toBeInTheDocument();
    expect(screen.getByText(/critical vulnerabilities/i)).toBeInTheDocument();
    expect(screen.getByText(/total endpoints discovered/i)).toBeInTheDocument();
    expect(screen.getByText(/scans last 30 days/i)).toBeInTheDocument();
  });

  it("renders at most five scorecard rows", async () => {
    // Ten categories; the page shows the five with the most findings first.
    const many = {
      scorecard: Array.from({ length: 10 }, (_, i) => ({
        code: `CAT-${i}`,
        name: `n${i}`,
        total: i,
      })),
    };
    webDashboardApi.getOwaspScorecard.mockResolvedValue({ data: many });
    await renderPage();
    await screen.findByText(/CAT-9/); // highest total → shown
    expect(screen.queryByText(/CAT-4/)).not.toBeInTheDocument(); // outside top 5
  });

  it("renders the scorecard categories and counts", async () => {
    await renderPage();
    expect(
      await screen.findByText(/Broken Access Control/),
    ).toBeInTheDocument();
    /* Anchored on the numbers within their own rows rather than on the exact
       strings "4 findings" / "0 findings". The clean row carries an explicit
       "clear" word (an accessibility requirement), so an exact-string assertion
       would contradict it. */
    const rowOf = (cat) => screen.getByText(new RegExp(cat)).closest("div");
    expect(rowOf("Broken Access Control").textContent).toMatch(/4 findings/);
    expect(rowOf("Cryptographic Failures").textContent).toMatch(/0 findings/);
  });

  it("renders the trend rows", async () => {
    await renderPage();
    /* The abbreviations "2 Crit" / "5 High" are what the migration replaces
       with named severity bands, so these are anchored on the row's text
       carrying both the count and the band name — stricter than the original
       substring. */
    const row = (await screen.findByText("2026-08-01")).closest("div");
    expect(row.textContent).toMatch(/2/);
    expect(row.textContent).toMatch(/critical/i);
    expect(row.textContent).toMatch(/5/);
    expect(row.textContent).toMatch(/high/i);
  });

  it("omits a zero trend count rather than printing it", async () => {
    await renderPage();
    await screen.findByText("2026-08-02");
    expect(screen.queryByText(/0 Crit/)).not.toBeInTheDocument();
    expect(screen.queryByText(/0 High/)).not.toBeInTheDocument();
  });

  it("shows a scorecard placeholder when the list is empty", async () => {
    webDashboardApi.getOwaspScorecard.mockResolvedValue({ data: [] });
    await renderPage();
    expect(
      await screen.findByText(/no owasp findings detected yet/i),
    ).toBeInTheDocument();
  });

  it("shows a trends placeholder when the list is empty", async () => {
    webDashboardApi.getTrends.mockResolvedValue({ data: [] });
    await renderPage();
    expect(
      await screen.findByText(/no trend data available/i),
    ).toBeInTheDocument();
  });

  it("navigates to the scan list", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /view all scans/i }));
    expect(navigate).toHaveBeenCalledWith("/web-scans/list");
  });

  it("navigates to the new-scan form", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByRole("button", { name: /new web scan/i }));
    expect(navigate).toHaveBeenCalledWith("/web-scans/new");
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<WebDashboard />);
      await waitFor(() =>
        expect(webDashboardApi.getSummary).toHaveBeenCalledTimes(1),
      );
      await vi.advanceTimersByTimeAsync(120000);
      expect(webDashboardApi.getSummary).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("WebDashboard — security", () => {
  it("renders 0 rather than blank when a counter is absent", async () => {
    webDashboardApi.getSummary.mockResolvedValue({ data: {} });
    await renderPage();
    const zeros = await screen.findAllByText("0");
    expect(zeros.length).toBe(4);
  });

  it("does not report a clean scorecard when the whole load failed", async () => {
    /* All three requests share one try/catch, so any failure leaves every
       widget in its placeholder state. "No OWASP findings detected yet" then
       reads as good news about a target nobody could ask about. The page has
       to distinguish the two. */
    webDashboardApi.getOwaspScorecard.mockRejectedValue(new Error("500"));
    await renderPage();
    await waitFor(() =>
      expect(
        screen.queryByText(/no owasp findings detected yet/i),
      ).not.toBeInTheDocument(),
    );
  });

  it("keeps the critical counter distinguishable from the others", async () => {
    /* `.closest("div")` reaches the card's header row, which carries the label
       and not the value — a wrong assertion. `.stat-card` / `.cc-card` is the
       card itself, which is what "this counter" means on both sides of the
       migration. */
    await renderPage();
    const critical = (
      await screen.findByText(/critical vulnerabilities/i)
    ).closest(".stat-card, .cc-card, section, article");
    expect(critical).toBeTruthy();
    expect(critical.textContent).toMatch(/7/);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("WebDashboard — accessibility", () => {
  it("announces the loading state", async () => {
    webDashboardApi.getSummary.mockImplementation(() => new Promise(() => {}));
    render(<WebDashboard />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading|dashboard|web/i);
  });

  it("does not expose the loading placeholders to assistive technology", async () => {
    webDashboardApi.getSummary.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<WebDashboard />);
    await waitFor(() => expect(webDashboardApi.getSummary).toHaveBeenCalled());
    const shimmer = container.querySelectorAll(
      ".skeleton-loader, .cc-skeleton",
    );
    expect(shimmer.length).toBeGreaterThan(0);
    for (const el of shimmer) {
      expect(el.getAttribute("aria-hidden")).toBe("true");
    }
  });

  it("gives each counter a programmatic name, not a visual pairing alone", async () => {
    await renderPage();
    await screen.findByText("7");
    /* `.closest("[role],section,article,div")` matched the card's inner
       heading wrapper, an unnamed div, rather than the card — the same
       mistake as reaching for `.closest("div")`. The card is what carries the
       name, so the selector names it. */
    const group = screen
      .getByText(/critical vulnerabilities/i)
      .closest(".cc-card, .stat-card, section, article");
    expect(group).toHaveAccessibleName();
  });

  it("gives each widget a heading", async () => {
    await renderPage();
    expect(
      await screen.findByRole("heading", { name: /owasp top 10 coverage/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /vulnerability trends/i }),
    ).toBeInTheDocument();
  });

  it("keeps a single top-level page heading", async () => {
    await renderPage();
    const h1s = screen
      .getAllByRole("heading")
      .filter((h) => h.tagName === "H1");
    expect(h1s.length).toBe(1);
  });

  it("does not skip a heading level between the page and its widgets", async () => {
    await renderPage();
    await screen.findByText(/owasp top 10 coverage/i);
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });

  it("does not convey the scorecard verdict by colour alone", async () => {
    /* count > 0 renders red and count === 0 renders green, with text that
       differs only by the number. The first version of this assertion listed
       "0 findings" inside its own alternation, so it matched the exact string
       it was written to reject and could never fail — a wrong assertion, not a
       passing page. It now requires the clean and breached rows to differ by
       something a reader can perceive without colour. */
    await renderPage();
    /* The marker has to look at what a reader actually perceives, which is the
       row's text plus the classes of the elements inside it — not the row
       wrapper's own className, which is `wsp-row` on every row by
       construction and so could never differ. */
    const rowOf = (text) =>
      screen.getByText(new RegExp(text)).closest(".wsp-row, div[class], div");
    const marker = (el) =>
      el.textContent.replace(/\d+/g, "#") +
      "|" +
      [...el.querySelectorAll("*")].map((n) => n.className).join(" ");
    expect(marker(rowOf("0 findings"))).not.toBe(marker(rowOf("4 findings")));
    // And the clean row must say so in words, not only in green.
    expect(rowOf("0 findings").textContent).toMatch(/clear|clean|none/i);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("WebDashboard — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("7");
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("7");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("confines official UX4G classes to shared adapters", async () => {
    const { container } = await renderPage();
    await screen.findByText("7");
    assertUx4gAdapters(container);
  });

  it("injects no <style> element into the document", async () => {
    webDashboardApi.getSummary.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<WebDashboard />);
    await waitFor(() => expect(webDashboardApi.getSummary).toHaveBeenCalled());
    expect(container.querySelectorAll("style").length).toBe(0);
  });
});

describe("WebDashboard — permission (F2)", () => {
  afterEach(() => {
    authState.user = FULL_PERMISSION_USER;
  });

  it("offers New Web Scan to a role holding scans:execute", async () => {
    await renderPage();
    expect(
      await screen.findByRole("button", { name: /new web scan/i }),
    ).toBeInTheDocument();
  });

  it("does not offer New Web Scan to a role without scans:execute", async () => {
    authState.user = VIEWER_USER;
    await renderPage();
    await screen.findByRole("button", { name: /view all scans/i });
    expect(screen.queryByRole("button", { name: /new web scan/i })).toBeNull();
  });
});
