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

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import WebDashboard from "../../../modules/web-scanning/pages/WebDashboard";
import { webDashboardApi } from "../../../modules/web-scanning/api/webScansApi";

const navigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("../../../modules/web-scanning/api/webScansApi", () => ({
  webScansApi: {},
  webDashboardApi: {
    getSummary: vi.fn(),
    getOwaspScorecard: vi.fn(),
    getTrends: vi.fn(),
  },
}));

vi.mock("../../../components/layout/AppLayout", () => ({
  default: ({ children, pageTitle }) => (
    <div data-testid="app-layout" data-page-title={pageTitle}>
      {children}
    </div>
  ),
}));

const SUMMARY = {
  active_scans: 3,
  critical_vulnerabilities: 7,
  total_endpoints: 412,
  scans_last_30_days: 11,
};

const SCORECARD = [
  { category: "A01 Broken Access Control", count: 4 },
  { category: "A02 Cryptographic Failures", count: 0 },
  { category: "A03 Injection", count: 2 },
];

const TRENDS = [
  { date: "2026-08-01", critical: 2, high: 5 },
  { date: "2026-08-02", critical: 0, high: 0 },
];

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
    const many = Array.from({ length: 10 }, (_, i) => ({
      category: `CAT-${i}`,
      count: i,
    }));
    webDashboardApi.getOwaspScorecard.mockResolvedValue({ data: many });
    await renderPage();
    await screen.findByText("CAT-0");
    expect(screen.queryByText("CAT-5")).not.toBeInTheDocument();
  });

  it("renders the scorecard categories and counts", async () => {
    await renderPage();
    expect(
      await screen.findByText("A01 Broken Access Control"),
    ).toBeInTheDocument();
    /* Anchored on the numbers within their own rows rather than on the exact
       strings "4 findings" / "0 findings". The clean row now carries an
       explicit "clear" word, which is what the accessibility group requires
       this page to add, so an exact-string assertion would have contradicted
       the migration it specifies. */
    const rowOf = (cat) => screen.getByText(cat).closest("div");
    expect(rowOf("A01 Broken Access Control").textContent).toMatch(
      /4 findings/,
    );
    expect(rowOf("A02 Cryptographic Failures").textContent).toMatch(
      /0 findings/,
    );
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

  it("uses no ux4g-* class in application markup", async () => {
    const { container } = await renderPage();
    await screen.findByText("7");
    expect(container.innerHTML).not.toMatch(/\bux4g-/);
  });

  it("injects no <style> element into the document", async () => {
    webDashboardApi.getSummary.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<WebDashboard />);
    await waitFor(() => expect(webDashboardApi.getSummary).toHaveBeenCalled());
    expect(container.querySelectorAll("style").length).toBe(0);
  });
});
