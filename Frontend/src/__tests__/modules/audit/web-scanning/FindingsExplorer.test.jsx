import { assertUx4gAdapters } from "../../../helpers/assertUx4gAdapters";
/**
 * FindingsExplorer — Checkpoint 3C batch 6 migration coverage.
 *
 * Written against the page BEFORE migration.
 *
 * ── Security contract ───────────────────────────────────────────────────────
 * This is the only page in the batch that changes state, and what it changes
 * is a **security finding's triage status**. Three properties matter:
 *
 *   * `updateFindingStatus(scanId, findingId, { status })` — the scan id comes
 *     from the route, the finding id from the row. Sending the wrong pairing
 *     would triage a finding belonging to a different scan.
 *   * A failed update must **not** move the row locally. The optimistic update
 *     is applied only after the request resolves, so a refused triage leaves
 *     the finding where it was rather than showing it as handled.
 *   * The detail panel renders `request_body`, `response_body` and
 *     `curl_command` — raw evidence captured from a target. It is rendered as
 *     text; nothing on this page may interpret it as markup. Asserted below,
 *     and it is the reason the module carries no `dangerouslySetInnerHTML`.
 *
 * Severity is the other load-bearing value. The pre-migration helper collapses
 * `critical` onto danger and `high` onto warning, which is precisely the
 * distinction `CcureSeverityBadge` was built at Checkpoint 3B to preserve.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import FindingsExplorer from "@audit/web-scanning/pages/FindingsExplorer";
import { webScansApi } from "@audit/web-scanning/api/webScansApi";
import { personaFrom } from "../../../fixtures/authorization";

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useParams: () => ({ id: "ws-42" }),
    // The page reads filters from the query string; return empty params so the
    // unfiltered list renders (the drill-down filtering is covered elsewhere).
    useSearchParams: () => [new URLSearchParams(""), vi.fn()],
    // The page renders a real <Link>, which needs a Router context. Stubbing
    // useParams alone left it in place and every test in this file died on
    // "Cannot destructure property 'basename'" — a defect in this harness, not
    // in the page.
    Link: ({ to, children, ...rest }) => (
      <a href={to} {...rest}>
        {children}
      </a>
    ),
  };
});

vi.mock("@audit/web-scanning/api/webScansApi", () => ({
  webScansApi: {
    getFindings: vi.fn(),
    updateFindingStatus: vi.fn(),
    getFindingScreenshot: vi.fn(() => Promise.resolve({ data: new Blob() })),
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

const FINDINGS = [
  {
    id: "f-1",
    title: "SQL injection in login form",
    severity: "critical",
    status: "open",
    request_method: "POST",
    request_url: "https://portal.example.test/login",
    finding_type: "sqli",
    owasp_category: "A03 Injection",
    cve_id: null,
    description: "Parameter `user` is concatenated into a query.",
    request_body: "user=admin'--&pass=x",
    response_body: "<html>SQL syntax error near</html>",
    curl_command:
      "curl -X POST 'https://portal.example.test/login' -d \"user=admin'--\"",
  },
  {
    id: "f-2",
    title: "Reflected XSS in search",
    severity: "high",
    status: "open",
    request_method: "GET",
    request_url: "https://portal.example.test/search?q=x",
    finding_type: "xss",
    owasp_category: "A03 Injection",
    cve_id: null,
    description: "Query parameter is reflected unescaped.",
  },
  {
    id: "f-3",
    title: "Missing HSTS header",
    severity: "low",
    status: "open",
    request_method: "GET",
    request_url: "https://portal.example.test/",
    finding_type: "header",
    owasp_category: "A05 Security Misconfiguration",
    cve_id: null,
    description: "Strict-Transport-Security is absent.",
  },
];

const ok = (findings = FINDINGS) =>
  Promise.resolve({ data: { data: findings } });

const renderPage = async () => {
  const result = render(<FindingsExplorer />);
  await waitFor(() => expect(webScansApi.getFindings).toHaveBeenCalled());
  return result;
};

beforeEach(() => {
  vi.clearAllMocks();
  webScansApi.getFindings.mockImplementation(() => ok());
  webScansApi.updateFindingStatus.mockResolvedValue({});
});

/* ══════════════════════════════════════════════════════════════════════════
   FUNCTIONAL
   ══════════════════════════════════════════════════════════════════════════ */
describe("FindingsExplorer — functional", () => {
  it("requests findings for the scan named in the route", async () => {
    await renderPage();
    expect(webScansApi.getFindings).toHaveBeenCalledWith("ws-42", {
      per_page: 200,
    });
  });

  it("renders one entry per finding", async () => {
    await renderPage();
    expect(
      await screen.findByText("SQL injection in login form"),
    ).toBeInTheDocument();
    expect(screen.getByText("Reflected XSS in search")).toBeInTheDocument();
    expect(screen.getByText("Missing HSTS header")).toBeInTheDocument();
  });

  it("accepts the `items` response shape as well as `data`", async () => {
    webScansApi.getFindings.mockResolvedValue({ data: { items: FINDINGS } });
    await renderPage();
    expect(
      await screen.findByText("SQL injection in login form"),
    ).toBeInTheDocument();
  });

  it("survives a failed load without crashing", async () => {
    webScansApi.getFindings.mockRejectedValue(new Error("network"));
    await renderPage();
    await waitFor(() =>
      expect(
        screen.queryByText("SQL injection in login form"),
      ).not.toBeInTheDocument(),
    );
  });

  it("opens the detail panel for the selected finding", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    expect(
      await screen.findByText(/parameter .?user.? is concatenated/i),
    ).toBeInTheDocument();
  });

  it("shows the OWASP category in the detail panel", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    expect(await screen.findByText(/A03 Injection/)).toBeInTheDocument();
  });

  it("shows the reproduction command when the finding carries one", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    expect(await screen.findByText(/curl -X POST/)).toBeInTheDocument();
  });

  it("does not poll", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<FindingsExplorer />);
      await waitFor(() =>
        expect(webScansApi.getFindings).toHaveBeenCalledTimes(1),
      );
      await vi.advanceTimersByTimeAsync(120000);
      expect(webScansApi.getFindings).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   SECURITY
   ══════════════════════════════════════════════════════════════════════════ */
describe("FindingsExplorer — security", () => {
  it("scopes the request to the route's scan id and nothing else", async () => {
    await renderPage();
    const [scanId, params] = webScansApi.getFindings.mock.calls[0];
    expect(scanId).toBe("ws-42");
    expect(Object.keys(params).sort()).toEqual(["per_page"]);
  });

  it("sends the triage change against the right scan and finding", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    const select = await screen.findByRole("combobox");
    await user.selectOptions(select, "false_positive");
    await waitFor(() =>
      expect(webScansApi.updateFindingStatus).toHaveBeenCalledWith(
        "ws-42",
        "f-1",
        { status: "false_positive" },
      ),
    );
  });

  it("does not move a finding locally when the triage request fails", async () => {
    webScansApi.updateFindingStatus.mockRejectedValue(new Error("403"));
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    const select = await screen.findByRole("combobox");
    await user.selectOptions(select, "false_positive");
    await waitFor(() =>
      expect(webScansApi.updateFindingStatus).toHaveBeenCalled(),
    );
    expect(select).toHaveValue("open");
  });

  it("renders captured response evidence as text, never as markup", async () => {
    /* `response_body` is whatever a scanned target returned. The fixture
       contains an <html> tag on purpose: it must appear as characters. */
    const user = userEvent.setup();
    const { container } = await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    await screen.findByText(/parameter .?user.? is concatenated/i);
    expect(container.querySelector("html, form, script")).toBeNull();
    expect(container.textContent).toMatch(/SQL syntax error near/);
  });

  it("renders the request body as text", async () => {
    const user = userEvent.setup();
    const { container } = await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    await screen.findByText(/parameter .?user.? is concatenated/i);
    expect(container.textContent).toMatch(/user=admin'--/);
  });

  it("keeps critical and high visually distinct", async () => {
    /* The pre-migration helper maps critical -> danger and high -> warning,
       which is a real distinction the migration must not collapse.
       The first version of this assertion climbed from the title with
       `.closest("div")` and landed on an inner flex wrapper shared by every
       row, so it compared two identical layout styles and failed against a
       page that draws the distinction correctly — a wrong assertion, not a
       defect. It now compares the element that actually carries the severity
       treatment: the badge bearing the severity word. */
    await renderPage();
    await screen.findByText("SQL injection in login form");
    const badge = (severity) => {
      const label = screen.getByText(new RegExp(`^${severity}$`, "i"));
      /* Climb to the element that carries the band. The label span itself has
         no class and no style in either implementation, so comparing it
         compared two empty strings — the same "closest() landed one level too
         shallow" mistake as before, not a page defect. */
      const el = label.closest(".cc-sev, .cc-badge, span[style]") || label;
      return (el.getAttribute("style") || "") + "|" + (el.className || "");
    };
    expect(badge("critical")).not.toBe(badge("high"));
    expect(badge("critical")).not.toBe(badge("low"));
  });

  it("names every severity in text, not by colour alone", async () => {
    await renderPage();
    const row = (
      await screen.findByText("SQL injection in login form")
    ).closest("div[style],div,li");
    expect(row.textContent).toMatch(/critical/i);
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   ACCESSIBILITY — the migration specification
   ══════════════════════════════════════════════════════════════════════════ */
describe("FindingsExplorer — accessibility", () => {
  it("makes every finding row reachable by keyboard", async () => {
    /* The rows are `<div onClick>`: no role, no tabIndex, no key handler. A
       keyboard user cannot open a single finding on this page. */
    await renderPage();
    await screen.findByText("SQL injection in login form");
    const rows = screen.getAllByRole("button", {
      name: /sql injection|xss|hsts/i,
    });
    expect(rows.length).toBe(3);
  });

  it("opens a finding with the keyboard", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("SQL injection in login form");
    const row = screen.getByRole("button", { name: /sql injection/i });
    row.focus();
    await user.keyboard("{Enter}");
    expect(
      await screen.findByText(/parameter .?user.? is concatenated/i),
    ).toBeInTheDocument();
  });

  it("reports which finding is currently selected", async () => {
    const user = userEvent.setup();
    await renderPage();
    await screen.findByText("SQL injection in login form");
    const row = screen.getByRole("button", { name: /sql injection/i });
    await user.click(row);
    await waitFor(() =>
      expect(
        row.getAttribute("aria-pressed") || row.getAttribute("aria-current"),
      ).toBeTruthy(),
    );
  });

  it("labels the triage control", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    const select = await screen.findByRole("combobox");
    expect(select).toHaveAccessibleName();
  });

  it("announces the loading state", async () => {
    let settle;
    webScansApi.getFindings.mockImplementation(
      () =>
        new Promise((r) => {
          settle = () => r({ data: { data: [] } });
        }),
    );
    render(<FindingsExplorer />);
    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent(/loading|finding/i);
    settle();
  });

  it("does not expose the loading placeholders to assistive technology", async () => {
    webScansApi.getFindings.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<FindingsExplorer />);
    await waitFor(() => expect(webScansApi.getFindings).toHaveBeenCalled());
    const shimmer = container.querySelectorAll(
      ".skeleton-loader, .cc-skeleton",
    );
    expect(shimmer.length).toBeGreaterThan(0);
    for (const el of shimmer) {
      expect(el.getAttribute("aria-hidden")).toBe("true");
    }
  });

  it("still tells the user when a triage change was refused", async () => {
    webScansApi.updateFindingStatus.mockRejectedValue(new Error("403"));
    const alertSpy = vi.spyOn(window, "alert").mockImplementation(() => {});
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    const select = await screen.findByRole("combobox");
    await user.selectOptions(select, "false_positive");
    await waitFor(() =>
      expect(webScansApi.updateFindingStatus).toHaveBeenCalled(),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Failed to update finding status.",
    );
    expect(alertSpy).not.toHaveBeenCalled();
    alertSpy.mockRestore();
  });

  it("does not skip a heading level", async () => {
    await renderPage();
    await screen.findByText("SQL injection in login form");
    const levels = screen
      .getAllByRole("heading")
      .map((h) => Number(h.tagName.slice(1)));
    const sorted = [...new Set(levels)].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    for (let i = 1; i < sorted.length; i += 1) {
      expect(sorted[i] - sorted[i - 1]).toBeLessThanOrEqual(1);
    }
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   RENDERED SURFACE
   ══════════════════════════════════════════════════════════════════════════ */
describe("FindingsExplorer — rendered surface", () => {
  it("carries no inline styles", async () => {
    const { container } = await renderPage();
    await screen.findByText("SQL injection in login form");
    const styled = [...container.querySelectorAll("[style]")].map((e) =>
      e.getAttribute("style"),
    );
    expect(styled).toEqual([]);
  });

  it("builds no colour value by concatenating onto a CSS variable", async () => {
    const { container } = await renderPage();
    await screen.findByText("SQL injection in login form");
    expect(container.innerHTML).not.toMatch(/var\(--[a-z-]+\)[0-9a-f]{2}/i);
  });

  it("carries no hardcoded colour literals", async () => {
    const { container } = await renderPage();
    await screen.findByText("SQL injection in login form");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(container.innerHTML).not.toMatch(/rgba?\(/i);
  });

  it("confines official UX4G classes to shared adapters", async () => {
    const { container } = await renderPage();
    await screen.findByText("SQL injection in login form");
    assertUx4gAdapters(container);
  });

  it("injects no <style> element into the document", async () => {
    webScansApi.getFindings.mockImplementation(() => new Promise(() => {}));
    const { container } = render(<FindingsExplorer />);
    await waitFor(() => expect(webScansApi.getFindings).toHaveBeenCalled());
    expect(container.querySelectorAll("style").length).toBe(0);
  });
});

describe("FindingsExplorer — permission (F2)", () => {
  afterEach(() => {
    authState.user = FULL_PERMISSION_USER;
  });

  it("shows the status read-only to a role without findings:update", async () => {
    authState.user = VIEWER_USER;
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.getByText("Update findings")).toBeInTheDocument();
  });

  it("does not let a role without findings:accept_risk accept a risk", async () => {
    authState.user = {
      role: { name: "triager" },
      permissionKeys: [
        "audit.scan.read",
        "audit.finding.read",
        "audit.finding.update",
      ],
    };
    const user = userEvent.setup();
    await renderPage();
    await user.click(await screen.findByText("SQL injection in login form"));
    const option = screen.getByRole("option", { name: /accepted risk/i });
    expect(option).toBeDisabled();
    expect(option.textContent).toMatch(/requires findings:accept_risk/i);
    expect(
      screen.getByRole("option", { name: /false positive/i }),
    ).toBeEnabled();
  });
});
