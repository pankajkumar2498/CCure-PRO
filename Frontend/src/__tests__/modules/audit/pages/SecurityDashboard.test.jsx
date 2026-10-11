/**
 * SecurityDashboard (`/audit-dashboard`; `/dashboard` redirects there) — Checkpoint 3C batch 17 baseline.
 *
 * Written against the page BEFORE migration. The regression block is the
 * gate every later change must keep passing; the batch 17 block is the
 * specification, and every test in it fails on the legacy page.
 *
 * ── The contract ───────────────────────────────────────────────────────────
 * The landing page reads and never writes. On mount it loads eleven panels
 * in parallel from `/dashboard/*`, then refreshes scan activity every 30
 * seconds. The notification centre (GET /notifications) or, with
 * `audit:read`, the audit timeline (GET /admin/audit-logs) loads alongside.
 * Choosing a date range reloads the same eleven panels with the same
 * parameters — the range is not sent.
 *
 * Permissions decide what is shown, never what is fetched:
 *   dashboard:read  — without it the page redirects to /scan
 *   assets:read     — Assets tab, top assets, inventory, services, TLS
 *   findings:read   — Vulnerabilities tab, top CVEs
 *   reports:read    — Compliance tab and panel, "Export PDF"
 *   audit:read      — Audit tab, audit timeline instead of notifications
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readFileSync } from "node:fs";
import path from "node:path";

import SecurityDashboard from "@audit/pages/SecurityDashboard";
import axiosInstance from "@shell/api/axiosInstance";
import { AUDIT_SRC } from "../../../testPaths";
import { keySetHolds } from "../../../fixtures/authorization";
import { personaFrom } from "../../../fixtures/authorization";

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

const navigate = vi.fn();
let location = { pathname: "/audit-dashboard", search: "", state: null };
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigate,
    useLocation: () => location,
    Link: ({ children, to, ...rest }) => (
      <a href={typeof to === "string" ? to : "#"} {...rest}>
        {children}
      </a>
    ),
  };
});

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({
    user: personaFrom({ username: "operator", id: 1, org_id: "o-1" }),
  }),
}));

let permissions;
vi.mock("@shell/auth/permissions", () => ({
  canPermission: (_u, p) => keySetHolds(permissions, p),
  can: (_u, r, a) => keySetHolds(permissions, r, a),
  denyMessage: "You do not have permission to perform this action.",
}));

/* Field names are the page's own reads. */
const SUMMARY = {
  severity: {
    critical: 12,
    high: 30,
    medium: 55,
    low: 20,
    info: 8,
    total: 125,
    deltas: { critical: 2, high: -1, medium: 0, low_info: 1 },
  },
  assets: {
    total: 42,
    new_24h: 2,
    risk_delta_7d: -3,
    avg_risk_score: 47,
    risk_level: "medium",
    unmanaged: 5,
  },
  scans: { running: 1, queued: 0, last_24h: 4, quota_limit_24h: 50 },
  kev: { open_count: 3 },
};

const CVES = [
  {
    id: "CVE-2026-1111",
    title: "Chrome use-after-free",
    cvss_v3_score: 9.8,
    priority_label: "P0",
    severity: "Critical",
    affected_assets: 3,
    in_kev: true,
  },
  {
    id: "CVE-2026-2222",
    title: "OpenSSL denial of service",
    cvss_v3_score: 7.5,
    priority_label: "P2",
    severity: "High",
    affected_assets: 1,
    in_kev: false,
  },
];

const BASE_ROUTES = {
  "/dashboard/summary": SUMMARY,
  "/dashboard/risk-breakdown": {
    priority_distribution: { p0_kev: 3, p2_cvss_9: 4 },
    finding_status: { open: 90, accepted: 20, fixed: 15 },
  },
  "/dashboard/top-assets": {
    assets: [
      {
        id: "a-1",
        ip_address: "10.180.5.10",
        hostname: "ws-01",
        os_name: "Windows 11 Pro",
        risk_score: 91,
        vuln_counts: { critical: 3, high: 5, medium: 9 },
        last_seen_at: "2026-09-10T10:00:00Z",
        is_managed: false,
      },
      {
        id: "a-2",
        ip_address: "10.180.5.11",
        hostname: "srv-02",
        os_family: "linux",
        risk_score: 44,
        vuln_counts: { critical: 0, high: 1, medium: 4 },
        last_seen_at: "2026-09-09T10:00:00Z",
        is_managed: true,
      },
    ],
  },
  "/dashboard/top-cves": { cves: CVES },
  "/dashboard/services-exposure": {
    services: [
      {
        port: 23,
        protocol: "tcp",
        service_name: "telnet",
        asset_count: 2,
        is_high_risk: true,
      },
      {
        port: 443,
        protocol: "tcp",
        service_name: "https",
        asset_count: 5,
        is_high_risk: false,
      },
    ],
  },
  "/dashboard/tls-health": {
    expiring_in_30d: 1,
    total_tls_services: 3,
    grade_distribution: { A: 1, C: 1, F: 1 },
  },
  "/dashboard/http-headers": {
    coverage: {
      strict_transport_security: { pct: 80 },
      content_security_policy: { pct: 30 },
    },
  },
  "/dashboard/compliance": {
    frameworks: [{ id: "iso27001", name: "ISO/IEC 27001", score: 72.4 }],
  },
  "/dashboard/asset-breakdown": {
    totals: { total: 42, managed: 37, unmanaged: 5, active: 40, offline: 2 },
    os_distribution: [
      { os_family: "Linux", count: 20 },
      { os_family: "Windows", count: 22 },
    ],
  },
  "/dashboard/scan-activity": {
    scans: [
      {
        id: "s-1",
        scan_type: "network",
        pipeline_mode: "vulnerability_audit",
        target_str: "10.180.6.0/24",
        status: "running",
        current_phase: "PORT_SCAN",
        progress_pct: 40,
        queued_at: "2026-09-12T09:55:00Z",
      },
      {
        id: "s-2",
        scan_type: "network",
        pipeline_mode: "basic",
        target_str: "10.180.5.0/24",
        status: "complete",
        active_hosts: 12,
        critical_count: 3,
        high_count: 5,
        queued_at: "2026-09-11T09:00:00Z",
      },
    ],
  },
  "/dashboard/insights": {
    insights: [
      {
        id: "i-1",
        severity: "high",
        icon: "⚠",
        title: "Cleartext telnet exposed",
        detail: "2 assets accept telnet connections.",
      },
    ],
  },
  "/admin/audit-logs": {
    logs: [
      {
        id: "l-1",
        action: "scan_started",
        username: "alice",
        resource_type: "scan",
        status: "success",
        created_at: "2026-09-12T09:00:00Z",
      },
    ],
  },
  "/notifications": {
    notifications: [
      {
        id: "n-1",
        type: "scan_completed",
        title: "Scan finished",
        message: "10.180.6.0/24",
        is_read: false,
        created_at: "2026-09-12T09:30:00Z",
      },
    ],
  },
};

const DASHBOARD_PANELS = [
  "/dashboard/summary",
  "/dashboard/risk-breakdown",
  "/dashboard/top-assets",
  "/dashboard/top-cves",
  "/dashboard/services-exposure",
  "/dashboard/tls-health",
  "/dashboard/http-headers",
  "/dashboard/compliance",
  "/dashboard/asset-breakdown",
  "/dashboard/scan-activity",
  "/dashboard/insights",
];

let routes = BASE_ROUTES;
const routeGet = (url) => {
  const u = String(url);
  return Object.prototype.hasOwnProperty.call(routes, u)
    ? Promise.resolve({ data: routes[u] })
    : Promise.resolve({ data: {} });
};

const callsTo = (p) =>
  axiosInstance.get.mock.calls.filter((c) => String(c[0]) === p);

const ANALYST = [
  "audit.dashboard.read",
  "audit.asset.read",
  "audit.finding.read",
  "audit.report.read",
];

const renderPage = async ({ ready = "Chrome use-after-free" } = {}) => {
  const r = render(<SecurityDashboard />);
  await screen.findByText(ready);
  return r;
};

/* The tab bar before (buttons) and after (tabs). */
const tabNames = (container) =>
  [...container.querySelectorAll('[role="tab"], button.db-tab')].map((t) =>
    (t.textContent || "").trim(),
  );
const tabNamed = (name) =>
  screen.queryByRole("tab", { name }) || screen.getByRole("button", { name });

/* A destination is reached either through a link (after) or a click handler
   that navigates (before). Either way the destination must be the same. */
const expectLeadsTo = async (user, element, destination) => {
  const link = element.closest("a");
  if (link) {
    expect(link.getAttribute("href")).toBe(destination);
  } else {
    await user.click(element);
    expect(navigate).toHaveBeenCalledWith(destination);
  }
};

beforeEach(() => {
  vi.clearAllMocks();
  navigate.mockReset();
  location = { pathname: "/audit-dashboard", search: "", state: null };
  permissions = new Set(ANALYST);
  routes = BASE_ROUTES;
  axiosInstance.get.mockImplementation(routeGet);
});

afterEach(() => {
  vi.useRealTimers();
});

/* ══════════════════════════════════════════════════════════════════════════
   REGRESSION — passes before and after batch 17
   ══════════════════════════════════════════════════════════════════════════ */
describe("SecurityDashboard — contract", () => {
  it("loads each of the eleven panels once on mount, with the page's parameters", async () => {
    await renderPage();
    await waitFor(() =>
      DASHBOARD_PANELS.forEach((p) => expect(callsTo(p)).toHaveLength(1)),
    );
    expect(callsTo("/dashboard/top-assets")[0][1]).toEqual({
      params: { limit: 10 },
    });
    expect(callsTo("/dashboard/top-cves")[0][1]).toEqual({
      params: { limit: 8, severity: "Critical,High" },
    });
    expect(callsTo("/dashboard/scan-activity")[0][1]).toEqual({
      params: { limit: 8 },
    });
    expect(callsTo("/dashboard/summary")[0][1]).toEqual({ params: {} });
  });

  it("never writes — not on load, not switching tabs, not choosing a date range", async () => {
    const user = userEvent.setup();
    await renderPage();
    for (const name of ["Assets", "Vulnerabilities", "Scans", "Compliance"]) {
      await user.click(tabNamed(name));
    }
    await user.click(tabNamed("Overview"));
    await user.click(screen.getByText(/Last 30 days/));
    await user.click(screen.getByRole("menuitem", { name: /Last 7 days/ }));
    await waitFor(() => expect(callsTo("/dashboard/summary")).toHaveLength(2));
    expect(axiosInstance.post).not.toHaveBeenCalled();
    expect(axiosInstance.put).not.toHaveBeenCalled();
    expect(axiosInstance.patch).not.toHaveBeenCalled();
    expect(axiosInstance.delete).not.toHaveBeenCalled();
  });

  it("reloads the same panels with the same parameters when a date range is chosen", async () => {
    const user = userEvent.setup();
    await renderPage();
    await user.click(screen.getByText(/Last 30 days/));
    await user.click(screen.getByRole("menuitem", { name: /Year to date/ }));
    await waitFor(() =>
      DASHBOARD_PANELS.forEach((p) => expect(callsTo(p)).toHaveLength(2)),
    );
    expect(callsTo("/dashboard/top-cves")[1][1]).toEqual({
      params: { limit: 8, severity: "Critical,High" },
    });
  });

  it("refreshes scan activity every 30 seconds, and nothing else", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<SecurityDashboard />);
    await waitFor(() =>
      expect(callsTo("/dashboard/scan-activity")).toHaveLength(1),
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    await waitFor(() =>
      expect(callsTo("/dashboard/scan-activity")).toHaveLength(2),
    );
    expect(callsTo("/dashboard/summary")).toHaveLength(1);
  });

  it("sends a user without dashboard:read to /scan", async () => {
    permissions = new Set(["audit.scan.read"]);
    render(<SecurityDashboard />);
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("/scan", { replace: true }),
    );
  });

  it("offers only the tabs the user may open", async () => {
    const all = await renderPage();
    expect(tabNames(all.container)).toEqual([
      "Overview",
      "Assets",
      "Vulnerabilities",
      "Scans",
      "Compliance",
    ]);
    all.unmount();

    permissions = new Set(["audit.dashboard.read"]);
    const restricted = render(<SecurityDashboard />);
    await screen.findByText("Informational only");
    expect(tabNames(restricted.container)).toEqual(["Overview", "Scans"]);
    expect(restricted.container.querySelectorAll("table")).toHaveLength(0);
    expect(screen.queryByText(/Compliance Posture/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Export PDF/)).not.toBeInTheDocument();
  });

  it("shows notifications without audit:read and the audit timeline with it", async () => {
    await renderPage();
    await screen.findByText("Scan finished");
    expect(callsTo("/notifications")[0][1]).toEqual({
      params: { limit: 5, unread_only: true },
    });
    expect(callsTo("/admin/audit-logs")).toHaveLength(0);
  });

  it("reads the audit timeline when the user holds audit:read", async () => {
    permissions = new Set([...ANALYST, "platform.audit_log.read"]);
    const { container } = await renderPage();
    await screen.findByText(/scan started/);
    expect(callsTo("/admin/audit-logs")[0][1]).toEqual({
      params: { limit: 6 },
    });
    expect(tabNames(container)).toContain("Audit");
  });

  it("states the posture: severity split, risk score and alerts", async () => {
    await renderPage();
    expect(screen.getByText("Critical 12 (10%)")).toBeInTheDocument();
    expect(screen.getByText(/12 Critical vulnerabilities/)).toBeInTheDocument();
    expect(screen.getByText(/3 CISA KEV-listed CVEs/)).toBeInTheDocument();
    expect(screen.getByText(/1 TLS certificate expiring/)).toBeInTheDocument();
    expect(screen.getByText(/Phase: PORT SCAN · 40%/)).toBeInTheDocument();
  });

  it("takes each metric card to its filtered list", async () => {
    const user = userEvent.setup();
    await renderPage();
    await expectLeadsTo(
      user,
      screen.getByText("Critical Findings"),
      "/vulnerabilities?severity=Critical",
    );
  });

  it("takes a top asset to its detail and a top CVE to its findings", async () => {
    const user = userEvent.setup();
    await renderPage();
    await expectLeadsTo(user, screen.getByText("10.180.5.10"), "/assets/a-1");
    navigate.mockReset();
    await expectLeadsTo(
      user,
      screen.getByText("Chrome use-after-free"),
      "/vulnerabilities?search=CVE-2026-1111",
    );
  });

  it("takes the critical alert to critical findings", async () => {
    const user = userEvent.setup();
    await renderPage();
    await expectLeadsTo(
      user,
      screen.getByText("View Now"),
      "/vulnerabilities?severity=Critical",
    );
  });

  it("offers Export PDF only with reports:read, and it opens reports", async () => {
    const user = userEvent.setup();
    await renderPage();
    await expectLeadsTo(user, screen.getByText(/Export PDF/), "/reports");
  });

  it("welcomes a new registration, and dismissing clears the router state", async () => {
    const user = userEvent.setup();
    location = { ...location, state: { isNewRegistration: true } };
    await renderPage();
    expect(screen.getByText("Welcome to CCure Audit PRO!")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Explore Dashboard/ }));
    expect(navigate).toHaveBeenCalledWith("/audit-dashboard", {
      replace: true,
      state: {},
    });
    expect(
      screen.queryByText("Welcome to CCure Audit PRO!"),
    ).not.toBeInTheDocument();
  });

  it("launching the first scan from the welcome closes it and opens /scan", async () => {
    const user = userEvent.setup();
    location = { ...location, state: { isNewRegistration: true } };
    await renderPage();
    await user.click(screen.getByRole("button", { name: /Launch First Scan/ }));
    expect(navigate).toHaveBeenLastCalledWith("/scan");
  });

  it("shows no welcome without the registration flag", async () => {
    await renderPage();
    expect(
      screen.queryByText("Welcome to CCure Audit PRO!"),
    ).not.toBeInTheDocument();
  });
});

/* ══════════════════════════════════════════════════════════════════════════
   BATCH 17 — every test here failed on the legacy page
   ══════════════════════════════════════════════════════════════════════════ */
describe("SecurityDashboard — batch 17", () => {
  it("names the page with a level-one heading", async () => {
    await renderPage();
    expect(
      screen.getByRole("heading", { level: 1, name: "Audit Dashboard" }),
    ).toBeInTheDocument();
  });

  it("gives every panel a heading", async () => {
    await renderPage();
    const names = screen
      .getAllByRole("heading", { level: 2 })
      .map((h) => h.textContent);
    for (const expected of [
      /Security Posture at a Glance/,
      /Org Risk Score/,
      /Findings by Severity/,
      /Live Scan Activity/,
      /Top Vulnerable Assets/,
      /Critical & High CVEs/,
      /Notification Center/,
      /Asset Inventory/,
      /Top Exposed Services/,
      /TLS & HTTP Security/,
      /Compliance Posture/,
    ]) {
      expect(names.some((n) => expected.test(n))).toBe(true);
    }
  });

  it("follows the tabs pattern, arrows included", async () => {
    const user = userEvent.setup();
    await renderPage();
    const tablist = screen.getByRole("tablist", { name: /dashboard/i });
    const overview = within(tablist).getByRole("tab", { name: "Overview" });
    expect(overview).toHaveAttribute("aria-selected", "true");
    overview.focus();
    await user.keyboard("{ArrowRight}");
    expect(
      within(tablist).getByRole("tab", { name: "Assets" }),
    ).toHaveAttribute("aria-selected", "true");
    expect(
      await screen.findByRole("heading", {
        name: /Asset Registry — Quick View/,
      }),
    ).toBeInTheDocument();
  });

  it("makes every metric card a link to its filtered list", async () => {
    await renderPage();
    const expected = {
      "Critical Findings": "/vulnerabilities?severity=Critical",
      "High Findings": "/vulnerabilities?severity=High",
      "Medium Findings": "/vulnerabilities?severity=Medium",
      "Low / Info": "/vulnerabilities?severity=Low,Info",
      "Assets Discovered": "/assets",
      "Scans (24h)": "/history",
      "Org Risk Score": "/assets",
      "Open CVEs (KEV)": "/vulnerabilities?in_kev=true",
    };
    for (const [label, href] of Object.entries(expected)) {
      const link = screen.getByRole("link", {
        name: new RegExp(`^${label.replace(/[()/]/g, "\\$&")}`),
      });
      expect(link).toHaveAttribute("href", href);
    }
  });

  it("reaches a top asset and a top CVE with real links", async () => {
    await renderPage();
    expect(
      screen.getByRole("link", { name: /10\.180\.5\.10/ }),
    ).toHaveAttribute("href", "/assets/a-1");
    expect(
      screen.getByRole("link", { name: "Chrome use-after-free" }),
    ).toHaveAttribute("href", "/vulnerabilities?search=CVE-2026-1111");
  });

  it("gives both tables a caption and scoped headers in full words", async () => {
    const { container } = await renderPage();
    const tables = [...container.querySelectorAll("table")];
    expect(tables).toHaveLength(2);
    for (const t of tables) {
      expect(t.querySelectorAll("caption")).toHaveLength(1);
      expect(t.firstElementChild.tagName).toBe("CAPTION");
      for (const th of t.querySelectorAll("thead th")) {
        expect(th).toHaveAttribute("scope", "col");
      }
    }
    const headers = [...tables[0].querySelectorAll("thead th")].map(
      (th) => th.textContent,
    );
    for (const word of ["Critical", "High", "Medium"]) {
      expect(headers.some((h) => h.includes(word))).toBe(true);
    }
  });

  it("makes the date range a disclosure that states its choice and closes on Escape", async () => {
    const user = userEvent.setup();
    await renderPage();
    const toggle = screen.getByRole("button", { name: /Date range/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(
      screen.getByRole("menuitem", { name: "Last 30 days" }),
    ).toHaveAttribute("aria-current", "true");
    expect(
      screen.getByRole("menuitem", { name: "Last 7 days" }),
    ).not.toHaveAttribute("aria-current");
    const menu = screen.getByRole("menu", { name: "Date range" });
    expect(menu.contains(document.activeElement)).toBe(true);
    await user.keyboard("{End}");
    expect(
      screen.getByRole("menuitem", { name: "Year to date" }),
    ).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveFocus();
  });

  it("presents the welcome as a modal dialog that Escape dismisses", async () => {
    const user = userEvent.setup();
    location = { ...location, state: { isNewRegistration: true } };
    await renderPage();
    const dialog = screen.getByRole("dialog", {
      name: /Welcome to CCure Audit PRO/,
    });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    await user.keyboard("{Escape}");
    expect(navigate).toHaveBeenCalledWith("/audit-dashboard", {
      replace: true,
      state: {},
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("renders a top CVE that carries no CVSS v3 score", async () => {
    // Same defect batch 16 fixed on the vulnerability browser: a v2-only CVE
    // hit `null.toFixed()` and took the landing page down.
    routes = {
      ...BASE_ROUTES,
      "/dashboard/top-cves": {
        cves: [
          ...CVES,
          {
            ...CVES[1],
            id: "CVE-2026-4444",
            title: "v2-only issue",
            cvss_v3_score: null,
          },
        ],
      },
    };
    await renderPage({ ready: "v2-only issue" });
    const cells = screen
      .getByText("v2-only issue")
      .closest("tr")
      .querySelectorAll("td");
    expect(cells[1].textContent.trim()).toBe("—");
  });

  it("names scan states in the application's vocabulary", async () => {
    // The legacy badge said "Done" and showed any unrecognised status as
    // "Queued" — a claim about a scan nobody made.
    await renderPage();
    expect(screen.getByText("Completed")).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("no longer depends on dashboard.css", async () => {
    const source = readFileSync(
      path.join(AUDIT_SRC, "pages/SecurityDashboard.jsx"),
      "utf8",
    );
    // The file segment must be exactly dashboard.css: the page's own
    // stylesheet is security-dashboard.css, which an unanchored pattern
    // matches.
    expect(source).not.toMatch(/import\s+["'](?:[^"']*\/)?dashboard\.css["']/);
    expect(source).toMatch(/import\s+["'][^"']*\/security-dashboard\.css["']/);
    const { container } = await renderPage();
    expect(container.querySelector("[class*='db-']")).toBeNull();
  });
});
