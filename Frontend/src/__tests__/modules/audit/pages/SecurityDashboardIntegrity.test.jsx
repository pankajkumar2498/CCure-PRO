/**
 * P0-2 and P0-3 — the dashboard states only what the backend measured.
 *
 * Two defects the field-level audit found, both of which rendered plausibly:
 *
 * * **P0-2.** "Org Risk Score" carried four bars labelled CVE CVSS, Port risk,
 *   HTTP hdrs and TLS grade, computed as `score * 0.72`, `* 0.55`, `* 0.38`
 *   and `* 0.6` — constants multiplied by the one score, presented as a
 *   component breakdown of it. The API publishes no such breakdown. It does
 *   publish `http_avg_security_score` and four `tls_issues` counts on the same
 *   endpoint, and both were ignored.
 *
 * * **P0-3.** The findings donut omitted `unscored` while dividing by
 *   `severity.total`, which includes it. Measured live: 370+2102+2063+193+2 =
 *   4730 against a total of 4740 — ten findings' worth of arc missing with
 *   nothing saying why.
 *
 * The fixtures below are the live payload shapes, with the live numbers for
 * the severity case.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import fs from "node:fs";
import path from "node:path";

import SecurityDashboard from "@audit/pages/SecurityDashboard";
import axiosInstance from "@shell/api/axiosInstance";
import { AUDIT_SRC } from "../../../testPaths";

vi.mock("@shell/api/axiosInstance", () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    defaults: { baseURL: "/api" },
  },
}));

vi.mock("@audit/components/layout/AppLayout", () => ({
  default: ({ children }) => <div>{children}</div>,
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => vi.fn(),
    useLocation: () => ({
      pathname: "/audit-dashboard",
      search: "",
      state: null,
    }),
    Link: ({ children, ...rest }) => <a {...rest}>{children}</a>,
  };
});

vi.mock("@shell/auth/AuthContext", () => ({
  useAuth: () => ({ user: { username: "operator", id: 1, org_id: "o-1" } }),
}));

vi.mock("@shell/auth/permissions", () => ({
  canPermission: () => true,
  can: () => true,
  denyMessage: "You do not have permission to perform this action.",
}));

/* The live severity distribution, which is the case that exposed P0-3. */
const SEVERITY = {
  critical: 370,
  high: 2102,
  medium: 2063,
  low: 193,
  info: 2,
  unscored: 10,
  total: 4740,
  deltas: { critical: 0, high: 0, medium: 0, low_info: 0 },
};

const SUMMARY = {
  severity: SEVERITY,
  assets: {
    total: 18,
    unmanaged: 17,
    new_7d: 2,
    new_24h: 1,
    avg_risk_score: 22.2,
    risk_level: "LOW",
    risk_delta_7d: -2.8,
  },
  scans: { last_24h: 3, running: 0, queued: 0, quota_used_pct: 0 },
  kev: { open_count: 19 },
};

/* The live `/dashboard/risk-breakdown` shape. */
const BREAKDOWN = {
  org_risk_score: 22.2,
  risk_level_distribution: {
    critical: 4,
    high: 0,
    medium: 0,
    low: 0,
    info: 11,
  },
  priority_distribution: { p0_kev: 19, p2_cvss_9: 368 },
  tls_issues: {
    expired_certs: 3,
    self_signed: 1,
    weak_ciphers: 2,
    grade_f: 0,
  },
  http_avg_security_score: 64.0,
  finding_status: { open: 4740, accepted: 0, fixed: 3893 },
};

let routes;
beforeEach(() => {
  vi.clearAllMocks();
  routes = {
    "/dashboard/summary": SUMMARY,
    "/dashboard/risk-breakdown": BREAKDOWN,
    "/dashboard/http-headers": {
      total_http_services: 12,
      avg_security_score: 64.0,
      coverage: { hsts: { count: 9, pct: 75 } },
    },
    "/dashboard/tls-health": {
      total_tls_services: 2,
      expiring_in_30d: 0,
      grade_distribution: { A: 2, B: 0, C: 0, D: 0, F: 0 },
    },
    /* The list endpoints need real arrays: the page reads them with
       `data?.[key] || data`, so an unlisted endpoint's `{}` reaches a `.map`
       and takes the whole tree down before the panels under test render. */
    "/dashboard/top-assets": { assets: [] },
    "/dashboard/top-cves": {
      cves: [
        {
          id: "CVE-2026-1",
          title: "t",
          severity: "Critical",
          cvss_v3_score: 9.8,
          affected_assets: 3,
          priority_label: "urgent",
          in_kev: true,
          has_exploit: true,
          epss_score: 0.94429,
        },
        {
          id: "CVE-2026-2",
          title: "u",
          severity: "High",
          cvss_v3_score: 7.5,
          affected_assets: 1,
          priority_label: "high",
          in_kev: false,
        },
      ],
    },
    "/dashboard/services-exposure": { services: [] },
    "/dashboard/scan-activity": {
      scans: [
        {
          id: "scn_1",
          status: "complete",
          target_str: "10.180.6.0/24",
          pipeline_mode: "vulnerability_audit",
          queued_at: "2026-09-23T12:41:00Z",
          started_at: "2026-09-23T12:41:13.404706Z",
          completed_at: "2026-09-23T12:41:17.425252Z",
          duration_seconds: 3.888261318206787,
          total_hosts: 1,
          intensity: "normal",
        },
      ],
    },
    "/dashboard/insights": { insights: [] },
    "/dashboard/asset-breakdown": {
      totals: { total: 18, managed: 1, unmanaged: 17 },
      os_distribution: [{ os_family: "Linux", count: 12 }],
      category_distribution: [
        { category: "server", count: 11 },
        { category: "Unknown", count: 7 },
      ],
    },
    "/dashboard/compliance": { frameworks: [] },
  };
  axiosInstance.get.mockImplementation((url) =>
    Promise.resolve({
      data: Object.prototype.hasOwnProperty.call(routes, String(url))
        ? routes[String(url)]
        : {},
    }),
  );
});

/* Waits for the panel's *loaded* body, not its title: the loading branch
   renders the same `<Panel title="Org Risk Score">` with a skeleton inside, so
   waiting on the title resolves before the data arrives and the assertions
   race it. The subtitle exists only once the payload is in. */
const mount = async () => {
  const r = render(<SecurityDashboard />);
  await screen.findAllByText(/publishes no component breakdown/i);
  return r;
};

/* ══ P0-2 ══════════════════════════════════════════════════════════════════ */

describe("P0-2 — no fabricated risk components", () => {
  it("contains no constant-multiplier value anywhere in the source", () => {
    // A source-level guard, because the rendered number of a fabricated bar is
    // indistinguishable from a real one. `score * 0.72` and its three siblings
    // were the defect; nothing may reintroduce that shape.
    const src = fs.readFileSync(
      path.join(AUDIT_SRC, "pages/SecurityDashboard.jsx"),
      "utf8",
    );
    const code = src
      .split("\n")
      .filter((line) => !line.trim().startsWith("*"))
      .join("\n");
    expect(code).not.toMatch(/score\s*\*\s*0\.\d+/);
    expect(code).not.toMatch(/Math\.round\(\s*score\s*\*/);
  });

  it("no longer claims a component breakdown the API does not publish", async () => {
    await mount();
    expect(screen.queryByText(/Composite: ports \+ CVE CVSS/i)).toBeNull();
    expect(
      screen.getAllByText(/publishes no component breakdown/i).length,
    ).toBeGreaterThan(0);
  });

  it("renders the real HTTP header security score", async () => {
    await mount();
    // Two layouts render, so each panel appears twice.
    expect(screen.getAllByText("HTTP header score").length).toBeGreaterThan(0);
    expect(screen.getAllByText("64 / 100").length).toBeGreaterThan(0);
  });

  it("renders the four real TLS issue counts", async () => {
    await mount();
    for (const label of [
      "Expired certs",
      "Self-signed",
      "Weak ciphers",
      "Grade F",
    ]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
  });

  it("says not assessed rather than 0 when no HTTP service was scored", async () => {
    // `http_avg_security_score` is 0 both when every service scores zero and
    // when there was no service to score. `total_http_services` is the only
    // field that separates them; printing 0 for the second is the same defect
    // one field over.
    routes["/dashboard/http-headers"] = {
      total_http_services: 0,
      coverage: {},
    };
    routes["/dashboard/risk-breakdown"] = {
      ...BREAKDOWN,
      http_avg_security_score: 0.0,
    };
    await mount();
    const [label] = screen.getAllByText("HTTP header score");
    expect(label.parentElement.textContent).toMatch(/Not assessed/);
    expect(label.parentElement.textContent).not.toMatch(/0 \/ 100/);
  });

  it("says not assessed when the API sends no tls_issues at all", async () => {
    routes["/dashboard/risk-breakdown"] = {
      ...BREAKDOWN,
      tls_issues: undefined,
    };
    await mount();
    expect(screen.getAllByText("TLS issues").length).toBeGreaterThan(0);
  });
});

/* ══ P0-3 ══════════════════════════════════════════════════════════════════ */

describe("P0-3 — unscored findings are their own band", () => {
  it("renders an explicit Unscored band", async () => {
    await mount();
    expect(
      screen.getAllByText(/Unscored — no rating published/).length,
    ).toBeGreaterThan(0);
  });

  it("does not fold unscored into Info", async () => {
    const { container } = await mount();
    // 2 info and 10 unscored are different facts. Read off the legend rows
    // themselves rather than by a bare "12" anywhere in the document, which
    // an unrelated OS-distribution count also matches.
    const legend = [...container.querySelectorAll(".sd-legend__row")].map(
      (el) => el.textContent,
    );
    expect(legend.some((t) => /^Info2$/.test(t.replace(/\s/g, "")))).toBe(true);
    expect(
      legend.some((t) =>
        /Unscored—noratingpublished10/.test(t.replace(/\s/g, "")),
      ),
    ).toBe(true);
  });

  it("makes the visible bands sum to severity.total", async () => {
    await mount();
    const bands = ["critical", "high", "medium", "low", "info", "unscored"];
    const sum = bands.reduce((n, k) => n + SEVERITY[k], 0);
    // 4730 was what the five old bands summed to; the sixth closes the arc.
    expect(sum).toBe(SEVERITY.total);
    expect(sum).toBe(4740);
  });

  it("survives a payload that carries no unscored figure", async () => {
    routes["/dashboard/summary"] = {
      ...SUMMARY,
      severity: {
        critical: 1,
        high: 1,
        medium: 1,
        low: 1,
        info: 1,
        total: 5,
      },
    };
    await mount();
    // Rendered as zero rather than throwing, and the other bands are intact.
    expect(screen.getAllByText(/Critical/).length).toBeGreaterThan(0);
  });
});

/* ══ P3-1 ══════════════════════════════════════════════════════════════════ */

describe("P3-1 — dashboard completeness", () => {
  it("renders the backend's own asset risk-level distribution", async () => {
    await mount();
    expect(screen.getAllByText("Assets by risk level").length).toBeGreaterThan(
      0,
    );
    // 4 critical / 11 info on the live payload, and nothing else on the page
    // carried a count per level.
    expect(screen.getAllByText("critical").length).toBeGreaterThan(0);
  });

  it("renders the scan's own duration, hosts and intensity", async () => {
    await mount();
    expect(screen.getAllByText("1 hosts").length).toBeGreaterThan(0);
    expect(screen.getAllByText("3.9s").length).toBeGreaterThan(0);
    expect(screen.getAllByText("normal").length).toBeGreaterThan(0);
  });

  it("omits a duration the scan has not got rather than printing 0s", async () => {
    routes["/dashboard/scan-activity"] = {
      scans: [
        {
          id: "scn_2",
          status: "running",
          target_str: "10.0.0.1",
          queued_at: "2026-09-23T12:41:00Z",
        },
      ],
    };
    await mount();
    expect(screen.queryByText("0.0s")).toBeNull();
  });

  it("names the HTTP population and the count behind each percentage", async () => {
    await mount();
    expect(screen.getAllByText(/Over 12 HTTP services/).length).toBeGreaterThan(
      0,
    );
    // "75%" over 12 services and over 4 are different facts.
    expect(screen.getAllByText("75% (9)").length).toBeGreaterThan(0);
  });

  it("says nothing was assessed rather than showing 0% coverage", async () => {
    routes["/dashboard/http-headers"] = {
      total_http_services: 0,
      coverage: { hsts: { count: 0, pct: 0 } },
    };
    await mount();
    expect(
      screen.getAllByText(/No HTTP service was assessed/).length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText("0%")).toBeNull();
  });

  it("renders the device-category distribution beside the OS one", async () => {
    await mount();
    expect(screen.getAllByText("By device category").length).toBeGreaterThan(0);
    expect(screen.getAllByText("server").length).toBeGreaterThan(0);
  });

  it("shows exploit availability and EPSS on the top CVEs, not only KEV", async () => {
    await mount();
    expect(screen.getAllByText("Exploit").length).toBeGreaterThan(0);
    expect(screen.getAllByText("94.4%").length).toBeGreaterThan(0);
  });

  it("shows no exploit or EPSS mark for a CVE the API did not enrich", async () => {
    // A missing `has_exploit` is not "no exploit exists"; a missing EPSS is
    // not a zero probability. Two CVE rows, one enriched.
    const { container } = await mount();
    expect(container.querySelectorAll(".sd-cveflags").length).toBe(2);
    expect(screen.getAllByText("Exploit").length).toBe(1);
    expect(screen.queryByText("0.0%")).toBeNull();
  });

  it("does not invent a daily scan quota", async () => {
    // This read `quota_limit_24h || 50`, so an installation with no limit
    // recorded was told its plan allows 50 scans a day.
    await mount();
    expect(
      screen.getAllByText(/No daily scan quota recorded/).length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/Plan limit 50\/day/)).toBeNull();
  });

  it("states the quota as a share when the API records a limit", async () => {
    routes["/dashboard/summary"] = {
      ...SUMMARY,
      scans: { ...SUMMARY.scans, quota_limit_24h: 50, quota_used_pct: 72 },
    };
    await mount();
    expect(
      screen.getAllByText(/Scan quota: 72% of 50\/day used/).length,
    ).toBeGreaterThan(0);
  });

  it("shows the week's new assets beside the unmanaged count", async () => {
    await mount();
    expect(
      screen.getAllByText(/17 unmanaged · 2 new in 7 days/).length,
    ).toBeGreaterThan(0);
  });
});
