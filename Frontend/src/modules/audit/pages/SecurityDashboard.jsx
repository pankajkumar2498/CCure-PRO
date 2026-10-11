/**
 * src/modules/audit/pages/SecurityDashboard.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * SOC-style Security Overview Dashboard — CCure Audit's landing page. Sign-in
 * itself lands on CCure Home (`/`), whose Audit card opens this page.
 *
 * Audit's dashboard, at /audit-dashboard since Phase 12 (/dashboard redirects
 * there); the scan template picker is at /scan.
 * All data comes from the real backend via /dashboard/* endpoints.
 * RBAC-aware: widgets gate on user permissions via canPermission().
 *
 * Architecture:
 *   - useDashboard() hook fetches all panels in parallel (Promise.allSettled)
 *   - 30-second auto-refresh for scan activity (live strip)
 *   - Each widget is a self-contained component for clean maintenance
 *
 * Checkpoint 3C batch 17: no longer reads dashboard.css. Panels are headed
 * sections, the two tables are CcureTable, the tab bar is CcureTabs, the
 * welcome is CcureModal, and every navigation — a metric card, a top asset, a
 * top CVE, "View All", "Export PDF" — is a link rather than a click handler on
 * a <div> or a <tr>. Colours that carried meaning are token classes named for
 * the fact; the widths that carry data stay inline. Every request, parameter,
 * refresh and permission check is unchanged.
 */

import { iconForBackendGlyph } from "../utils/backendIcons";
import { useState, useEffect, useCallback, useId } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { useAuth } from "@shell/auth/AuthContext";
import { canPermission } from "@shell/auth/permissions";
import {
  getDashboardSummary,
  getRiskBreakdown,
  getTopAssets,
  getTopCVEs,
  getServicesExposure,
  getTLSHealth,
  getHTTPHeaders,
  getCompliance,
  getAssetBreakdown,
  getScanActivity,
  getInsights,
} from "@audit/api/dashboard";
import CVELink from "@audit/components/common/CVELink";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureEmptyState,
  CcureModal,
  CcureScanStatus,
  CcureSeverityBadge,
  CcureSkeleton,
  CcureTable,
  CcureTabPanel,
  CcureTabs,
  useCcureTabs,
  CcureCard,
  CcureDropdown,
  CcureMenuItem,
  CcurePage,
  CcurePageHeader,
  CcureIcon,
} from "../../../design-system";
import "../styles/security-dashboard.css";

// ── Tiny helpers ──────────────────────────────────────────────────────────────

const fmt = (n) => (n ?? 0).toLocaleString();
const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);
const ago = (iso) => {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const clamp = (v, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, v || 0));

/* Asset risk bands — the thresholds the page always used (75 / 50 / 25). The
   score is printed beside every band, so the number never depends on colour. */
const riskTone = (score) =>
  score >= 75
    ? "critical"
    : score >= 50
      ? "high"
      : score >= 25
        ? "medium"
        : "low";

/* A CVSS v3 score is absent for a CVE NVD scored only under v2.
   `cvss_v3_score.toFixed(1)` threw on the first such CVE and took the landing
   page down — the defect batch 16 fixed on the vulnerability browser. An
   absent score is shown as absent. Bands unchanged: >= 9, >= 7. */
const toScore = (value) =>
  value === null || value === undefined || value === "" ? null : Number(value);
const hasScore = (value) => Number.isFinite(value);
const cvssText = (value) => (hasScore(value) ? value.toFixed(1) : "—");
const cvssTone = (value) =>
  !hasScore(value)
    ? "neutral"
    : value >= 9
      ? "critical"
      : value >= 7
        ? "high"
        : "medium";

/* The label is printed inside the badge; the variant reinforces it. */
const PRIORITY_VARIANT = {
  P0: "danger",
  P1: "warning",
  P2: "warning",
  P3: "info",
  P4: "neutral",
};

const PriBadge = ({ label }) =>
  label ? (
    <CcureBadge variant={PRIORITY_VARIANT[label] || "neutral"}>
      {label}
    </CcureBadge>
  ) : null;

/**
 * The tone for an asset risk level, which is a different vocabulary from a
 * finding severity even where the words coincide: these count *assets* by the
 * level the backend assigned them.
 */
const RISK_LEVEL_TONE = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

/**
 * The severity bands, and `unscored` is one of them.
 *
 * It was omitted while the donut still divided by `severity.total`, which
 * includes it — measured live at 370+2102+2063+193+2 = 4730 against a total of
 * 4740, so the arcs were ten findings short and nothing said why.
 *
 * It is **not** folded into Info or None. `normalize_severity()` keeps it
 * separate on the backend because "no rating published is a different fact
 * from a published rating of zero", and collapsing it here would undo that at
 * the last step.
 */
const SEVERITY_BANDS = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["info", "Info"],
  ["unscored", "Unscored — no rating published"],
];

/* A single letter is what a sighted reader scans; the word is what a screen
   reader announces. The card around the table is positioned, so the visually
   hidden word cannot escape it (batch 16). */
const CountHeader = ({ letter, word }) => (
  <span title={word}>
    <span aria-hidden="true">{letter}</span>
    <span className="cc-sr-only">{word}</span>
  </span>
);

// ── Shared building blocks ────────────────────────────────────────────────────

/* A headed panel. The titles were <div>s, so the page had no headings at all
   and nothing to navigate by. Emoji are decorative and hidden. */
function Panel({ title, icon, subtitle, action, flush = false, children }) {
  return (
    <CcureCard
      className="sd-card"
      title={
        <>
          {icon ? <span aria-hidden="true">{icon} </span> : null}
          {title}
        </>
      }
      subtitle={subtitle}
      actions={action}
      bodyFlush={flush}
    >
      {children}
    </CcureCard>
  );
}

function SkeletonRows({ count, size = 28 }) {
  return (
    <div className="sd-skeleton-rows">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="sd-skeleton-row">
          <CcureSkeleton width={size} height={size} radius={7} />
          <div className="sd-skeleton-row__text">
            <CcureSkeleton width="70%" height={10} />
            <CcureSkeleton width="50%" height={8} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Risk ring SVG ─────────────────────────────────────────────────────────────

function RiskRing({ score, level }) {
  const r = 36,
    cx = 44,
    cy = 44;
  const circ = 2 * Math.PI * r;
  const dash = (circ * clamp(score)) / 100;
  const tone = riskTone(score);

  return (
    <div className="sd-ring">
      {/* The arc repeats the number printed in its centre, so it is hidden
          from assistive technology. The dash length is data; the colour is the
          band. */}
      <svg
        viewBox="0 0 88 88"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
        focusable="false"
      >
        <circle
          className="sd-ring__track"
          cx={cx}
          cy={cy}
          r={r}
          strokeWidth="7"
        />
        <circle
          className={`sd-stroke--${tone}`}
          cx={cx}
          cy={cy}
          r={r}
          strokeWidth="7"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
        />
      </svg>
      <div className="sd-ring__center">
        <div className={`sd-ring__num sd-tone--${tone}`}>{score}</div>
        <div className="sd-ring__lbl">{level || "—"}</div>
      </div>
    </div>
  );
}

// ── Mini bar helper ───────────────────────────────────────────────────────────

function BarRow({ label, value, max, tone = "primary", valDisplay }) {
  const w = max ? clamp((value / max) * 100) : 0;
  return (
    <div className="sd-bar">
      <div className="sd-bar__label" title={label}>
        {label}
      </div>
      <div className="sd-bar__track" aria-hidden="true">
        <div
          className={`sd-bar__fill sd-fill--${tone}`}
          style={{ width: `${w}%` }}
        />
      </div>
      <div className={`sd-bar__val sd-tone--${tone}`}>
        {valDisplay ?? value}
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// WIDGET COMPONENTS
// ═════════════════════════════════════════════════════════════════════════════

// ── 1. Top Metric Cards ───────────────────────────────────────────────────────

function MetricCards({ summary, loading }) {
  if (loading) {
    return (
      <div className="sd-metrics">
        {Array.from({ length: 8 }).map((_, i) => (
          <CcureCard as={"div"} key={i} className="sd-metric">
            <CcureSkeleton width="60%" height={10} />
            <CcureSkeleton width="50%" height={28} />
            <CcureSkeleton width="80%" height={10} />
          </CcureCard>
        ))}
      </div>
    );
  }

  const sev = summary?.severity || {};
  const ast = summary?.assets || {};
  const scn = summary?.scans || {};
  const kev = summary?.kev || {};
  const d = sev.deltas || {};

  const getVulnTrend = (val) => {
    if (val > 0) return { label: `▲ +${val} from last scan`, tone: "bad" };
    if (val < 0)
      return { label: `▼ ${Math.abs(val)} remediated`, tone: "good" };
    return { label: "— unchanged", tone: "neutral" };
  };

  const getRiskTrend = (val) => {
    if (val > 0) return { label: `▲ +${val} pts vs last week`, tone: "bad" };
    if (val < 0)
      return { label: `▼ ${Math.abs(val)} pts vs last week`, tone: "good" };
    return { label: "— stable", tone: "neutral" };
  };

  const getAssetTrend = (val) => {
    if (val > 0) return { label: `▲ +${val} new hosts`, tone: "good" };
    return { label: "— unchanged", tone: "neutral" };
  };

  const tCritical = getVulnTrend(d.critical);
  const tHigh = getVulnTrend(d.high);
  const tMedium = getVulnTrend(d.medium);
  const tLowInfo = getVulnTrend(d.low_info);
  const tAssets = getAssetTrend(ast.new_24h);
  const tRisk = getRiskTrend(ast.risk_delta_7d);

  const cards = [
    {
      label: "Critical Findings",
      value: fmt(sev.critical),
      variant: "critical",
      trend: tCritical,
      sub: `Across ${ast.total || 0} assets`,
      nav: "/vulnerabilities?severity=Critical",
    },
    {
      label: "High Findings",
      value: fmt(sev.high),
      variant: "high",
      trend: tHigh,
      sub: `Across assets`,
      nav: "/vulnerabilities?severity=High",
    },
    {
      label: "Medium Findings",
      value: fmt(sev.medium),
      variant: "medium",
      trend: tMedium,
      sub: `Across assets`,
      nav: "/vulnerabilities?severity=Medium",
    },
    {
      label: "Low / Info",
      value: fmt((sev.low || 0) + (sev.info || 0)),
      variant: "low",
      trend: tLowInfo,
      sub: "Informational only",
      nav: "/vulnerabilities?severity=Low,Info",
    },
    {
      label: "Assets Discovered",
      value: fmt(ast.total),
      variant: "blue",
      trend: tAssets,
      /* `new_7d` is the week's arrivals and was on the payload unused; the
         trend chip already carries the 24-hour figure, so the two do not
         repeat each other. */
      sub:
        typeof ast.new_7d === "number"
          ? `${ast.unmanaged || 0} unmanaged · ${ast.new_7d} new in 7 days`
          : `${ast.unmanaged || 0} unmanaged`,
      nav: "/assets",
    },
    {
      label: "Scans (24h)",
      value: fmt(scn.last_24h),
      variant: "teal",
      trend: {
        label: `${scn.running || 0} running · ${scn.queued || 0} queued`,
        tone: "neutral",
      },
      /* This read `quota_limit_24h || 50`, so an installation with no limit
         recorded — which is what the live one sends — was told its plan
         allows 50 scans a day. Nobody set that number. Where a limit does
         exist the API's own `quota_used_pct` says how much of it is gone. */
      sub:
        typeof scn.quota_limit_24h === "number"
          ? `Scan quota: ${scn.quota_used_pct ?? 0}% of ${scn.quota_limit_24h}/day used`
          : "No daily scan quota recorded",
      nav: "/history",
    },
    {
      label: "Org Risk Score",
      value: `${ast.avg_risk_score || 0}/100`,
      variant: "purple",
      trend: tRisk,
      sub: `${ast.risk_level || "INFO"} risk level`,
      nav: "/assets",
    },
    {
      label: "Open CVEs (KEV)",
      value: fmt(kev.open_count),
      variant: "critical",
      trend: { label: "CISA KEV listed", tone: "bad" },
      sub: "Priority P0 required",
      nav: "/vulnerabilities?in_kev=true",
    },
  ];

  return (
    <div className="sd-metrics">
      {/* Each card was a <div> with a click handler: a mouse could open the
          filtered list and a keyboard could not reach it. A card is a link to
          exactly the place the handler went. */}
      {cards.map((c) => (
        <CcureCard
          as={Link}
          key={c.label}
          to={c.nav}
          className={`sd-metric sd-metric--${c.variant}`}
        >
          <span className="sd-metric__label">{c.label}</span>{" "}
          <span className={`sd-metric__value sd-metric__value--${c.variant}`}>
            {c.value}
          </span>{" "}
          {c.trend ? (
            <span className={`sd-metric__trend sd-trend--${c.trend.tone}`}>
              {c.trend.label}
            </span>
          ) : null}{" "}
          <span className="sd-metric__sub">{c.sub}</span>
        </CcureCard>
      ))}
    </div>
  );
}

// ── 2. Severity Bar ───────────────────────────────────────────────────────────

function SevBar({ summary }) {
  const sev = summary?.severity || {};
  const total = sev.total || 1;
  const segs = SEVERITY_BANDS.map(([key, label]) => ({
    key,
    label,
    count: sev[key] || 0,
  }));

  return (
    <div className="sd-sevbar">
      {/* The legend states every count and share in words; the bar is its
          picture and is hidden from assistive technology. */}
      <div className="sd-sevbar__bar" aria-hidden="true">
        {segs.map(
          (s) =>
            s.count > 0 && (
              <div
                key={s.key}
                className={`sd-sevbar__seg sd-fill--${s.key}`}
                style={{ width: `${pct(s.count, total)}%` }}
                title={`${s.label}: ${s.count}`}
              />
            ),
        )}
      </div>
      <div className="sd-sevbar__legend">
        {segs.map((s) => (
          <span key={s.key} className="sd-sevbar__item">
            <span className={`sd-dot sd-fill--${s.key}`} aria-hidden="true" />
            {s.label} {s.count} ({pct(s.count, total)}%)
          </span>
        ))}
      </div>
    </div>
  );
}

// ── 3. Risk Score Panel ───────────────────────────────────────────────────────

/**
 * Org risk, from the backend's own numbers only.
 *
 * This panel used to render four bars labelled "CVE CVSS", "Port risk",
 * "HTTP hdrs" and "TLS grade" as `score * 0.72`, `* 0.55`, `* 0.38` and
 * `* 0.6` — constants multiplied by the one score, presented as a component
 * breakdown of it. The backend publishes no such breakdown, so those bars were
 * the UI asserting something nobody measured.
 *
 * What it does publish on the same endpoint is `http_avg_security_score` and
 * the four `tls_issues` counts, and those are rendered instead. The subtitle
 * no longer claims a composition the payload does not carry.
 *
 * `httpHeaders` is read for one reason: `http_avg_security_score` is 0 both
 * when every HTTP service scores zero and when there was no HTTP service to
 * score. `total_http_services` is the only field that separates them, and a
 * zero printed for the second case is the same defect one field over.
 */
function RiskScorePanel({ summary, breakdown, httpHeaders, loading }) {
  if (loading) {
    return (
      <Panel title="Org Risk Score">
        <div className="sd-risk">
          <CcureSkeleton width={88} height={88} radius="50%" />
          <div className="sd-risk__bars">
            {[1, 2, 3, 4].map((i) => (
              <CcureSkeleton key={i} height={8} />
            ))}
          </div>
        </div>
      </Panel>
    );
  }

  const ast = summary?.assets || {};
  const bd = breakdown || {};
  const score = ast.avg_risk_score || 0;
  const level = ast.risk_level || "INFO";

  const pd = bd.priority_distribution || {};
  const fs = bd.finding_status || {};

  /* Every entry here is a value the API returned. `??` rather than `||`
     throughout: 0 is a measurement and absent is not, and folding them is the
     defect this panel was rewritten to remove. */
  const httpScore = bd.http_avg_security_score;
  const httpServices = httpHeaders?.total_http_services;
  const httpAssessed = typeof httpScore === "number" && (httpServices ?? 0) > 0;

  const tls = bd.tls_issues || {};
  const TLS_ISSUES = [
    ["expired_certs", "Expired certs"],
    ["self_signed", "Self-signed"],
    ["weak_ciphers", "Weak ciphers"],
    ["grade_f", "Grade F"],
  ];
  const tlsRows = TLS_ISSUES.filter(([key]) => typeof tls[key] === "number");

  /* `risk_level_distribution` as the API sent it, in its own order. Absent
     levels are not invented and a level of zero is kept — it is a measured
     count, not a missing one. */
  const rld = Object.entries(bd.risk_level_distribution || {});

  return (
    <Panel
      title="Org Risk Score"
      subtitle="Mean asset risk. The API publishes no component breakdown of it."
    >
      <div className="sd-risk">
        <RiskRing score={score} level={level} />
        <div className="sd-risk__bars">
          {httpAssessed ? (
            <BarRow
              label="HTTP header score"
              value={Math.round(httpScore)}
              max={100}
              tone={httpScore >= 70 ? "success" : "medium"}
              valDisplay={`${Math.round(httpScore)} / 100`}
            />
          ) : (
            <div className="sd-bar">
              <div className="sd-bar__label">HTTP header score</div>
              <div className="sd-muted">
                {/* Not zero. Nothing was assessed. */}
                Not assessed
              </div>
            </div>
          )}
          {tlsRows.length > 0 ? (
            tlsRows.map(([key, label]) => (
              <BarRow
                key={key}
                label={label}
                value={tls[key]}
                max={Math.max(...tlsRows.map(([k]) => tls[k]), 1)}
                tone={tls[key] > 0 ? "critical" : "neutral"}
              />
            ))
          ) : (
            <div className="sd-bar">
              <div className="sd-bar__label">TLS issues</div>
              <div className="sd-muted">Not assessed</div>
            </div>
          )}
        </div>
      </div>

      {/* The backend's own distribution of asset risk levels. Not recreated
          from any figure on this page — it is a count per level and nothing
          else here carries it. */}
      {rld.length > 0 ? (
        <div className="sd-mb-sm">
          <h3 className="sd-subhead">Assets by risk level</h3>
          {rld.map(([level, count]) => (
            <BarRow
              key={level}
              label={level}
              value={count}
              max={Math.max(...rld.map(([, n]) => n), 1)}
              tone={RISK_LEVEL_TONE[level] || "neutral"}
            />
          ))}
        </div>
      ) : null}

      <div className="sd-tiles">
        {[
          { label: "P0 KEV", val: pd.p0_kev || 0, tone: "danger" },
          { label: "P2 CVSS≥9", val: pd.p2_cvss_9 || 0, tone: "warning" },
          { label: "Open", val: fs.open || 0, tone: "neutral" },
          { label: "Fixed", val: fs.fixed || 0, tone: "success" },
        ].map((b) => (
          <div key={b.label} className="sd-tile">
            <div className="sd-tile__label">{b.label}</div>
            <div className={`sd-tile__val sd-tone--${b.tone}`}>{b.val}</div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── 4. Findings Donut ─────────────────────────────────────────────────────────

function FindingsDonut({ summary, breakdown, loading }) {
  if (loading) {
    return (
      <Panel title="Findings by Severity">
        <div className="sd-donut-wrap">
          <CcureSkeleton width={80} height={80} radius="50%" />
          <div className="sd-risk__bars">
            {[1, 2, 3, 4, 5].map((i) => (
              <CcureSkeleton key={i} height={8} />
            ))}
          </div>
        </div>
      </Panel>
    );
  }

  const sev = summary?.severity || {};
  const fs = breakdown?.finding_status || {};
  const total = sev.total || 0;

  const items = SEVERITY_BANDS.map(([key, label]) => ({
    key,
    label,
    count: sev[key] || 0,
  }));

  // CSS conic-gradient donut. The angles are data and stay inline; each
  // band's colour is its token.
  let cumulative = 0;
  const segments = items.map((item) => {
    const slice = total > 0 ? (item.count / total) * 360 : 0;
    const from = cumulative;
    cumulative += slice;
    return { ...item, from, to: cumulative };
  });

  const gradientStr = segments
    .map((s) => `var(--ccure-sev-${s.key}) ${s.from}deg ${s.to}deg`)
    .join(", ");

  return (
    <Panel
      title="Findings by Severity"
      subtitle={`${fmt(total)} total open findings`}
    >
      <div className="sd-donut-wrap">
        <div
          className="sd-donut"
          aria-hidden="true"
          style={
            total > 0
              ? { background: `conic-gradient(${gradientStr})` }
              : undefined
          }
        >
          <div className="sd-donut__hole" />
        </div>

        <ul className="sd-legend">
          {items.map((item) => (
            <li key={item.key} className="sd-legend__row">
              <span className="sd-legend__name">
                <span
                  className={`sd-dot sd-fill--${item.key}`}
                  aria-hidden="true"
                />
                {item.label}
              </span>
              <span className="sd-legend__count">{item.count}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="sd-mt-md">
        <BarRow
          label="Open"
          value={fs.open || 0}
          max={Math.max(total, 1)}
          tone="danger"
        />
        <BarRow
          label="Accepted"
          value={fs.accepted || 0}
          max={Math.max(total, 1)}
          tone="warning"
        />
        <BarRow
          label="Fixed"
          value={fs.fixed || 0}
          max={Math.max(total, 1)}
          tone="success"
        />
      </div>
    </Panel>
  );
}

// ── 5. Scan Activity ──────────────────────────────────────────────────────────

const MODE_ICON = {
  basic: "radio",
  asset: "search",
  advanced: "zap",
  vulnerability_audit: "zap",
  credentialed: "key",
};
const MODE_LABEL = {
  basic: "Basic",
  asset: "Asset",
  advanced: "Vulnerability Audit",
  vulnerability_audit: "Vulnerability Audit",
  credentialed: "Credentialed",
};

/* The icon tile's tint follows the scan's state — the same three buckets the
   page always used. The state itself is the CcureScanStatus word beside it. */
const activityTone = (status) =>
  status === "running" ? "info" : status === "failed" ? "danger" : "success";

function ScanActivity({ scans, loading }) {
  const title = "Live Scan Activity";
  const icon = <span className="sd-pulse" />;
  const subtitle = "Real-time · WebSocket-driven progress";

  if (loading) {
    return (
      <Panel title={title} icon={icon} subtitle={subtitle}>
        <SkeletonRows count={4} size={30} />
      </Panel>
    );
  }

  const scanList = scans || [];

  return (
    <Panel title={title} icon={icon} subtitle={subtitle}>
      {scanList.length === 0 && (
        <CcureEmptyState
          icon={<CcureIcon name="radio" />}
          title="No recent scans"
        />
      )}

      {scanList.length > 0 && (
        <ul className="sd-feed">
          {scanList.map((scan) => {
            const isCredentialed = scan.scan_type === "credentialed";
            const modeIcon = isCredentialed
              ? MODE_ICON.credentialed
              : MODE_ICON[scan.pipeline_mode] || "radio";

            return (
              <li key={scan.id} className="sd-feed__row">
                <span
                  className={`sd-feed__icon sd-feed__icon--${activityTone(scan.status)}`}
                  aria-hidden="true"
                >
                  <CcureIcon name={modeIcon} />
                </span>
                <div className="sd-feed__body">
                  <div className="sd-feed__title">
                    {(isCredentialed
                      ? MODE_LABEL.credentialed
                      : MODE_LABEL[scan.pipeline_mode]) || "Scan"}{" "}
                    · {scan.target_str}
                  </div>
                  <div className="sd-feed__sub">
                    {scan.current_phase
                      ? `Phase: ${scan.current_phase.replace(/_/g, " ")} · ${scan.progress_pct || 0}%`
                      : scan.active_hosts
                        ? `${scan.active_hosts} hosts · C:${scan.critical_count} H:${scan.high_count}`
                        : scan.scan_name || scan.id}
                  </div>
                  {/* The backend's own figures for what the scan did. They
                      were on the payload and the feed showed none of them, so
                      a four-second scan and a sixteen-minute one read the
                      same. Each is printed only where the API sent it —
                      `duration_seconds` is absent on a scan that has not
                      finished, which is not a duration of zero. */}
                  <div className="sd-feed__facts">
                    {typeof scan.total_hosts === "number" ? (
                      <span>{scan.total_hosts} hosts</span>
                    ) : null}
                    {typeof scan.duration_seconds === "number" ? (
                      <span>{scan.duration_seconds.toFixed(1)}s</span>
                    ) : null}
                    {scan.intensity ? <span>{scan.intensity}</span> : null}
                    {scan.completed_at ? (
                      <span title={`Completed ${scan.completed_at}`}>
                        completed {ago(scan.completed_at)}
                      </span>
                    ) : scan.started_at ? (
                      <span title={`Started ${scan.started_at}`}>
                        started {ago(scan.started_at)}
                      </span>
                    ) : null}
                  </div>
                  {/* The percentage is in the line above; the bar is its
                      picture. */}
                  {scan.status === "running" && (
                    <div className="sd-progress" aria-hidden="true">
                      <div
                        className="sd-progress__fill sd-fill--primary"
                        style={{ width: `${scan.progress_pct || 5}%` }}
                      />
                    </div>
                  )}
                </div>
                <div className="sd-feed__meta">
                  {/* The legacy badge said "Done", and showed any status it
                      did not recognise as "Queued" — a claim about a scan that
                      nobody made. CcureScanStatus says "Unknown". */}
                  <CcureScanStatus status={scan.status} />
                  <span className="sd-feed__time">{ago(scan.queued_at)}</span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

// ── 6. Top Assets Table ───────────────────────────────────────────────────────

const ASSET_COLUMNS = [
  { key: "host", header: "IP / Host" },
  { key: "os", header: "OS" },
  { key: "risk", header: "Risk" },
  { key: "critical", header: <CountHeader letter="C" word="Critical" /> },
  { key: "high", header: <CountHeader letter="H" word="High" /> },
  { key: "medium", header: <CountHeader letter="M" word="Medium" /> },
  { key: "last_seen", header: "Last Seen" },
  { key: "managed", header: "Managed" },
];

function TopAssetsTable({ assets, loading, onNavigate }) {
  const rows = assets || [];

  return (
    <Panel
      flush
      icon={<CcureIcon name="monitor" />}
      title="Top Vulnerable Assets"
      subtitle="Ranked by composite risk score · click to drill into asset"
      action={
        <CcureButton as={Link} to="/assets" variant="secondary" size="sm">
          View All<span className="cc-sr-only"> assets</span>{" "}
          <span aria-hidden="true">→</span>
        </CcureButton>
      }
    >
      <CcureTable
        caption="Top vulnerable assets, ranked by composite risk score"
        columns={ASSET_COLUMNS}
        density="compact"
        loading={loading}
        loadingRows={5}
      >
        {!loading && rows.length === 0 && (
          <tr>
            <td colSpan={ASSET_COLUMNS.length} className="sd-table-empty">
              No assets found. Run a scan to populate the registry.
            </td>
          </tr>
        )}
        {!loading &&
          rows.map((a) => {
            const tone = riskTone(a.risk_score);
            return (
              <tr
                key={a.id}
                className="sd-row-link"
                onClick={() => onNavigate(`/assets/${a.id}`)}
              >
                <td>
                  {/* The row navigated for a mouse only. The address is the
                      keyboard route to the same place; the row keeps its
                      click target. */}
                  <Link
                    to={`/assets/${a.id}`}
                    className="sd-link sd-mono"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {a.ip_address}
                  </Link>
                  {a.hostname && (
                    <div className="sd-cell-sub">{a.hostname}</div>
                  )}
                  {/* The fully-qualified name only where it says something the
                      hostname does not — on the live estate the two are often
                      the same string, and printing it twice is noise. */}
                  {a.fqdn && a.fqdn !== a.hostname ? (
                    <div className="sd-cell-sub">{a.fqdn}</div>
                  ) : null}
                </td>
                <td>
                  <span className="sd-chip">
                    {a.os_name || a.os_family || "Unknown"}
                    {/* What kind of device, which the OS alone does not say. */}
                    {a.device_category ? (
                      <span className="sd-cell-muted">
                        {" "}
                        · {a.device_category}
                      </span>
                    ) : null}
                  </span>
                </td>
                <td>
                  <div className="sd-riskcell">
                    <div className="sd-riskbar" aria-hidden="true">
                      <div
                        className={`sd-riskbar__fill sd-fill--${tone}`}
                        style={{ width: `${clamp(a.risk_score)}%` }}
                      />
                    </div>
                    <span className={`sd-riskscore sd-tone--${tone}`}>
                      {a.risk_score}
                    </span>
                  </div>
                </td>
                <td className="sd-count sd-tone--critical">
                  {a.vuln_counts?.critical || 0}
                </td>
                <td className="sd-count sd-tone--high">
                  {a.vuln_counts?.high || 0}
                </td>
                <td className="sd-count sd-tone--medium">
                  {a.vuln_counts?.medium || 0}
                </td>
                <td className="sd-cell-muted">{ago(a.last_seen_at)}</td>
                <td>
                  <span
                    className={`sd-chip sd-chip--${a.is_managed ? "managed" : "unmanaged"}`}
                  >
                    {a.is_managed ? "Managed" : "Unmanaged"}
                  </span>
                </td>
              </tr>
            );
          })}
      </CcureTable>
    </Panel>
  );
}

// ── 7. Top CVEs Table ─────────────────────────────────────────────────────────

const CVE_COLUMNS = [
  { key: "cve", header: "CVE ID" },
  { key: "cvss", header: "CVSS" },
  { key: "priority", header: "Priority" },
  { key: "severity", header: "Severity" },
  { key: "affected", header: "Affected" },
  { key: "kev", header: "KEV" },
];

function TopCVEsTable({ cves, loading, onNavigate }) {
  const rows = cves || [];

  return (
    <Panel
      flush
      icon={<CcureIcon name="alert-octagon" />}
      title="Critical & High CVEs"
      subtitle="Sorted by priority score — P0 KEV first"
    >
      <CcureTable
        caption="Critical and high CVEs, sorted by priority score"
        columns={CVE_COLUMNS}
        density="compact"
        loading={loading}
        loadingRows={5}
      >
        {!loading && rows.length === 0 && (
          <tr>
            <td colSpan={CVE_COLUMNS.length} className="sd-table-empty">
              No critical/high CVEs found. Your environment may be well-patched.
            </td>
          </tr>
        )}
        {!loading &&
          rows.map((c) => {
            const score = toScore(c.cvss_v3_score);
            const findings = `/vulnerabilities?search=${c.id}`;
            return (
              <tr
                key={c.id}
                className="sd-row-link"
                onClick={() => onNavigate(findings)}
              >
                <td>
                  <div className="sd-cve-id">
                    <CVELink cveId={c.id} />
                  </div>
                  {/* The CVE id links out to NVD; the title is the keyboard
                      route to this estate's findings for it — where the row
                      went. */}
                  <Link
                    to={findings}
                    className="sd-link sd-truncate"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {c.title || c.id}
                  </Link>
                </td>
                <td>
                  <span className={`sd-cvss sd-tone--${cvssTone(score)}`}>
                    {cvssText(score)}
                  </span>
                </td>
                <td>
                  <PriBadge label={c.priority_label} />
                </td>
                <td>
                  <CcureSeverityBadge severity={c.severity} />
                </td>
                <td className="sd-cell-muted">{c.affected_assets} assets</td>
                <td>
                  {/* KEV was the only enrichment shown. Exploit availability
                      and EPSS are on the same payload and decide which of two
                      equally-scored CVEs is worked first. Each appears only
                      where the API sent it — a missing EPSS is not a zero
                      probability, and a missing `has_exploit` is not "no
                      exploit exists". */}
                  <span className="sd-cveflags">
                    {c.in_kev ? (
                      <span className="sd-flag sd-flag--kev">KEV</span>
                    ) : null}
                    {c.has_exploit === true ? (
                      <span
                        className="sd-flag sd-flag--exploit"
                        title="A public exploit exists for this CVE. It does not mean any host here is exploitable."
                      >
                        Exploit
                      </span>
                    ) : null}
                    {typeof c.epss_score === "number" ? (
                      <span
                        className="sd-cell-muted"
                        title="EPSS — the modelled probability of exploitation in the next 30 days."
                      >
                        {(c.epss_score * 100).toFixed(1)}%
                      </span>
                    ) : null}
                  </span>
                </td>
              </tr>
            );
          })}
      </CcureTable>
    </Panel>
  );
}

// ── 8. Asset Breakdown ────────────────────────────────────────────────────────

/* One outline mark for every operating system: the family is the label beside
   it. Brand logos are not part of the icon set. */
const OS_ICON = {
  Unknown: "help-circle",
};

function AssetBreakdownPanel({ assetBreakdown, loading }) {
  if (loading)
    return (
      <Panel icon={<CcureIcon name="monitor" />} title="Asset Inventory">
        <CcureSkeleton height={80} />
      </Panel>
    );

  const t = assetBreakdown?.totals || {};
  const os = assetBreakdown?.os_distribution || [];
  const cat = assetBreakdown?.category_distribution || [];

  return (
    <Panel
      icon={<CcureIcon name="monitor" />}
      title="Asset Inventory"
      subtitle={`${fmt(t.total)} total assets`}
    >
      <ul className="sd-os">
        {os.slice(0, 6).map((o) => (
          <li key={o.os_family} className="sd-os__item">
            <span className="sd-os__icon" aria-hidden="true">
              <CcureIcon name={OS_ICON[o.os_family] || "monitor"} />
            </span>
            <span className="sd-os__count">{o.count}</span>
            <span className="sd-os__name">{o.os_family}</span>
          </li>
        ))}
      </ul>
      {/* What kind of device, which the OS list cannot answer. */}
      {cat.length > 0 ? (
        <>
          <h3 className="sd-subhead">By device category</h3>
          {cat.slice(0, 6).map((c) => (
            <BarRow
              key={c.category}
              label={c.category}
              value={c.count}
              max={Math.max(...cat.map((x) => x.count), 1)}
              tone="primary"
            />
          ))}
        </>
      ) : null}

      <BarRow
        label="Managed"
        value={t.managed || 0}
        max={t.total || 1}
        tone="success"
      />
      <BarRow
        label="Unmanaged"
        value={t.unmanaged || 0}
        max={t.total || 1}
        tone="danger"
      />
      <BarRow
        label="Active"
        value={t.active || 0}
        max={t.total || 1}
        tone="primary"
      />
      <BarRow
        label="Offline"
        value={t.offline || 0}
        max={t.total || 1}
        tone="neutral"
      />
    </Panel>
  );
}

// ── 9. Service Exposure ───────────────────────────────────────────────────────

function ServiceExposurePanel({ services, loading }) {
  if (loading)
    return (
      <Panel icon={<CcureIcon name="unlock" />} title="Top Exposed Services">
        <CcureSkeleton height={160} />
      </Panel>
    );

  const top = (services || []).slice(0, 10);
  const maxCount = Math.max(...top.map((s) => s.asset_count), 1);

  return (
    <Panel
      icon={<CcureIcon name="unlock" />}
      title="Top Exposed Services"
      subtitle="Open ports across all assets"
    >
      {top.map((s) => (
        <BarRow
          key={`${s.port}/${s.protocol}`}
          label={`${s.service_name || s.port}/${s.protocol}`}
          value={s.asset_count}
          max={maxCount}
          tone={s.is_high_risk ? "danger" : "primary"}
        />
      ))}
      {top.some((s) => s.is_high_risk) && (
        <CcureAlert
          variant="danger"
          live={false}
          className="sd-mt-sm"
          title="High-risk cleartext protocols detected"
        >
          Telnet/FTP exposure increases attack surface. Recommend replacement
          with SSH/SFTP.
        </CcureAlert>
      )}
    </Panel>
  );
}

// ── 10. TLS Health ────────────────────────────────────────────────────────────

const GRADE_TONE = {
  A: "success",
  B: "success",
  C: "warning",
  D: "high",
  F: "danger",
};

const coverageTone = (p) =>
  p >= 70 ? "success" : p >= 40 ? "warning" : "high";

function TLSHealthPanel({ tlsHealth, httpHeaders, loading }) {
  if (loading)
    return (
      <Panel icon={<CcureIcon name="lock" />} title="TLS & HTTP Security">
        <CcureSkeleton height={140} />
      </Panel>
    );

  const tls = tlsHealth || {};
  const http = httpHeaders || {};
  const gd = tls.grade_distribution || {};

  const grades = ["A", "B", "C", "D", "F"];
  const maxGrade = Math.max(...grades.map((g) => gd[g] || 0), 1);

  const httpCoverage = http.coverage || {};

  return (
    <Panel
      icon={<CcureIcon name="lock" />}
      title="TLS & HTTP Security"
      subtitle={
        <>
          {tls.expiring_in_30d > 0 ? (
            <span className="sd-strong sd-tone--danger">
              <CcureIcon name="alert-triangle" /> {tls.expiring_in_30d} certs
              expiring in 30d ·{" "}
            </span>
          ) : null}
          {tls.total_tls_services || 0} TLS services
        </>
      }
    >
      <div className="sd-mb-sm">
        {grades.map((g) => (
          <BarRow
            key={g}
            label={`Grade ${g}`}
            value={gd[g] || 0}
            max={maxGrade}
            tone={GRADE_TONE[g]}
          />
        ))}
      </div>

      <h3 className="sd-subhead">HTTP Security Headers Coverage</h3>
      {/* The population the percentages are over. Without it every bar reads
          0% on an estate with no HTTP service at all, which says "no host sets
          HSTS" where the truth is "nothing was assessed". */}
      {typeof http.total_http_services === "number" &&
      http.total_http_services === 0 ? (
        <p className="sd-muted">
          No HTTP service was assessed, so there is no coverage to report.
        </p>
      ) : (
        <>
          {typeof http.total_http_services === "number" ? (
            <p className="sd-muted">
              Over {http.total_http_services} HTTP service
              {http.total_http_services === 1 ? "" : "s"}
              {typeof http.avg_security_score === "number"
                ? ` · mean header score ${Math.round(http.avg_security_score)}/100`
                : ""}
            </p>
          ) : null}
          {Object.entries(httpCoverage).map(([key, entry]) => (
            <BarRow
              key={key}
              label={key
                .replace(/_/g, "-")
                .toUpperCase()
                .replace("REFERRER", "Referrer")}
              value={entry?.pct ?? 0}
              max={100}
              tone={coverageTone(entry?.pct ?? 0)}
              /* The count as well as the share: "75%" over 12 services and
                 over 4 are different facts. */
              valDisplay={
                typeof entry?.count === "number"
                  ? `${entry.pct}% (${entry.count})`
                  : `${entry?.pct ?? 0}%`
              }
            />
          ))}
        </>
      )}
    </Panel>
  );
}

// ── 11. Compliance Panel ──────────────────────────────────────────────────────

function CompliancePanel({ compliance, loading }) {
  const action = (
    <CcureButton as={Link} to="/reports" variant="secondary" size="sm">
      Reports <span aria-hidden="true">→</span>
    </CcureButton>
  );

  if (loading)
    return (
      <Panel
        icon={<CcureIcon name="check-circle" />}
        title="Compliance Posture"
        action={action}
      >
        <div className="sd-frameworks">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <CcureSkeleton key={i} height={70} />
          ))}
        </div>
      </Panel>
    );

  const frameworks = compliance?.frameworks || [];

  return (
    <Panel
      icon={<CcureIcon name="check-circle" />}
      title="Compliance Posture"
      subtitle="Derived from scan findings · frameworks updated on each scan"
      action={action}
    >
      <ul className="sd-frameworks">
        {frameworks.map((fw) => {
          const score = Math.round(fw.score);
          const tone =
            score >= 80 ? "success" : score >= 60 ? "warning" : "high";
          return (
            <li key={fw.id} className="sd-framework">
              <span className={`sd-framework__pct sd-tone--${tone}`}>
                {score}%
              </span>
              <span className="sd-framework__name">{fw.name}</span>
              <span className="sd-progress" aria-hidden="true">
                <span
                  className={`sd-progress__fill sd-fill--${tone}`}
                  style={{ width: `${score}%` }}
                />
              </span>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

// ── 12. Insights Strip ────────────────────────────────────────────────────────

function InsightsStrip({ insights }) {
  const cards = insights || [];
  if (cards.length === 0) return null;

  return (
    <ul className="sd-insights">
      {cards.map((ins) => (
        <li
          key={ins.id}
          className={`sd-insight sd-insight--${ins.severity || "medium"}`}
        >
          <span className="sd-insight__icon" aria-hidden="true">
            <CcureIcon name={iconForBackendGlyph(ins.icon, "alert-triangle")} />
          </span>
          <div className="sd-insight__body">
            <div className="sd-insight__title">{ins.title}</div>
            <div className="sd-insight__detail">{ins.detail}</div>
          </div>
        </li>
      ))}
    </ul>
  );
}

// ── 13. Audit Timeline ────────────────────────────────────────────────────────

const ACTION_ICON = {
  scan_started: "radio",
  scan_completed: "check-circle",
  scan_failed: "x-circle",
  vulnerability_found: "alert-octagon",
  user_created: "user",
  user_login: "key",
  asset_updated: "monitor",
  finding_accepted: "check",
  finding_fixed: "tool",
  report_generated: "file-text",
};

const ACTION_TONE = {
  vulnerability_found: "danger",
  scan_failed: "danger",
  scan_started: "info",
  scan_completed: "success",
  user_created: "accent",
  finding_fixed: "success",
  report_generated: "warning",
};

function AuditTimeline() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    import("@shell/api/axiosInstance").then(({ default: api }) => {
      api
        .get("/admin/audit-logs", { params: { limit: 6 } })
        .then((r) => setLogs(r.data?.logs || []))
        .catch(() => {})
        .finally(() => setLoading(false));
    });
  }, []);

  return (
    <Panel
      icon={<CcureIcon name="clipboard" />}
      title="Activity & Audit Timeline"
      subtitle="Immutable · SOC 2 / ISO 27001 ready"
      action={
        <CcureButton
          as={Link}
          to="/admin/audit-logs"
          variant="secondary"
          size="sm"
        >
          Full Log <span aria-hidden="true">→</span>
        </CcureButton>
      }
    >
      {loading && <SkeletonRows count={5} />}

      {!loading && logs.length === 0 && (
        <CcureEmptyState
          icon={<CcureIcon name="clipboard" />}
          title="No audit events yet"
        />
      )}

      {!loading && logs.length > 0 && (
        <ul className="sd-feed">
          {logs.map((log) => (
            <li key={log.id} className="sd-feed__row">
              <span
                className={`sd-feed__icon sd-feed__icon--${ACTION_TONE[log.action] || "neutral"}`}
                aria-hidden="true"
              >
                <CcureIcon name={ACTION_ICON[log.action] || "flag"} />
              </span>
              <div className="sd-feed__body">
                <div className="sd-feed__title">
                  {log.action?.replace(/_/g, " ")}
                </div>
                <div className="sd-feed__sub">
                  {log.username
                    ? `${log.username} · `
                    : log.user_id
                      ? `uid:...${log.user_id.slice(-6)} · `
                      : ""}
                  {log.resource_type} · {log.status}
                </div>
              </div>
              <span className="sd-feed__time">{ago(log.created_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

// ── 14. Notification Center ───────────────────────────────────────────────────

const TYPE_ICON = {
  scan_completed: "radio",
  scan_failed: "x-circle",
  vulnerability_found: "alert-octagon",
  system_message: "info",
  admin_notice: "user",
};

const TYPE_TONE = {
  vulnerability_found: "danger",
  scan_failed: "danger",
  scan_completed: "info",
  system_message: "warning",
  admin_notice: "accent",
};

function NotifCenter() {
  const [notifs, setNotifs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    import("@shell/api/axiosInstance").then(({ default: api }) => {
      api
        .get("/notifications", { params: { limit: 5, unread_only: true } })
        .then((r) => setNotifs(r.data?.notifications || []))
        .catch(() => {})
        .finally(() => setLoading(false));
    });
  }, []);

  return (
    <Panel
      icon={<CcureIcon name="bell" />}
      title="Notification Center"
      action={
        <CcureButton
          as={Link}
          to="/notifications"
          variant="secondary"
          size="sm"
        >
          View All<span className="cc-sr-only"> notifications</span>{" "}
          <span aria-hidden="true">→</span>
        </CcureButton>
      }
    >
      {loading && <SkeletonRows count={3} />}

      {!loading && notifs.length === 0 && (
        <CcureEmptyState
          icon={<CcureIcon name="bell" />}
          title="No unread notifications"
        />
      )}

      {!loading && notifs.length > 0 && (
        <ul className="sd-feed">
          {notifs.map((n) => (
            <li key={n.id} className="sd-feed__row">
              <span
                className={`sd-feed__icon sd-feed__icon--${TYPE_TONE[n.type] || "neutral"}`}
                aria-hidden="true"
              >
                <CcureIcon name={TYPE_ICON[n.type] || "flag"} />
              </span>
              <div className="sd-feed__body">
                <div className="sd-feed__title">
                  {/* Unread was a coloured dot drawn by CSS and nothing else. */}
                  {!n.is_read && (
                    <>
                      <span className="sd-unread-dot" aria-hidden="true" />
                      <span className="cc-sr-only">Unread: </span>
                    </>
                  )}
                  {n.title}
                </div>
                <div className="sd-feed__sub">{n.message}</div>
              </div>
              <span className="sd-feed__time">{ago(n.created_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN DATA HOOK
// ═════════════════════════════════════════════════════════════════════════════

function useDashboard() {
  const [state, setState] = useState({
    summary: null,
    breakdown: null,
    topAssets: null,
    topCVEs: null,
    services: null,
    tlsHealth: null,
    httpHeaders: null,
    compliance: null,
    assetBreakdown: null,
    scanActivity: null,
    insights: null,
    loading: true,
    error: null,
  });

  const load = useCallback(async () => {
    setState((s) => ({ ...s, loading: true, error: null }));

    const results = await Promise.allSettled([
      getDashboardSummary(), // 0
      getRiskBreakdown(), // 1
      getTopAssets(10), // 2
      getTopCVEs(8, "Critical,High"), // 3
      getServicesExposure(), // 4
      getTLSHealth(), // 5
      getHTTPHeaders(), // 6
      getCompliance(), // 7
      getAssetBreakdown(), // 8
      getScanActivity(8), // 9
      getInsights(), // 10
    ]);

    const ok = (r, key) =>
      r.status === "fulfilled"
        ? r.value?.data?.[key] || r.value?.data || null
        : null;

    setState({
      summary:
        results[0].status === "fulfilled" ? results[0].value?.data : null,
      breakdown:
        results[1].status === "fulfilled" ? results[1].value?.data : null,
      topAssets: ok(results[2], "assets"),
      topCVEs: ok(results[3], "cves"),
      services: ok(results[4], "services"),
      tlsHealth:
        results[5].status === "fulfilled" ? results[5].value?.data : null,
      httpHeaders:
        results[6].status === "fulfilled" ? results[6].value?.data : null,
      compliance:
        results[7].status === "fulfilled" ? results[7].value?.data : null,
      assetBreakdown:
        results[8].status === "fulfilled" ? results[8].value?.data : null,
      scanActivity: ok(results[9], "scans"),
      insights: ok(results[10], "insights"),
      loading: false,
      error: null,
    });
  }, []);

  // Initial load
  useEffect(() => {
    load();
  }, [load]);

  // Auto-refresh scan activity every 30s
  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const r = await getScanActivity(8);
        setState((s) => ({
          ...s,
          scanActivity: r.data?.scans || s.scanActivity,
        }));
      } catch {
        /* silent */
      }
    }, 30_000);
    return () => clearInterval(t);
  }, []);

  return { ...state, refresh: load };
}

// ═════════════════════════════════════════════════════════════════════════════
// DATE RANGE
// ═════════════════════════════════════════════════════════════════════════════

const DATE_RANGES = [
  "Last 7 days",
  "Last 30 days",
  "Last 90 days",
  "Year to date",
];

/* Was a <div> with a click handler, so the choice could not be reached from
   the keyboard; the options also stated the current range by colour and a
   tick. A disclosure button now, each option stating its state with
   aria-current through the shared menu, and Escape restores its trigger. Choosing a range
   reloads the panels exactly as it did — the range is not sent. */
function DateRangeControl({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const menuId = useId();
  return (
    <CcureDropdown
      open={open}
      onOpenChange={setOpen}
      label="Date range"
      id={menuId}
      className="sd-daterange"
      align="end"
      trigger={({ ref, buttonProps }) => (
        <CcureButton
          {...buttonProps}
          ref={ref}
          variant="secondary"
          size="sm"
          aria-label={`Date range: ${value}`}
        >
          <CcureIcon name="calendar" /> {value}{" "}
          <span aria-hidden="true">▼</span>
        </CcureButton>
      )}
    >
      {DATE_RANGES.map((range) => (
        <CcureMenuItem
          key={range}
          aria-current={range === value ? "true" : undefined}
          onClick={() => onChange(range)}
        >
          <span aria-hidden="true">{range === value ? "✓" : ""}</span> {range}
        </CcureMenuItem>
      ))}
    </CcureDropdown>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// PAGE COMPONENT
// ═════════════════════════════════════════════════════════════════════════════

export default function SecurityDashboard() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();

  const [showWelcomeModal, setShowWelcomeModal] = useState(() => {
    return !!location.state?.isNewRegistration;
  });

  const handleCloseWelcomeModal = useCallback(() => {
    setShowWelcomeModal(false);
    navigate("/audit-dashboard", { replace: true, state: {} });
  }, [navigate]);

  useEffect(() => {
    if (user && !canPermission(user, "audit.dashboard.read")) {
      navigate("/scan", { replace: true });
    }
  }, [user, navigate]);

  const db = useDashboard();
  const [activeTab, setActiveTab] = useState("overview");
  const [dateRange, setDateRange] = useState("Last 30 days");
  const tabsModel = useCcureTabs("overview", {
    value: activeTab,
    onChange: setActiveTab,
  });

  const canAssets = canPermission(user, "audit.asset.read");
  const canFindings = canPermission(user, "audit.finding.read");
  const canReports = canPermission(user, "audit.report.read");
  const canAudit = canPermission(user, "platform.audit_log.read");

  const nav = useCallback((path) => navigate(path), [navigate]);

  // Alert banners from real data
  const critCount = db.summary?.severity?.critical || 0;
  const kevCount = db.summary?.kev?.open_count || 0;
  const certExpire = db.tlsHealth?.expiring_in_30d || 0;
  const hasAlerts = critCount > 0 || certExpire > 0;

  const lastUpdated = new Date().toLocaleTimeString();

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "assets", label: "Assets", show: canAssets },
    { id: "vulns", label: "Vulnerabilities", show: canFindings },
    { id: "scans", label: "Scans" },
    { id: "compliance", label: "Compliance", show: canReports },
    { id: "audit", label: "Audit", show: canAudit },
  ].filter((t) => t.show !== false);

  return (
    <AppLayout pageTitle="Audit Dashboard">
      <CcurePage className="sd-page">
        {/* Always mounted, so there is something to observe changing. */}
        <div role="status" aria-live="polite" className="cc-sr-only">
          {db.loading ? "Loading dashboard…" : ""}
        </div>

        {/* ── Page Header ── */}
        <CcurePageHeader
          title="Audit Dashboard"
          subtitle={
            <>
              <span className="sd-live-dot" aria-hidden="true" />
              Last updated: {lastUpdated} · {db.summary?.scans?.running || 0}{" "}
              scans running
            </>
          }
          actions={
            <div className="sd-header-actions">
              <DateRangeControl
                value={dateRange}
                onChange={(range) => {
                  setDateRange(range);
                  db.refresh();
                }}
              />
              {canReports && (
                <CcureButton
                  as={Link}
                  to="/reports"
                  variant="secondary"
                  size="sm"
                >
                  <span aria-hidden="true">⬇</span> Export PDF
                </CcureButton>
              )}
              <CcureButton as={Link} to="/scan" variant="primary" size="sm">
                + New Scan
              </CcureButton>
            </div>
          }
        />

        {/* ── Tab Bar ── Buttons with an "active" class and no tab semantics
            before; CcureTabs is the WAI-ARIA pattern, arrows included. */}
        <CcureTabs
          {...tabsModel.listProps}
          tabs={tabs}
          label="Dashboard views"
          className="sd-tabs"
        />

        {/* ── Alert Banners (real data) ── Part of the page as it loads, not
            events, so they are not announced as interruptions. */}
        {hasAlerts && (
          <div className="sd-alerts">
            {critCount > 0 && (
              <CcureAlert variant="danger" live={false}>
                <span className="sd-alert__row">
                  <span>
                    <strong>
                      {critCount} Critical{" "}
                      {critCount === 1 ? "vulnerability" : "vulnerabilities"}
                    </strong>
                    {kevCount > 0 && (
                      <>
                        {" "}
                        including{" "}
                        <strong>
                          {kevCount} CISA KEV-listed CVE
                          {kevCount > 1 ? "s" : ""}
                        </strong>
                      </>
                    )}
                    . Immediate remediation required.
                  </span>
                  <CcureButton
                    as={Link}
                    to="/vulnerabilities?severity=Critical"
                    variant="danger"
                    size="sm"
                  >
                    View Now
                  </CcureButton>
                </span>
              </CcureAlert>
            )}
            {certExpire > 0 && (
              <CcureAlert variant="warning" live={false}>
                <strong>
                  {certExpire} TLS{" "}
                  {certExpire === 1 ? "certificate" : "certificates"} expiring
                </strong>{" "}
                within 30 days. Renew before expiry to prevent service
                disruption.
              </CcureAlert>
            )}
          </div>
        )}

        {/* ═══════════ OVERVIEW TAB ═══════════ */}
        <CcureTabPanel {...tabsModel.panelProps("overview")}>
          <section className="sd-section" aria-labelledby="sd-posture-title">
            <h2 className="sd-section-title" id="sd-posture-title">
              Security Posture at a Glance
            </h2>
            <MetricCards summary={db.summary} loading={db.loading} />
            {!db.loading && <SevBar summary={db.summary} />}
          </section>

          {!db.loading && db.insights && db.insights.length > 0 && (
            <section className="sd-section" aria-labelledby="sd-insights-title">
              <h2 className="sd-section-title" id="sd-insights-title">
                AI Insights
              </h2>
              <InsightsStrip insights={db.insights} />
            </section>
          )}

          <div className="sd-section">
            <div className="sd-grid-3">
              <RiskScorePanel
                summary={db.summary}
                breakdown={db.breakdown}
                httpHeaders={db.httpHeaders}
                loading={db.loading}
              />
              <FindingsDonut
                summary={db.summary}
                breakdown={db.breakdown}
                loading={db.loading}
              />
              <ScanActivity scans={db.scanActivity} loading={db.loading} />
            </div>
          </div>

          {canAssets && (
            <div className="sd-section">
              <TopAssetsTable
                assets={db.topAssets}
                loading={db.loading}
                onNavigate={nav}
              />
            </div>
          )}

          {canFindings && (
            <div className="sd-section">
              <div className="sd-grid-2">
                <TopCVEsTable
                  cves={db.topCVEs}
                  loading={db.loading}
                  onNavigate={nav}
                />
                {canAudit ? <AuditTimeline /> : <NotifCenter />}
              </div>
            </div>
          )}

          {canAssets && (
            <div className="sd-section">
              <div className="sd-grid-3">
                <AssetBreakdownPanel
                  assetBreakdown={db.assetBreakdown}
                  loading={db.loading}
                />
                <ServiceExposurePanel
                  services={db.services}
                  loading={db.loading}
                />
                <TLSHealthPanel
                  tlsHealth={db.tlsHealth}
                  httpHeaders={db.httpHeaders}
                  loading={db.loading}
                />
              </div>
            </div>
          )}

          {canReports && (
            <div className="sd-section">
              <CompliancePanel
                compliance={db.compliance}
                loading={db.loading}
              />
            </div>
          )}
        </CcureTabPanel>

        {/* ═══════════ ASSETS TAB ═══════════ */}
        {canAssets && (
          <CcureTabPanel {...tabsModel.panelProps("assets")}>
            <section className="sd-section" aria-labelledby="sd-assets-title">
              <h2 className="sd-section-title" id="sd-assets-title">
                Asset Registry — Quick View
              </h2>
              <div className="sd-stack">
                <div className="sd-grid-2">
                  <AssetBreakdownPanel
                    assetBreakdown={db.assetBreakdown}
                    loading={db.loading}
                  />
                  <ServiceExposurePanel
                    services={db.services}
                    loading={db.loading}
                  />
                </div>
                <TopAssetsTable
                  assets={db.topAssets}
                  loading={db.loading}
                  onNavigate={nav}
                />
                <div className="sd-more">
                  <CcureButton as={Link} to="/assets" variant="primary">
                    Open Full Asset Registry <span aria-hidden="true">→</span>
                  </CcureButton>
                </div>
              </div>
            </section>
          </CcureTabPanel>
        )}

        {/* ═══════════ VULNERABILITIES TAB ═══════════ */}
        {canFindings && (
          <CcureTabPanel {...tabsModel.panelProps("vulns")}>
            <section className="sd-section" aria-labelledby="sd-vulns-title">
              <h2 className="sd-section-title" id="sd-vulns-title">
                Vulnerability Intelligence — Quick View
              </h2>
              <div className="sd-stack">
                <div className="sd-grid-2">
                  <FindingsDonut
                    summary={db.summary}
                    breakdown={db.breakdown}
                    loading={db.loading}
                  />
                  <RiskScorePanel
                    summary={db.summary}
                    breakdown={db.breakdown}
                    httpHeaders={db.httpHeaders}
                    loading={db.loading}
                  />
                </div>
                <TopCVEsTable
                  cves={db.topCVEs}
                  loading={db.loading}
                  onNavigate={nav}
                />
                <div className="sd-more">
                  <CcureButton
                    as={Link}
                    to="/vulnerabilities"
                    variant="primary"
                  >
                    Open Full Vulnerability Browser{" "}
                    <span aria-hidden="true">→</span>
                  </CcureButton>
                </div>
              </div>
            </section>
          </CcureTabPanel>
        )}

        {/* ═══════════ COMPLIANCE TAB ═══════════ */}
        {canReports && (
          <CcureTabPanel {...tabsModel.panelProps("compliance")}>
            <section
              className="sd-section"
              aria-labelledby="sd-compliance-title"
            >
              <h2 className="sd-section-title" id="sd-compliance-title">
                Compliance &amp; Security Posture
              </h2>
              <div className="sd-stack">
                <CompliancePanel
                  compliance={db.compliance}
                  loading={db.loading}
                />
                <TLSHealthPanel
                  tlsHealth={db.tlsHealth}
                  httpHeaders={db.httpHeaders}
                  loading={db.loading}
                />
              </div>
            </section>
          </CcureTabPanel>
        )}

        {/* ═══════════ SCANS TAB ═══════════ */}
        <CcureTabPanel {...tabsModel.panelProps("scans")}>
          <section className="sd-section" aria-labelledby="sd-scans-title">
            <h2 className="sd-section-title" id="sd-scans-title">
              Scan Activity &amp; History
            </h2>
            <div className="sd-stack">
              <ScanActivity scans={db.scanActivity} loading={db.loading} />
              <div className="sd-more">
                <CcureButton as={Link} to="/history" variant="primary">
                  Open Full Scan History <span aria-hidden="true">→</span>
                </CcureButton>
              </div>
            </div>
          </section>
        </CcureTabPanel>

        {/* ═══════════ AUDIT TAB ═══════════ The page has never had audit
            content for this tab; the panel exists so the tab's aria-controls
            names a real element. Recorded as a product question. */}
        {canAudit && <CcureTabPanel {...tabsModel.panelProps("audit")} />}

        {/* ═══════════ WELCOME ONBOARDING MODAL ═══════════ A backdrop and a
            panel before, with no dialog role, no focus trap and no Escape. */}
        <CcureModal
          open={showWelcomeModal}
          onClose={handleCloseWelcomeModal}
          title="Welcome to CCure Audit PRO!"
          size="md"
          footer={
            <>
              <CcureButton
                variant="primary"
                onClick={() => {
                  handleCloseWelcomeModal();
                  nav("/scan");
                }}
              >
                Launch First Scan <span aria-hidden="true">→</span>
              </CcureButton>
              <CcureButton
                variant="secondary"
                onClick={handleCloseWelcomeModal}
              >
                Explore Dashboard
              </CcureButton>
            </>
          }
        >
          <div className="sd-welcome__icon" aria-hidden="true">
            <CcureIcon name="shield" />
          </div>
          <p className="sd-welcome__text">
            Your account has been successfully created. You&apos;re ready to
            start auditing, running vulnerability scans, and monitoring
            enterprise compliance posture.
          </p>
        </CcureModal>
      </CcurePage>
    </AppLayout>
  );
}
