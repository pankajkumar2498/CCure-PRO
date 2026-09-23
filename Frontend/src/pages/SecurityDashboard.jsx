/**
 * src/pages/SecurityDashboard.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * SOC-style Security Overview Dashboard — the primary landing page after login.
 *
 * Replaces the current /dashboard route (scan template picker moves to /scan).
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

import { useState, useEffect, useCallback, useId, useRef } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { canPermission } from "../auth/permissions";
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
} from "../api/dashboard";
import CVELink from "../components/common/CVELink";
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
} from "../design-system";
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
  const id = useId();
  return (
    <section
      className={`sd-card${flush ? " sd-card--flush" : ""}`}
      aria-labelledby={id}
    >
      <div className="sd-card__head">
        <div>
          <h2 className="sd-card__title" id={id}>
            {icon ? (
              <>
                <span aria-hidden="true">{icon}</span>{" "}
              </>
            ) : null}
            {title}
          </h2>
          {subtitle ? <p className="sd-card__sub">{subtitle}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
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
          <div key={i} className="sd-metric">
            <CcureSkeleton width="60%" height={10} />
            <CcureSkeleton width="50%" height={28} />
            <CcureSkeleton width="80%" height={10} />
          </div>
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
    if (val > 0) return { label: `🔺 +${val} from last scan`, tone: "bad" };
    if (val < 0)
      return { label: `🔻 ${Math.abs(val)} remediated`, tone: "good" };
    return { label: "— unchanged", tone: "neutral" };
  };

  const getRiskTrend = (val) => {
    if (val > 0) return { label: `🔺 +${val} pts vs last week`, tone: "bad" };
    if (val < 0)
      return { label: `🔻 ${Math.abs(val)} pts vs last week`, tone: "good" };
    return { label: "— stable", tone: "neutral" };
  };

  const getAssetTrend = (val) => {
    if (val > 0) return { label: `🔺 +${val} new hosts`, tone: "good" };
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
      sub: `${ast.unmanaged || 0} unmanaged`,
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
      sub: `Plan limit ${scn.quota_limit_24h || 50}/day`,
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
        <Link
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
        </Link>
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
  basic: "📡",
  asset: "🔍",
  advanced: "⚡",
  vulnerability_audit: "⚡",
  credentialed: "🔑",
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
        <CcureEmptyState icon="📡" title="No recent scans" />
      )}

      {scanList.length > 0 && (
        <ul className="sd-feed">
          {scanList.map((scan) => {
            const isCredentialed = scan.scan_type === "credentialed";
            const modeIcon = isCredentialed
              ? MODE_ICON.credentialed
              : MODE_ICON[scan.pipeline_mode] || "📡";

            return (
              <li key={scan.id} className="sd-feed__row">
                <span
                  className={`sd-feed__icon sd-feed__icon--${activityTone(scan.status)}`}
                  aria-hidden="true"
                >
                  {modeIcon}
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
      icon="🖥"
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
                </td>
                <td>
                  <span className="sd-chip">
                    {a.os_name || a.os_family || "Unknown"}
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
      icon="🔥"
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
                  {c.in_kev && (
                    <span className="sd-flag sd-flag--kev">KEV</span>
                  )}
                </td>
              </tr>
            );
          })}
      </CcureTable>
    </Panel>
  );
}

// ── 8. Asset Breakdown ────────────────────────────────────────────────────────

const OS_ICON = {
  Linux: "🐧",
  Windows: "🪟",
  macOS: "🍎",
  BSD: "🐡",
  Unknown: "❓",
};

function AssetBreakdownPanel({ assetBreakdown, loading }) {
  if (loading)
    return (
      <Panel icon="🖥" title="Asset Inventory">
        <CcureSkeleton height={80} />
      </Panel>
    );

  const t = assetBreakdown?.totals || {};
  const os = assetBreakdown?.os_distribution || [];

  return (
    <Panel
      icon="🖥"
      title="Asset Inventory"
      subtitle={`${fmt(t.total)} total assets`}
    >
      <ul className="sd-os">
        {os.slice(0, 6).map((o) => (
          <li key={o.os_family} className="sd-os__item">
            <span className="sd-os__icon" aria-hidden="true">
              {OS_ICON[o.os_family] || "💻"}
            </span>
            <span className="sd-os__count">{o.count}</span>
            <span className="sd-os__name">{o.os_family}</span>
          </li>
        ))}
      </ul>
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
      <Panel icon="🔓" title="Top Exposed Services">
        <CcureSkeleton height={160} />
      </Panel>
    );

  const top = (services || []).slice(0, 10);
  const maxCount = Math.max(...top.map((s) => s.asset_count), 1);

  return (
    <Panel
      icon="🔓"
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
      <Panel icon="🔐" title="TLS & HTTP Security">
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
      icon="🔐"
      title="TLS & HTTP Security"
      subtitle={
        <>
          {tls.expiring_in_30d > 0 ? (
            <span className="sd-strong sd-tone--danger">
              ⚠ {tls.expiring_in_30d} certs expiring in 30d ·{" "}
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
      {Object.entries(httpCoverage).map(([key, { pct: p }]) => (
        <BarRow
          key={key}
          label={key
            .replace(/_/g, "-")
            .toUpperCase()
            .replace("REFERRER", "Referrer")}
          value={p}
          max={100}
          tone={coverageTone(p)}
          valDisplay={`${p}%`}
        />
      ))}
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
      <Panel icon="✅" title="Compliance Posture" action={action}>
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
      icon="✅"
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
            {ins.icon}
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
  scan_started: "📡",
  scan_completed: "✅",
  scan_failed: "❌",
  vulnerability_found: "🚨",
  user_created: "👤",
  user_login: "🔑",
  asset_updated: "🖥",
  finding_accepted: "✔",
  finding_fixed: "🛠",
  report_generated: "📄",
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
    import("../api/axiosInstance").then(({ default: api }) => {
      api
        .get("/admin/audit-logs", { params: { limit: 6 } })
        .then((r) => setLogs(r.data?.logs || []))
        .catch(() => {})
        .finally(() => setLoading(false));
    });
  }, []);

  return (
    <Panel
      icon="📋"
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
        <CcureEmptyState icon="📋" title="No audit events yet" />
      )}

      {!loading && logs.length > 0 && (
        <ul className="sd-feed">
          {logs.map((log) => (
            <li key={log.id} className="sd-feed__row">
              <span
                className={`sd-feed__icon sd-feed__icon--${ACTION_TONE[log.action] || "neutral"}`}
                aria-hidden="true"
              >
                {ACTION_ICON[log.action] || "📌"}
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
  scan_completed: "📡",
  scan_failed: "❌",
  vulnerability_found: "🚨",
  system_message: "ℹ️",
  admin_notice: "👤",
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
    import("../api/axiosInstance").then(({ default: api }) => {
      api
        .get("/notifications", { params: { limit: 5, unread_only: true } })
        .then((r) => setNotifs(r.data?.notifications || []))
        .catch(() => {})
        .finally(() => setLoading(false));
    });
  }, []);

  return (
    <Panel
      icon="🔔"
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
        <CcureEmptyState icon="🔔" title="No unread notifications" />
      )}

      {!loading && notifs.length > 0 && (
        <ul className="sd-feed">
          {notifs.map((n) => (
            <li key={n.id} className="sd-feed__row">
              <span
                className={`sd-feed__icon sd-feed__icon--${TYPE_TONE[n.type] || "neutral"}`}
                aria-hidden="true"
              >
                {TYPE_ICON[n.type] || "📌"}
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
   aria-pressed, and Escape closes it and returns focus. Choosing a range
   reloads the panels exactly as it did — the range is not sent. */
function DateRangeControl({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const menuId = useId();
  const toggleRef = useRef(null);

  const close = () => {
    setOpen(false);
    toggleRef.current?.focus();
  };

  return (
    <div
      className="sd-daterange"
      onKeyDown={(e) => {
        if (e.key === "Escape" && open) {
          e.stopPropagation();
          close();
        }
      }}
    >
      <button
        ref={toggleRef}
        type="button"
        className="sd-daterange__toggle"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={`Date range: ${value}`}
        onClick={() => setOpen((s) => !s)}
      >
        <span aria-hidden="true">📅</span> {value}{" "}
        <span className="sd-daterange__caret" aria-hidden="true">
          ▼
        </span>
      </button>
      {open && (
        <div
          id={menuId}
          role="group"
          aria-label="Date range"
          className="sd-daterange__menu"
        >
          {DATE_RANGES.map((range) => (
            <button
              key={range}
              type="button"
              aria-pressed={range === value}
              className={`sd-daterange__option${range === value ? " sd-daterange__option--on" : ""}`}
              onClick={() => {
                close();
                onChange(range);
              }}
            >
              <span className="sd-daterange__check" aria-hidden="true">
                {range === value ? "✓" : ""}
              </span>
              {range}
            </button>
          ))}
        </div>
      )}
    </div>
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
    navigate("/dashboard", { replace: true, state: {} });
  }, [navigate]);

  useEffect(() => {
    if (
      user &&
      !canPermission(user, { resource: "dashboard", action: "read" })
    ) {
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

  const canAssets = canPermission(user, { resource: "assets", action: "read" });
  const canFindings = canPermission(user, {
    resource: "findings",
    action: "read",
  });
  const canReports = canPermission(user, {
    resource: "reports",
    action: "read",
  });
  const canAudit = canPermission(user, { resource: "audit", action: "read" });

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
    <AppLayout
      pageTitle="Security Dashboard"
      onNewScan={() => navigate("/scan")}
    >
      <div className="sd-page">
        {/* Always mounted, so there is something to observe changing. */}
        <div role="status" aria-live="polite" className="cc-sr-only">
          {db.loading ? "Loading dashboard…" : ""}
        </div>

        {/* ── Page Header ── */}
        <div className="sd-page-header">
          <div>
            <h1 className="sd-page-title">Security Dashboard</h1>
            <p className="sd-page-subtitle">
              <span className="sd-live-dot" aria-hidden="true" />
              Last updated: {lastUpdated} · {db.summary?.scans?.running || 0}{" "}
              scans running
            </p>
          </div>
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
        </div>

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
            🛡️
          </div>
          <p className="sd-welcome__text">
            Your account has been successfully created. You&apos;re ready to
            start auditing, running vulnerability scans, and monitoring
            enterprise compliance posture.
          </p>
        </CcureModal>
      </div>
    </AppLayout>
  );
}
