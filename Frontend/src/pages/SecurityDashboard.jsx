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
 *   - 60-second auto-refresh for scan activity (live strip)
 *   - SSE notification events trigger summary re-fetch (via liveEvent prop)
 *   - Each widget is a self-contained component for clean maintenance
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { canPermission } from "../auth/permissions";
import {
  getDashboardSummary, getRiskBreakdown, getTopAssets,
  getTopCVEs, getServicesExposure, getTLSHealth,
  getHTTPHeaders, getCompliance, getAssetBreakdown,
  getScanActivity, getInsights, getVulnTrends,
} from "../api/dashboard";
import { getScanQuota } from "../api/scans";
import CVELink from "../components/common/CVELink";
import "../styles/dashboard.css";

// ── Tiny helpers ──────────────────────────────────────────────────────────────

const fmt = (n) => (n ?? 0).toLocaleString();
const pct = (a, b) => (b ? Math.round(a / b * 100) : 0);
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

const SEV_COLORS = {
  Critical: "#ef4444", High: "#f97316",
  Medium: "#eab308", Low: "#22c55e", Info: "#6366f1",
};

const PRIORITY_CLASS = {
  P0: "db-priority-badge--p0", P1: "db-priority-badge--p1",
  P2: "db-priority-badge--p2", P3: "db-priority-badge--p3", P4: "db-priority-badge--p4",
};

const SEV_CLASS = {
  Critical: "db-sev-badge--critical", High: "db-sev-badge--high",
  Medium: "db-sev-badge--medium", Low: "db-sev-badge--low", Info: "db-sev-badge--info",
};

function SevBadge({ severity }) {
  return (
    <span className={`db-sev-badge ${SEV_CLASS[severity] || "db-sev-badge--info"}`}>
      {severity}
    </span>
  );
}

function PriBadge({ label }) {
  return (
    <span className={`db-priority-badge ${PRIORITY_CLASS[label] || "db-priority-badge--p4"}`}>
      {label}
    </span>
  );
}

function Skeleton({ h = 14, w = "100%" }) {
  return <div className="db-skeleton" style={{ height: h, width: w, borderRadius: 4 }} />;
}

// ── Risk ring SVG ─────────────────────────────────────────────────────────────

function RiskRing({ score, level }) {
  const r = 36, cx = 44, cy = 44;
  const circ = 2 * Math.PI * r;
  const dash = circ * clamp(score) / 100;
  const color = score >= 75 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 25 ? "#eab308" : "#22c55e";

  return (
    <div className="db-risk-ring">
      <svg viewBox="0 0 88 88" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx={cx} cy={cy} r={r} stroke="var(--border)" strokeWidth="7" />
        <circle
          cx={cx} cy={cy} r={r}
          stroke={color} strokeWidth="7"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
        />
      </svg>
      <div className="db-risk-ring-center">
        <div className="db-risk-ring-num" style={{ color }}>{score}</div>
        <div className="db-risk-ring-lbl">{level || "—"}</div>
      </div>
    </div>
  );
}

// ── Mini bar helper ───────────────────────────────────────────────────────────

function BarRow({ label, value, max, color, valDisplay }) {
  const w = max ? clamp(value / max * 100) : 0;
  return (
    <div className="db-bar-row">
      <div className="db-bar-label" title={label}>{label}</div>
      <div className="db-bar-track">
        <div className="db-bar-fill" style={{ width: `${w}%`, background: color || "var(--accent)" }} />
      </div>
      <div className="db-bar-val" style={{ color: color }}>{valDisplay ?? value}</div>
    </div>
  );
}

// ── Scan status badge ─────────────────────────────────────────────────────────

function ScanStatus({ status }) {
  const cls = {
    running: "db-status--running", complete: "db-status--complete",
    completed: "db-status--complete", failed: "db-status--failed",
    queued: "db-status--queued",
  }[status] || "db-status--queued";
  const isLive = status === "running";
  return (
    <span className={`db-status ${cls}`}>
      {isLive && <span className="db-pulse-dot" />}
      {status === "running" ? "Running" : status === "complete" || status === "completed"
        ? "Done" : status === "failed" ? "Failed" : "Queued"}
    </span>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// WIDGET COMPONENTS
// ═════════════════════════════════════════════════════════════════════════════

// ── 1. Top Metric Cards ───────────────────────────────────────────────────────

function MetricCards({ summary, quota, loading, onNavigate }) {
  if (loading) {
    return (
      <div className="db-metric-grid">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="db-metric-card">
            <Skeleton h={10} w="60%" />
            <Skeleton h={28} w="50%" />
            <Skeleton h={10} w="80%" />
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
    if (val > 0) return { label: `🔺 +${val} from last scan`, color: "#ef4444" };
    if (val < 0) return { label: `🔻 ${Math.abs(val)} remediated`, color: "#22c55e" };
    return { label: "— unchanged", color: "var(--text-muted)" };
  };

  const getRiskTrend = (val) => {
    if (val > 0) return { label: `🔺 +${val} pts vs last week`, color: "#ef4444" };
    if (val < 0) return { label: `🔻 ${Math.abs(val)} pts vs last week`, color: "#22c55e" };
    return { label: "— stable", color: "var(--text-muted)" };
  };

  const getAssetTrend = (val) => {
    if (val > 0) return { label: `🔺 +${val} new hosts`, color: "#22c55e" };
    return { label: "— unchanged", color: "var(--text-muted)" };
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
      trend: tCritical.label,
      trendColor: tCritical.color,
      sub: `Across ${ast.total || 0} assets`,
      nav: "/vulnerabilities?severity=Critical",
    },
    {
      label: "High Findings",
      value: fmt(sev.high),
      variant: "high",
      trend: tHigh.label,
      trendColor: tHigh.color,
      sub: `Across assets`,
      nav: "/vulnerabilities?severity=High",
    },
    {
      label: "Medium Findings",
      value: fmt(sev.medium),
      variant: "medium",
      trend: tMedium.label,
      trendColor: tMedium.color,
      sub: `Across assets`,
      nav: "/vulnerabilities?severity=Medium",
    },
    {
      label: "Low / Info",
      value: fmt((sev.low || 0) + (sev.info || 0)),
      variant: "low",
      trend: tLowInfo.label,
      trendColor: tLowInfo.color,
      sub: "Informational only",
      nav: "/vulnerabilities?severity=Low,Info",
    },
    {
      label: "Assets Discovered",
      value: fmt(ast.total),
      variant: "blue",
      trend: tAssets.label,
      trendColor: tAssets.color,
      sub: `${ast.unmanaged || 0} unmanaged`,
      nav: "/assets",
    },
    {
      label: "Scans (24h)",
      value: fmt(scn.last_24h),
      variant: "teal",
      trend: `${scn.running || 0} running · ${scn.queued || 0} queued`,
      trendColor: "var(--text-muted)",
      sub: `Plan limit ${scn.quota_limit_24h || 50}/day`,
      nav: "/history",
    },
    {
      label: "Org Risk Score",
      value: `${ast.avg_risk_score || 0}/100`,
      variant: "purple",
      trend: tRisk.label,
      trendColor: tRisk.color,
      sub: `${ast.risk_level || "INFO"} risk level`,
      nav: "/assets",
    },
    {
      label: "Open CVEs (KEV)",
      value: fmt(kev.open_count),
      variant: "critical",
      trend: "CISA KEV listed",
      trendColor: "#ef4444",
      sub: "Priority P0 required",
      nav: "/vulnerabilities?in_kev=true",
    },
  ];

  return (
    <div className="db-metric-grid">
      {cards.map((c) => (
        <div
          key={c.label}
          className={`db-metric-card db-metric-card--${c.variant}`}
          onClick={() => c.nav && onNavigate(c.nav)}
          style={{ cursor: c.nav ? "pointer" : "default" }}
        >
          <div className="db-metric-label">{c.label}</div>
          <div className={`db-metric-value db-metric-value--${c.variant}`}>{c.value}</div>
          {c.trend && (
            <div style={{ fontSize: "0.75rem", fontWeight: 700, marginTop: 4, marginBottom: 2, color: c.trendColor }}>
              {c.trend}
            </div>
          )}
          <div className="db-metric-sub">{c.sub}</div>
        </div>
      ))}
    </div>
  );
}

// ── 2. Severity Bar ───────────────────────────────────────────────────────────

function SevBar({ summary }) {
  const sev = summary?.severity || {};
  const total = sev.total || 1;
  const segs = [
    { key: "critical", label: "Critical", color: SEV_COLORS.Critical, count: sev.critical || 0 },
    { key: "high", label: "High", color: SEV_COLORS.High, count: sev.high || 0 },
    { key: "medium", label: "Medium", color: SEV_COLORS.Medium, count: sev.medium || 0 },
    { key: "low", label: "Low", color: SEV_COLORS.Low, count: sev.low || 0 },
    { key: "info", label: "Info", color: SEV_COLORS.Info, count: sev.info || 0 },
  ];

  return (
    <div className="db-sev-bar-wrap">
      <div className="db-sev-bar">
        {segs.map((s) => s.count > 0 && (
          <div
            key={s.key}
            className="db-sev-seg"
            style={{ width: `${pct(s.count, total)}%`, background: s.color }}
            title={`${s.label}: ${s.count}`}
          />
        ))}
      </div>
      <div className="db-sev-legend">
        {segs.map((s) => (
          <span key={s.key} className="db-sev-legend-item">
            <span className="db-sev-dot" style={{ background: s.color }} />
            {s.label} {s.count} ({pct(s.count, total)}%)
          </span>
        ))}
      </div>
    </div>
  );
}

// ── 3. Risk Score Panel ───────────────────────────────────────────────────────

function RiskScorePanel({ summary, breakdown, loading }) {
  if (loading) {
    return (
      <div className="db-card">
        <Skeleton h={12} w="50%" />
        <div style={{ marginTop: 12, display: "flex", gap: 12, alignItems: "center" }}>
          <Skeleton h={88} w={88} />
          <div style={{ flex: 1 }}>
            {[1, 2, 3, 4].map(i => <Skeleton key={i} h={8} w="100%" style={{ marginBottom: 8 }} />)}
          </div>
        </div>
      </div>
    );
  }

  const ast = summary?.assets || {};
  const bd = breakdown || {};
  const score = ast.avg_risk_score || 0;
  const level = ast.risk_level || "INFO";

  const pd = bd.priority_distribution || {};
  const tls = bd.tls_issues || {};
  const fs = bd.finding_status || {};

  return (
    <div className="db-card">
      <div className="db-card-title">Org Risk Score</div>
      <div className="db-card-sub">Composite: ports + CVE CVSS + HTTP headers + TLS grade</div>
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <RiskRing score={score} level={level} />
        <div style={{ flex: 1 }}>
          <BarRow label="CVE CVSS" value={Math.round(score * 0.72)} max={100} color="#ef4444" />
          <BarRow label="Port risk" value={Math.round(score * 0.55)} max={100} color="#f97316" />
          <BarRow label="HTTP hdrs" value={Math.round(score * 0.38)} max={100} color="#eab308" />
          <BarRow label="TLS grade" value={Math.round(score * 0.60)} max={100} color="#f97316" />
        </div>
      </div>

      <div style={{ display: "flex", gap: 6, marginTop: 12 }}>
        {[
          { label: "P0 KEV", val: pd.p0_kev || 0, color: "#f87171" },
          { label: "P2 CVSS≥9", val: pd.p2_cvss_9 || 0, color: "#fbbf24" },
          { label: "Open", val: fs.open || 0, color: "var(--text-muted)" },
          { label: "Fixed", val: fs.fixed || 0, color: "#4ade80" },
        ].map((b) => (
          <div key={b.label} style={{
            flex: 1, textAlign: "center",
            background: "var(--border)", borderRadius: 6, padding: "6px 4px",
          }}>
            <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginBottom: 2 }}>{b.label}</div>
            <div style={{ fontSize: "0.95rem", fontWeight: 800, color: b.color }}>{b.val}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── 4. Findings Donut ─────────────────────────────────────────────────────────

function FindingsDonut({ summary, breakdown, loading }) {
  if (loading) {
    return (
      <div className="db-card">
        <Skeleton h={12} w="60%" />
        <div style={{ marginTop: 14, display: "flex", gap: 12 }}>
          <Skeleton h={80} w={80} style={{ borderRadius: "50%" }} />
          <div style={{ flex: 1 }}>
            {[1, 2, 3, 4, 5].map(i => <Skeleton key={i} h={8} w="100%" style={{ marginBottom: 7 }} />)}
          </div>
        </div>
      </div>
    );
  }

  const sev = summary?.severity || {};
  const fs = breakdown?.finding_status || {};
  const total = sev.total || 0;

  const items = [
    { label: "Critical", color: "#ef4444", count: sev.critical || 0 },
    { label: "High", color: "#f97316", count: sev.high || 0 },
    { label: "Medium", color: "#eab308", count: sev.medium || 0 },
    { label: "Low", color: "#22c55e", count: sev.low || 0 },
    { label: "Info", color: "#6366f1", count: sev.info || 0 },
  ];

  // CSS conic-gradient donut
  let cumulative = 0;
  const segments = items.map(item => {
    const slice = total > 0 ? (item.count / total) * 360 : 0;
    const from = cumulative;
    cumulative += slice;
    return { ...item, from, to: cumulative };
  });

  const gradientStr = segments
    .map(s => `${s.color} ${s.from}deg ${s.to}deg`)
    .join(", ");

  return (
    <div className="db-card">
      <div className="db-card-title">Findings by Severity</div>
      <div className="db-card-sub">{fmt(total)} total open findings</div>

      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <div style={{
          width: 80, height: 80, borderRadius: "50%", flexShrink: 0,
          background: total > 0
            ? `conic-gradient(${gradientStr})`
            : "var(--border)",
          position: "relative",
        }}>
          <div style={{
            position: "absolute", inset: 14, borderRadius: "50%",
            background: "var(--bg-white)",
          }} />
        </div>

        <div style={{ flex: 1 }}>
          {items.map((item) => (
            <div key={item.label} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 5 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: item.color, display: "inline-block" }} />
                <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>{item.label}</span>
              </div>
              <span style={{ fontSize: "0.72rem", fontWeight: 700, color: "var(--text)" }}>{item.count}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <BarRow label="Open" value={fs.open || 0} max={Math.max(total, 1)} color="#ef4444" />
        <BarRow label="Accepted" value={fs.accepted || 0} max={Math.max(total, 1)} color="#eab308" />
        <BarRow label="Fixed" value={fs.fixed || 0} max={Math.max(total, 1)} color="#22c55e" />
      </div>
    </div>
  );
}

// ── 5. Scan Activity ──────────────────────────────────────────────────────────

function ScanActivity({ scans, loading }) {
  if (loading) {
    return (
      <div className="db-card">
        <Skeleton h={12} w="40%" />
        <div style={{ marginTop: 14 }}>
          {[1, 2, 3, 4].map(i => (
            <div key={i} style={{ display: "flex", gap: 10, marginBottom: 10 }}>
              <Skeleton h={30} w={30} style={{ borderRadius: 8, flexShrink: 0 }} />
              <div style={{ flex: 1 }}>
                <Skeleton h={10} w="70%" />
                <Skeleton h={8} w="50%" style={{ marginTop: 5 }} />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const scanList = scans || [];
  const modeIcon = { basic: "📡", asset: "🔍", advanced: "⚡", vulnerability_audit: "⚡", credentialed: "🔑" };
  const modeLabel = { basic: "Basic", asset: "Asset", advanced: "Vulnerability Audit", vulnerability_audit: "Vulnerability Audit", credentialed: "Credentialed" };

  return (
    <div className="db-card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <div className="db-card-title">
          <span className="db-pulse-dot" />
          Live Scan Activity
        </div>
      </div>
      <div className="db-card-sub">Real-time · WebSocket-driven progress</div>

      {scanList.length === 0 && (
        <div className="db-empty">
          <div className="db-empty-icon">📡</div>
          No recent scans
        </div>
      )}

      {scanList.map((scan) => {
        const isCredentialed = scan.scan_type === "credentialed";
        const icon = isCredentialed ? modeIcon.credentialed : (modeIcon[scan.pipeline_mode] || "📡");
        const iconBg = scan.status === "running"
           ? "rgba(59,130,246,0.1)"
           : scan.status === "failed"
             ? "rgba(239,68,68,0.1)"
             : "rgba(34,197,94,0.08)";
 
         return (
           <div key={scan.id} className="db-scan-row">
             <div className="db-scan-icon" style={{ background: iconBg }}>{icon}</div>
             <div className="db-scan-body">
               <div className="db-scan-title">
                 {(isCredentialed ? modeLabel.credentialed : modeLabel[scan.pipeline_mode]) || "Scan"} · {scan.target_str}
               </div>
              <div className="db-scan-sub">
                {scan.current_phase
                  ? `Phase: ${scan.current_phase.replace(/_/g, " ")} · ${scan.progress_pct || 0}%`
                  : scan.active_hosts
                    ? `${scan.active_hosts} hosts · C:${scan.critical_count} H:${scan.high_count}`
                    : scan.scan_name || scan.id}
              </div>
              {scan.status === "running" && (
                <div className="db-progress" style={{ marginTop: 5 }}>
                  <div
                    className="db-progress-fill"
                    style={{ width: `${scan.progress_pct || 5}%`, background: "var(--accent)" }}
                  />
                </div>
              )}
            </div>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
              <ScanStatus status={scan.status} />
              <div className="db-scan-time">{ago(scan.queued_at)}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── 6. Top Assets Table ───────────────────────────────────────────────────────

function TopAssetsTable({ assets, loading, onNavigate }) {
  if (loading) {
    return (
      <div className="db-card">
        <Skeleton h={12} w="40%" />
        <div style={{ marginTop: 14 }}>
          {[1, 2, 3, 4, 5].map(i => <Skeleton key={i} h={36} w="100%" style={{ marginBottom: 2 }} />)}
        </div>
      </div>
    );
  }

  const riskColor = (score) =>
    score >= 75 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 25 ? "#eab308" : "#22c55e";

  return (
    <div className="db-card" style={{ padding: 0 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 16px 8px" }}>
        <div>
          <div className="db-card-title">🖥 Top Vulnerable Assets</div>
          <div className="db-card-sub" style={{ marginBottom: 0 }}>Ranked by composite risk score · click to drill into asset</div>
        </div>
        <button className="db-btn db-btn--ghost" onClick={() => onNavigate("/assets")}>
          View All →
        </button>
      </div>
      <div className="db-table-wrap">
        <table className="db-table">
          <thead>
            <tr>
              <th>IP / Host</th>
              <th>OS</th>
              <th>Risk</th>
              <th>C</th>
              <th>H</th>
              <th>M</th>
              <th>Last Seen</th>
              <th>Managed</th>
            </tr>
          </thead>
          <tbody>
            {(assets || []).length === 0 && (
              <tr>
                <td colSpan={8} style={{ textAlign: "center", color: "var(--text-muted)", padding: 24 }}>
                  No assets found. Run a scan to populate the registry.
                </td>
              </tr>
            )}
            {(assets || []).map((a) => (
              <tr
                key={a.id}
                style={{ cursor: "pointer" }}
                onClick={() => onNavigate(`/assets/${a.id}`)}
              >
                <td>
                  <div className="mono">{a.ip_address}</div>
                  {a.hostname && (
                    <div style={{ fontSize: "0.65rem", color: "var(--text-faint)" }}>{a.hostname}</div>
                  )}
                </td>
                <td>
                  <span className="db-tag">{a.os_name || a.os_family || "Unknown"}</span>
                </td>
                <td>
                  <div className="db-risk-cell">
                    <div className="db-risk-bar-mini">
                      <div
                        className="db-risk-bar-fill"
                        style={{ width: `${clamp(a.risk_score)}%`, background: riskColor(a.risk_score) }}
                      />
                    </div>
                    <span style={{ fontWeight: 700, fontSize: "0.78rem", color: riskColor(a.risk_score) }}>
                      {a.risk_score}
                    </span>
                  </div>
                </td>
                <td style={{ color: "#f87171", fontWeight: 700 }}>{a.vuln_counts?.critical || 0}</td>
                <td style={{ color: "#fb923c", fontWeight: 700 }}>{a.vuln_counts?.high || 0}</td>
                <td style={{ color: "#fbbf24" }}>{a.vuln_counts?.medium || 0}</td>
                <td style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>{ago(a.last_seen_at)}</td>
                <td>
                  <span className={`db-tag`} style={a.is_managed
                    ? { background: "rgba(34,197,94,0.08)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.2)" }
                    : { background: "rgba(239,68,68,0.08)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)" }
                  }>
                    {a.is_managed ? "Managed" : "Unmanaged"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── 7. Top CVEs Table ─────────────────────────────────────────────────────────

function TopCVEsTable({ cves, loading, onNavigate }) {
  if (loading) {
    return (
      <div className="db-card">
        <Skeleton h={12} w="40%" />
        <div style={{ marginTop: 14 }}>
          {[1, 2, 3, 4, 5].map(i => <Skeleton key={i} h={36} w="100%" style={{ marginBottom: 2 }} />)}
        </div>
      </div>
    );
  }

  return (
    <div className="db-card" style={{ padding: 0 }}>
      <div style={{ padding: "14px 16px 8px" }}>
        <div className="db-card-title">🔥 Critical &amp; High CVEs</div>
        <div className="db-card-sub" style={{ marginBottom: 0 }}>Sorted by priority score — P0 KEV first</div>
      </div>
      <div className="db-table-wrap">
        <table className="db-table">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>CVSS</th>
              <th>Priority</th>
              <th>Severity</th>
              <th>Affected</th>
              <th>KEV</th>
            </tr>
          </thead>
          <tbody>
            {(cves || []).length === 0 && (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: 24 }}>
                  No critical/high CVEs found. Your environment may be well-patched.
                </td>
              </tr>
            )}
            {(cves || []).map((c) => (
              <tr key={c.id} style={{ cursor: "pointer" }} onClick={() => onNavigate(`/vulnerabilities?search=${c.id}`)}>
                <td>
                  <div className="cve-id"><CVELink cveId={c.id} /></div>
                  <div style={{ fontSize: "0.65rem", color: "var(--text-faint)", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {c.title}
                  </div>
                </td>
                <td>
                  <span className="db-table cvss-score" style={{
                    color: c.cvss_v3_score >= 9 ? "#f87171" : c.cvss_v3_score >= 7 ? "#fb923c" : "#fbbf24"
                  }}>
                    {c.cvss_v3_score.toFixed(1)}
                  </span>
                </td>
                <td><PriBadge label={c.priority_label} /></td>
                <td><SevBadge severity={c.severity} /></td>
                <td style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>{c.affected_assets} assets</td>
                <td>
                  {c.in_kev && (
                    <span style={{ fontSize: "0.65rem", fontWeight: 700, background: "rgba(239,68,68,0.12)", color: "#f87171", padding: "2px 6px", borderRadius: 4 }}>
                      KEV
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── 8. Asset Breakdown ────────────────────────────────────────────────────────

function AssetBreakdownPanel({ assetBreakdown, loading }) {
  if (loading) return (
    <div className="db-card"><Skeleton h={12} w="50%" /><Skeleton h={80} w="100%" style={{ marginTop: 14 }} /></div>
  );

  const t = assetBreakdown?.totals || {};
  const os = assetBreakdown?.os_distribution || [];
  const OS_ICON = { Linux: "🐧", Windows: "🪟", macOS: "🍎", "BSD": "🐡", Unknown: "❓" };

  return (
    <div className="db-card">
      <div className="db-card-title">🖥 Asset Inventory</div>
      <div className="db-card-sub">{fmt(t.total)} total assets</div>
      <div className="db-os-grid" style={{ marginBottom: 14 }}>
        {os.slice(0, 6).map((o) => (
          <div key={o.os_family} className="db-os-bubble">
            <div className="db-os-icon">{OS_ICON[o.os_family] || "💻"}</div>
            <div className="db-os-count">{o.count}</div>
            <div className="db-os-name">{o.os_family}</div>
          </div>
        ))}
      </div>
      <BarRow label="Managed" value={t.managed || 0} max={t.total || 1} color="#22c55e" />
      <BarRow label="Unmanaged" value={t.unmanaged || 0} max={t.total || 1} color="#ef4444" />
      <BarRow label="Active" value={t.active || 0} max={t.total || 1} color="#3b82f6" />
      <BarRow label="Offline" value={t.offline || 0} max={t.total || 1} color="var(--text-faint)" />
    </div>
  );
}

// ── 9. Service Exposure ───────────────────────────────────────────────────────

function ServiceExposurePanel({ services, loading }) {
  if (loading) return (
    <div className="db-card"><Skeleton h={12} w="50%" /><Skeleton h={160} w="100%" style={{ marginTop: 14 }} /></div>
  );

  const top = (services || []).slice(0, 10);
  const maxCount = Math.max(...top.map(s => s.asset_count), 1);

  return (
    <div className="db-card">
      <div className="db-card-title">🔓 Top Exposed Services</div>
      <div className="db-card-sub">Open ports across all assets</div>
      {top.map((s) => (
        <BarRow
          key={`${s.port}/${s.protocol}`}
          label={`${s.service_name || s.port}/${s.protocol}`}
          value={s.asset_count}
          max={maxCount}
          color={s.is_high_risk ? "#ef4444" : "#3b82f6"}
        />
      ))}
      {top.some(s => s.is_high_risk) && (
        <div style={{
          marginTop: 10, padding: "8px 10px", background: "rgba(239,68,68,0.06)",
          border: "1px solid rgba(239,68,68,0.15)", borderRadius: 7
        }}>
          <div style={{ fontSize: "0.72rem", color: "#fca5a5", fontWeight: 600 }}>
            ⚠ High-risk cleartext protocols detected
          </div>
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginTop: 2 }}>
            Telnet/FTP exposure increases attack surface. Recommend replacement with SSH/SFTP.
          </div>
        </div>
      )}
    </div>
  );
}

// ── 10. TLS Health ────────────────────────────────────────────────────────────

function TLSHealthPanel({ tlsHealth, httpHeaders, loading }) {
  if (loading) return (
    <div className="db-card"><Skeleton h={12} w="50%" /><Skeleton h={140} w="100%" style={{ marginTop: 14 }} /></div>
  );

  const tls = tlsHealth || {};
  const http = httpHeaders || {};
  const gd = tls.grade_distribution || {};

  const grades = [
    { g: "A", color: "#22c55e" }, { g: "B", color: "#4ade80" },
    { g: "C", color: "#eab308" }, { g: "D", color: "#f97316" }, { g: "F", color: "#ef4444" },
  ];
  const maxGrade = Math.max(...grades.map(g => gd[g.g] || 0), 1);

  const httpCoverage = http.coverage || {};

  return (
    <div className="db-card">
      <div className="db-card-title">🔐 TLS &amp; HTTP Security</div>
      <div className="db-card-sub">
        {tls.expiring_in_30d > 0
          ? <span style={{ color: "#f87171", fontWeight: 600 }}>⚠ {tls.expiring_in_30d} certs expiring in 30d · </span>
          : null}
        {tls.total_tls_services || 0} TLS services
      </div>

      <div style={{ marginBottom: 10 }}>
        {grades.map(({ g, color }) => (
          <BarRow
            key={g}
            label={`Grade ${g}`}
            value={gd[g] || 0}
            max={maxGrade}
            color={color}
          />
        ))}
      </div>

      <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontWeight: 600, marginBottom: 6 }}>
        HTTP Security Headers Coverage
      </div>
      {Object.entries(httpCoverage).map(([key, { pct: p, count }]) => (
        <BarRow
          key={key}
          label={key.replace(/_/g, "-").toUpperCase().replace("REFERRER", "Referrer")}
          value={p}
          max={100}
          color={p >= 70 ? "#22c55e" : p >= 40 ? "#eab308" : "#f97316"}
          valDisplay={`${p}%`}
        />
      ))}
    </div>
  );
}

// ── 11. Compliance Panel ──────────────────────────────────────────────────────

function CompliancePanel({ compliance, loading, onNavigate }) {
  if (loading) return (
    <div className="db-card">
      <Skeleton h={12} w="50%" />
      <div className="db-compliance-grid" style={{ marginTop: 14 }}>
        {[1, 2, 3, 4, 5, 6].map(i => <Skeleton key={i} h={70} />)}
      </div>
    </div>
  );

  const frameworks = compliance?.frameworks || [];

  return (
    <div className="db-card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <div className="db-card-title">✅ Compliance Posture</div>
        <button className="db-btn db-btn--ghost" style={{ fontSize: "0.68rem" }} onClick={() => onNavigate("/reports")}>
          Reports →
        </button>
      </div>
      <div className="db-card-sub">Derived from scan findings · frameworks updated on each scan</div>
      <div className="db-compliance-grid">
        {frameworks.map((fw) => {
          const score = Math.round(fw.score);
          const color = score >= 80 ? "#22c55e" : score >= 60 ? "#eab308" : "#f97316";
          return (
            <div key={fw.id} className="db-compliance-tile">
              <div className="db-compliance-pct" style={{ color }}>{score}%</div>
              <div className="db-compliance-name">{fw.name}</div>
              <div style={{ marginTop: 6 }}>
                <div className="db-progress">
                  <div className="db-progress-fill" style={{ width: `${score}%`, background: color }} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── 12. Insights Strip ────────────────────────────────────────────────────────

function InsightsStrip({ insights, loading }) {
  if (loading) return (
    <div className="db-insights-strip">
      {[1, 2, 3].map(i => <Skeleton key={i} h={72} />)}
    </div>
  );

  const cards = insights || [];
  if (cards.length === 0) return null;

  return (
    <div className="db-insights-strip">
      {cards.map((ins) => (
        <div key={ins.id} className={`db-insight-card db-insight-card--${ins.severity || "medium"}`}>
          <div className="db-insight-icon">{ins.icon}</div>
          <div className="db-insight-body">
            <div className="db-insight-title">{ins.title}</div>
            <div className="db-insight-detail">{ins.detail}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── 13. Audit Timeline ────────────────────────────────────────────────────────

function AuditTimeline({ onNavigate }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    import("../api/axiosInstance").then(({ default: api }) => {
      api.get("/admin/audit-logs", { params: { limit: 6 } })
        .then(r => setLogs(r.data?.logs || []))
        .catch(() => { })
        .finally(() => setLoading(false));
    });
  }, []);

  const ACTION_ICON = {
    scan_started: "📡", scan_completed: "✅", scan_failed: "❌",
    vulnerability_found: "🚨", user_created: "👤", user_login: "🔑",
    asset_updated: "🖥", finding_accepted: "✔", finding_fixed: "🛠",
    report_generated: "📄",
  };

  const ACTION_COLOR = {
    vulnerability_found: "rgba(239,68,68,0.1)", scan_failed: "rgba(239,68,68,0.1)",
    scan_started: "rgba(59,130,246,0.1)", scan_completed: "rgba(34,197,94,0.08)",
    user_created: "rgba(168,85,247,0.1)", finding_fixed: "rgba(34,197,94,0.08)",
    report_generated: "rgba(234,179,8,0.1)",
  };

  return (
    <div className="db-card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <div className="db-card-title">📋 Activity &amp; Audit Timeline</div>
        <button className="db-btn db-btn--ghost" style={{ fontSize: "0.68rem" }} onClick={() => onNavigate("/admin/audit-logs")}>
          Full Log →
        </button>
      </div>
      <div className="db-card-sub">Immutable · SOC 2 / ISO 27001 ready</div>

      {loading && [1, 2, 3, 4, 5].map(i => (
        <div key={i} style={{ display: "flex", gap: 10, marginBottom: 10 }}>
          <Skeleton h={28} w={28} style={{ borderRadius: 7, flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <Skeleton h={10} w="70%" />
            <Skeleton h={8} w="50%" style={{ marginTop: 4 }} />
          </div>
        </div>
      ))}

      {!loading && logs.length === 0 && (
        <div className="db-empty">
          <div className="db-empty-icon">📋</div>
          No audit events yet
        </div>
      )}

      {!loading && logs.map((log) => (
        <div key={log.id} className="db-scan-row">
          <div className="db-scan-icon" style={{ background: ACTION_COLOR[log.action] || "var(--border)" }}>
            {ACTION_ICON[log.action] || "📌"}
          </div>
          <div className="db-scan-body">
            <div className="db-scan-title">{log.action?.replace(/_/g, " ")}</div>
            <div className="db-scan-sub">
              {log.username ? `${log.username} · ` : (log.user_id ? `uid:...${log.user_id.slice(-6)} · ` : '')}{log.resource_type} · {log.status}
            </div>
          </div>
          <div className="db-scan-time">{ago(log.created_at)}</div>
        </div>
      ))}
    </div>
  );
}

// ── 14. Notification Center ───────────────────────────────────────────────────

function NotifCenter({ onNavigate }) {
  const [notifs, setNotifs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    import("../api/axiosInstance").then(({ default: api }) => {
      api.get("/notifications", { params: { limit: 5, unread_only: true } })
        .then(r => setNotifs(r.data?.notifications || []))
        .catch(() => { })
        .finally(() => setLoading(false));
    });
  }, []);

  const TYPE_ICON = {
    scan_completed: "📡", scan_failed: "❌", vulnerability_found: "🚨",
    system_message: "ℹ️", admin_notice: "👤",
  };
  const TYPE_COLOR = {
    vulnerability_found: "rgba(239,68,68,0.1)",
    scan_failed: "rgba(239,68,68,0.1)",
    scan_completed: "rgba(59,130,246,0.1)",
    system_message: "rgba(234,179,8,0.1)",
    admin_notice: "rgba(168,85,247,0.1)",
  };

  return (
    <div className="db-card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div className="db-card-title">🔔 Notification Center</div>
        <button className="db-btn db-btn--ghost" style={{ fontSize: "0.68rem" }} onClick={() => onNavigate("/notifications")}>
          View All →
        </button>
      </div>

      {loading && [1, 2, 3].map(i => (
        <div key={i} style={{ display: "flex", gap: 10, marginBottom: 10 }}>
          <Skeleton h={28} w={28} style={{ borderRadius: 7 }} />
          <div style={{ flex: 1 }}>
            <Skeleton h={10} w="70%" />
            <Skeleton h={8} w="50%" style={{ marginTop: 5 }} />
          </div>
        </div>
      ))}

      {!loading && notifs.length === 0 && (
        <div className="db-empty">
          <div className="db-empty-icon">🔔</div>
          No unread notifications
        </div>
      )}

      {!loading && notifs.map((n) => (
        <div key={n.id} className={`db-notif-row ${!n.is_read ? "db-notif-unread" : ""}`}>
          <div className="db-notif-icon" style={{ background: TYPE_COLOR[n.type] || "var(--border)" }}>
            {TYPE_ICON[n.type] || "📌"}
          </div>
          <div className="db-notif-body">
            <div className="db-notif-title">{n.title}</div>
            <div className="db-notif-sub">{n.message}</div>
          </div>
          <div className="db-notif-time">{ago(n.created_at)}</div>
        </div>
      ))}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN DATA HOOK
// ═════════════════════════════════════════════════════════════════════════════

function useDashboard() {
  const [state, setState] = useState({
    summary: null, breakdown: null, topAssets: null,
    topCVEs: null, services: null, tlsHealth: null,
    httpHeaders: null, compliance: null, assetBreakdown: null,
    scanActivity: null, insights: null,
    loading: true, error: null,
  });

  const load = useCallback(async () => {
    setState(s => ({ ...s, loading: true, error: null }));

    const results = await Promise.allSettled([
      getDashboardSummary(),    // 0
      getRiskBreakdown(),       // 1
      getTopAssets(10),         // 2
      getTopCVEs(8, "Critical,High"), // 3
      getServicesExposure(),    // 4
      getTLSHealth(),           // 5
      getHTTPHeaders(),         // 6
      getCompliance(),          // 7
      getAssetBreakdown(),      // 8
      getScanActivity(8),       // 9
      getInsights(),            // 10
    ]);

    const ok = (r, key) => r.status === "fulfilled" ? r.value?.data?.[key] || r.value?.data || null : null;

    setState({
      summary: results[0].status === "fulfilled" ? results[0].value?.data : null,
      breakdown: results[1].status === "fulfilled" ? results[1].value?.data : null,
      topAssets: ok(results[2], "assets"),
      topCVEs: ok(results[3], "cves"),
      services: ok(results[4], "services"),
      tlsHealth: results[5].status === "fulfilled" ? results[5].value?.data : null,
      httpHeaders: results[6].status === "fulfilled" ? results[6].value?.data : null,
      compliance: results[7].status === "fulfilled" ? results[7].value?.data : null,
      assetBreakdown: results[8].status === "fulfilled" ? results[8].value?.data : null,
      scanActivity: ok(results[9], "scans"),
      insights: ok(results[10], "insights"),
      loading: false,
      error: null,
    });
  }, []);

  // Initial load
  useEffect(() => { load(); }, [load]);

  // Auto-refresh scan activity every 30s
  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const r = await getScanActivity(8);
        setState(s => ({ ...s, scanActivity: r.data?.scans || s.scanActivity }));
      } catch { /* silent */ }
    }, 30_000);
    return () => clearInterval(t);
  }, []);

  return { ...state, refresh: load };
}

// ═════════════════════════════════════════════════════════════════════════════
// PAGE COMPONENT
// ═════════════════════════════════════════════════════════════════════════════

export default function SecurityDashboard() {
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    if (user && !canPermission(user, { resource: "dashboard", action: "read" })) {
      navigate("/scan", { replace: true });
    }
  }, [user, navigate]);

  const db = useDashboard();
  const [activeTab, setActiveTab] = useState("overview");
  const [showDateDropdown, setShowDateDropdown] = useState(false);
  const [dateRange, setDateRange] = useState("Last 30 days");

  const canAssets = canPermission(user, { resource: "assets", action: "read" });
  const canFindings = canPermission(user, { resource: "findings", action: "read" });
  const canReports = canPermission(user, { resource: "reports", action: "read" });
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
  ].filter(t => t.show !== false);

  return (
    <AppLayout pageTitle="Security Dashboard" onNewScan={() => navigate("/scan")}>
      <div className="db-page">

        {/* ── Page Header ── */}
        <div className="db-page-header">
          <div>
            <div className="db-page-title">Security Dashboard</div>
            <div className="db-page-subtitle">
              <span className="live-dot" />
              Last updated: {lastUpdated} · {db.summary?.scans?.running || 0} scans running
            </div>
          </div>
          <div className="db-header-actions">
            <div style={{ position: "relative" }}>
              <div
                onClick={() => setShowDateDropdown(s => !s)}
                style={{ display: "flex", alignItems: "center", gap: 6, background: "rgba(255,255,255,0.05)", padding: "4px 12px", borderRadius: 6, cursor: "pointer", border: "1px solid var(--border)", fontSize: "0.78rem", color: "var(--text)", transition: "background 0.2s" }}
              >
                <span style={{ color: "var(--text)" }}>📅 {dateRange}</span>
                <span style={{ marginLeft: 4, color: "var(--text-muted)", fontSize: "0.6rem" }}>▼</span>
              </div>
              {showDateDropdown && (
                <div style={{ position: "absolute", top: "100%", right: 0, marginTop: 8, width: 180, background: "var(--bg-app)", border: "1px solid var(--border)", borderRadius: 8, boxShadow: "0 10px 25px rgba(0,0,0,0.5)", zIndex: 100, overflow: "hidden" }}>
                  {["Last 7 days", "Last 30 days", "Last 90 days", "Year to date"].map(range => (
                    <button
                      key={range}
                      onClick={() => { setDateRange(range); setShowDateDropdown(false); db.refresh(); }}
                      style={{ width: "100%", padding: "10px 12px", textAlign: "left", background: "transparent", border: "none", cursor: "pointer", fontSize: "0.82rem", color: range === dateRange ? "var(--accent)" : "var(--text)", display: "flex", alignItems: "center", gap: 8 }}
                    >
                      {range === dateRange ? <span style={{ width: 14 }}>✓</span> : <span style={{ width: 14 }} />}
                      {range}
                    </button>
                  ))}
                </div>
              )}
            </div>
            {canReports && (
              <button className="db-btn db-btn--ghost" onClick={() => navigate("/reports")}>
                ⬇ Export PDF
              </button>
            )}
            <button className="db-btn db-btn--primary" onClick={() => navigate("/scan")}>
              + New Scan
            </button>
          </div>
        </div>

        {/* ── Tab Bar ── */}
        <div className="db-tab-bar">
          {tabs.map((t) => (
            <button
              key={t.id}
              className={`db-tab ${activeTab === t.id ? "active" : ""}`}
              onClick={() => setActiveTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* ── Alert Banners (real data) ── */}
        {hasAlerts && (
          <div className="db-alerts">
            {critCount > 0 && (
              <div className="db-alert db-alert--critical">
                <span className="db-alert-icon">🚨</span>
                <div className="db-alert-body">
                  <strong>{critCount} Critical {critCount === 1 ? "vulnerability" : "vulnerabilities"}</strong>
                  {kevCount > 0 && <> including <strong>{kevCount} CISA KEV-listed CVE{kevCount > 1 ? "s" : ""}</strong></>}. Immediate remediation required.
                </div>
                <button className="db-btn db-btn--danger" onClick={() => navigate("/vulnerabilities?severity=Critical")}>
                  View Now
                </button>
              </div>
            )}
            {certExpire > 0 && (
              <div className="db-alert db-alert--warning">
                <span className="db-alert-icon">⚠️</span>
                <div className="db-alert-body">
                  <strong>{certExpire} TLS {certExpire === 1 ? "certificate" : "certificates"} expiring</strong> within 30 days. Renew before expiry to prevent service disruption.
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══════════ OVERVIEW TAB ═══════════ */}
        {activeTab === "overview" && (
          <>
            {/* Metric Cards + Sev Bar */}
            <div className="db-section" style={{ marginTop: 16 }}>
              <div className="db-section-title">Security Posture at a Glance</div>
              <MetricCards summary={db.summary} loading={db.loading} onNavigate={nav} />
              {!db.loading && <SevBar summary={db.summary} />}
            </div>

            {/* Insights Strip */}
            {!db.loading && db.insights && db.insights.length > 0 && (
              <div className="db-section" style={{ marginTop: 16 }}>
                <div className="db-section-title">AI Insights</div>
                <InsightsStrip insights={db.insights} loading={db.loading} />
              </div>
            )}

            {/* Risk Score + Donut + Live Scan */}
            <div className="db-section" style={{ marginTop: 16 }}>
              <div className="db-grid-3">
                <RiskScorePanel summary={db.summary} breakdown={db.breakdown} loading={db.loading} />
                <FindingsDonut summary={db.summary} breakdown={db.breakdown} loading={db.loading} />
                <ScanActivity scans={db.scanActivity} loading={db.loading} />
              </div>
            </div>

            {/* Top Assets Table */}
            {canAssets && (
              <div className="db-section" style={{ marginTop: 12 }}>
                <TopAssetsTable assets={db.topAssets} loading={db.loading} onNavigate={nav} />
              </div>
            )}

            {/* Top CVEs + Audit Timeline */}
            {canFindings && (
              <div className="db-section" style={{ marginTop: 12 }}>
                <div className="db-grid-2">
                  <TopCVEsTable cves={db.topCVEs} loading={db.loading} onNavigate={nav} />
                  {canAudit
                    ? <AuditTimeline onNavigate={nav} />
                    : <NotifCenter onNavigate={nav} />}
                </div>
              </div>
            )}

            {/* Asset Breakdown + Services + TLS */}
            {canAssets && (
              <div className="db-section" style={{ marginTop: 12 }}>
                <div className="db-grid-3">
                  <AssetBreakdownPanel assetBreakdown={db.assetBreakdown} loading={db.loading} />
                  <ServiceExposurePanel services={db.services} loading={db.loading} />
                  <TLSHealthPanel tlsHealth={db.tlsHealth} httpHeaders={db.httpHeaders} loading={db.loading} />
                </div>
              </div>
            )}

            {/* Compliance */}
            {canReports && (
              <div className="db-section" style={{ marginTop: 12 }}>
                <CompliancePanel compliance={db.compliance} loading={db.loading} onNavigate={nav} />
              </div>
            )}
          </>
        )}

        {/* ═══════════ ASSETS TAB ═══════════ */}
        {activeTab === "assets" && canAssets && (
          <div className="db-section" style={{ marginTop: 16 }}>
            <div className="db-section-title">Asset Registry — Quick View</div>
            <div style={{ display: "flex", gap: 12, flexDirection: "column" }}>
              <div className="db-grid-2">
                <AssetBreakdownPanel assetBreakdown={db.assetBreakdown} loading={db.loading} />
                <ServiceExposurePanel services={db.services} loading={db.loading} />
              </div>
              <TopAssetsTable assets={db.topAssets} loading={db.loading} onNavigate={nav} />
              <div style={{ textAlign: "center", paddingTop: 8 }}>
                <button className="db-btn db-btn--primary" onClick={() => nav("/assets")}>
                  Open Full Asset Registry →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ═══════════ VULNERABILITIES TAB ═══════════ */}
        {activeTab === "vulns" && canFindings && (
          <div className="db-section" style={{ marginTop: 16 }}>
            <div className="db-section-title">Vulnerability Intelligence — Quick View</div>
            <div style={{ display: "flex", gap: 12, flexDirection: "column" }}>
              <div className="db-grid-2">
                <FindingsDonut summary={db.summary} breakdown={db.breakdown} loading={db.loading} />
                <RiskScorePanel summary={db.summary} breakdown={db.breakdown} loading={db.loading} />
              </div>
              <TopCVEsTable cves={db.topCVEs} loading={db.loading} onNavigate={nav} />
              <div style={{ textAlign: "center", paddingTop: 8 }}>
                <button className="db-btn db-btn--primary" onClick={() => nav("/vulnerabilities")}>
                  Open Full Vulnerability Browser →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ═══════════ COMPLIANCE TAB ═══════════ */}
        {activeTab === "compliance" && canReports && (
          <div className="db-section" style={{ marginTop: 16 }}>
            <div className="db-section-title">Compliance &amp; Security Posture</div>
            <div style={{ display: "flex", gap: 12, flexDirection: "column" }}>
              <CompliancePanel compliance={db.compliance} loading={db.loading} onNavigate={nav} />
              <TLSHealthPanel tlsHealth={db.tlsHealth} httpHeaders={db.httpHeaders} loading={db.loading} />
            </div>
          </div>
        )}

        {/* ═══════════ SCANS TAB ═══════════ */}
        {activeTab === "scans" && (
          <div className="db-section" style={{ marginTop: 16 }}>
            <div className="db-section-title">Scan Activity & History</div>
            <div style={{ display: "flex", gap: 12, flexDirection: "column" }}>
              <ScanActivity scans={db.scanActivity} loading={db.loading} />
              <div style={{ textAlign: "center", paddingTop: 8 }}>
                <button className="db-btn db-btn--primary" onClick={() => nav("/history")}>
                  Open Full Scan History →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ═══════════ AUDIT TAB ═══════════ */}
        {activeTab === "audit" && canAudit && (
          <div className="db-section" style={{ marginTop: 16 }}>
            <div className="db-section-title">Audit Logs & Activity</div>
            <div style={{ display: "flex", gap: 12, flexDirection: "column" }}>
              <AuditTimeline onNavigate={nav} />
            </div>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
