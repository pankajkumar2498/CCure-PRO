/**
 * src/components/scan/ScanQuotaBar.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Displays the organisation's real-time scan quota usage on the NewScan page.
 *
 * Shows:
 *   • Plan badge (community / pro / enterprise)
 *   • Scans used today  vs  daily limit  (animated progress bar)
 *   • Concurrent scans running
 *   • Max IPs per scan allowed by the plan
 *   • Warning / blocked states when limits are reached
 *
 * Fetches from GET /scan/quota on mount and refreshes every 30 s.
 * Gracefully hides itself if the API call fails (no layout shift).
 */

import { useEffect, useState, useRef } from "react";
import { getScanQuota } from "../../api/scans";

/* ── Plan colour palette ────────────────────────────────────────────────── */
const PLAN_META = {
  community:  { label: "Community",  color: "#64748b", glow: "rgba(100,116,139,0.25)" },
  pro:        { label: "Pro",         color: "#8b5cf6", glow: "rgba(139,92,246,0.25)"  },
  enterprise: { label: "Enterprise", color: "#f59e0b", glow: "rgba(245,158,11,0.25)"  },
  unknown:    { label: "Free",        color: "#64748b", glow: "rgba(100,116,139,0.25)" },
};

/* ── Helper ─────────────────────────────────────────────────────────────── */
function pct(used, limit) {
  if (!limit) return 0;
  return Math.min(100, Math.round((used / limit) * 100));
}

function barColor(p) {
  if (p >= 100) return "#ef4444";   // red   — limit hit
  if (p >= 80)  return "#f59e0b";   // amber — warning
  if (p >= 50)  return "#0ea5e9";   // blue  — normal
  return "#22c55e";                  // green — plenty of quota left
}

/* ── Component ──────────────────────────────────────────────────────────── */
export default function ScanQuotaBar({ className = "", onQuotaChange }) {
  const [quota, setQuota]       = useState(null);
  const [visible, setVisible]   = useState(false);
  const intervalRef             = useRef(null);

  const fetchQuota = async () => {
    try {
      const { data } = await getScanQuota();
      setQuota(data);
      setVisible(true);
      onQuotaChange?.({
        quota_exceeded:      data.quota_exceeded,
        concurrent_exceeded: data.concurrent_exceeded,
      });
    } catch {
      /* Silently hide — quota widget is non-critical */
      setVisible(false);
    }
  };

  useEffect(() => {
    fetchQuota();
    intervalRef.current = setInterval(fetchQuota, 30_000);
    return () => clearInterval(intervalRef.current);
  }, []);

  if (!visible || !quota) return null;

  const plan        = PLAN_META[quota.plan] || PLAN_META.unknown;
  const isUnlimited = quota.scans_limit_24h === null;
  const dailyPct    = isUnlimited ? 0 : pct(quota.scans_used_24h, quota.scans_limit_24h);
  const dailyColor  = isUnlimited ? "#22c55e" : barColor(dailyPct);
  const concPct     = pct(quota.concurrent_running, quota.concurrent_limit);
  const concColor   = barColor(concPct);
  const isBlocked   = quota.quota_exceeded || quota.concurrent_exceeded;

  return (
    <div
      className={`sqb-root ${isBlocked ? "sqb-root--blocked" : ""} ${className}`}
      role="region"
      aria-label="Scan quota usage"
    >
      {/* ── Header row ──────────────────────────────────────────────────── */}
      <div className="sqb-header">
        <div className="sqb-header-left">
          <span
            className="sqb-plan-badge"
            style={{ background: `${plan.color}18`, color: plan.color, borderColor: `${plan.color}40` }}
          >
            {plan.label}
          </span>
          <span className="sqb-title">Scan Quota</span>
        </div>

        <div className="sqb-limits-row">
          {/* Max IPs per scan */}
          <span className="sqb-pill sqb-pill--ip" title="Maximum IPs per scan target">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
              <circle cx="12" cy="12" r="10"/><path d="M12 8v4l2 2"/>
            </svg>
            Max {quota.max_ips_per_scan?.toLocaleString()} IPs/scan
          </span>

          {/* Concurrent running */}
          <span
            className={`sqb-pill ${quota.concurrent_exceeded ? "sqb-pill--warn" : "sqb-pill--ok"}`}
            title="Active concurrent scans"
          >
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
              <path d="M5 12h14M12 5l7 7-7 7"/>
            </svg>
            {quota.concurrent_running}/{quota.concurrent_limit} running
          </span>
        </div>
      </div>

      {/* ── Daily bar ───────────────────────────────────────────────────── */}
      <div className="sqb-track-wrap">
        <div className="sqb-track-label">
          <span>Scans today (24 h)</span>
          <span className="sqb-track-count" style={{ color: dailyColor }}>
            {quota.scans_used_24h}
            {!isUnlimited && (
              <> / {quota.scans_limit_24h} used</>
            )}
            {isUnlimited && " (unlimited)"}
          </span>
        </div>
        {!isUnlimited && (
          <div className="sqb-track">
            <div
              className="sqb-fill"
              style={{ width: `${dailyPct}%`, background: dailyColor, boxShadow: `0 0 6px ${dailyColor}60` }}
              role="progressbar"
              aria-valuenow={dailyPct}
              aria-valuemin={0}
              aria-valuemax={100}
            />
          </div>
        )}
      </div>

      {/* ── Concurrent bar ──────────────────────────────────────────────── */}
      <div className="sqb-track-wrap">
        <div className="sqb-track-label">
          <span>Concurrent scans</span>
          <span className="sqb-track-count" style={{ color: concColor }}>
            {quota.concurrent_running} / {quota.concurrent_limit} active
          </span>
        </div>
        <div className="sqb-track">
          <div
            className="sqb-fill"
            style={{ width: `${concPct}%`, background: concColor, boxShadow: `0 0 6px ${concColor}60` }}
            role="progressbar"
            aria-valuenow={concPct}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
      </div>

      {/* ── Blocked warning ─────────────────────────────────────────────── */}
      {isBlocked && (
        <div className="sqb-blocked-banner" role="alert">
          <span className="sqb-blocked-icon">⚠</span>
          <span>
            {quota.quota_exceeded
              ? `Daily scan limit reached (${quota.scans_used_24h}/${quota.scans_limit_24h}). Please wait or upgrade your plan.`
              : `Concurrent scan limit reached (${quota.concurrent_running}/${quota.concurrent_limit}). Wait for a running scan to finish.`}
          </span>
        </div>
      )}
    </div>
  );
}
