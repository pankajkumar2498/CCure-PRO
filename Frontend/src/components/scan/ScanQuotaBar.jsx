/**
 * src/components/scan/ScanQuotaBar.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * The organisation's scan quota on the NewScan page: plan, scans used in the
 * last 24 hours, concurrent scans, and the per-scan IP ceiling.
 *
 * Fetches GET /scan/quota on mount and every 30 s. Hides itself if the call
 * fails: the widget is advisory, and the backend is what enforces the quota.
 *
 * ── Checkpoint 3C batch 15 ──────────────────────────────────────────────────
 * Usage is a `meter` — a measurement within a known range — not a
 * progressbar, which describes a task advancing towards completion. Each
 * meter is named, valued in scans rather than percent, and not drawn at all
 * when there is no limit to measure against. Near-limit and limit-reached are
 * said in words; before, the count's colour was the only signal. The poll is
 * unchanged and now has tests of its own.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { CcureAlert, CcureBadge } from "../../design-system";
import { getScanQuota } from "../../api/scans";
import "../../styles/scan-quota.css";

/* A plan tier is a label, not a status — no plan is a warning or a danger. The
   legacy violet and amber were hex literals that did not follow the theme. */
const PLAN_META = {
  community: { label: "Community", variant: "neutral" },
  pro: { label: "Pro", variant: "primary" },
  enterprise: { label: "Enterprise", variant: "info" },
  unknown: { label: "Free", variant: "neutral" },
};

/* ── Helpers ────────────────────────────────────────────────────────────── */
function pct(used, limit) {
  if (!limit) return 0;
  return Math.min(100, Math.round((used / limit) * 100));
}

/** The band a usage percentage falls in, as a tone and — where it matters —
 *  words. Thresholds unchanged from the legacy bar colours. */
function band(p) {
  if (p >= 100) return { tone: "danger", words: "Limit reached" };
  if (p >= 80) return { tone: "warning", words: "Near limit" };
  if (p >= 50) return { tone: "primary", words: null };
  return { tone: "success", words: null };
}

function UsageMeter({ label, count, used, limit, unit }) {
  const labelId = useId();
  const hasLimit = typeof limit === "number" && limit > 0;
  const measured = Math.max(Number(used) || 0, 0);
  const p = hasLimit ? pct(measured, limit) : 0;
  const { tone, words } = hasLimit ? band(p) : band(0);

  return (
    <div className={`sq__meter sq__meter--${tone}`}>
      <div className="sq__meter-labels">
        <span id={labelId}>{label}</span>
        <span className="sq__meter-count">
          {words && <CcureBadge variant={tone}>{words}</CcureBadge>}
          <span className="sq__meter-value">{count}</span>
        </span>
      </div>
      {hasLimit && (
        <div
          className="sq__track"
          role="meter"
          aria-labelledby={labelId}
          aria-valuemin={0}
          aria-valuemax={limit}
          // Held inside the range the role declares; the text keeps the real
          // figure when use has run past the limit.
          aria-valuenow={Math.min(measured, limit)}
          aria-valuetext={`${used} of ${limit} ${unit}`}
        >
          {/* Width is the one per-instance value; everything else is a class. */}
          <div className="sq__fill" style={{ width: `${p}%` }} />
        </div>
      )}
    </div>
  );
}

/* ── Component ──────────────────────────────────────────────────────────── */
export default function ScanQuotaBar({ className = "", onQuotaChange }) {
  const [quota, setQuota] = useState(null);
  const [visible, setVisible] = useState(false);
  const intervalRef = useRef(null);

  // `onQuotaChange` is passed as an inline arrow by every caller, so it is a
  // new function on each of the parent's renders. Depending on it directly
  // would rebuild `fetchQuota`, which would tear down and restart the 30s
  // interval on every parent render — turning a poll into a burst of requests.
  // Holding it in a ref keeps the poll on its own clock while still calling the
  // *current* callback rather than the one captured at mount.
  const onQuotaChangeRef = useRef(onQuotaChange);
  useEffect(() => {
    onQuotaChangeRef.current = onQuotaChange;
  }, [onQuotaChange]);

  const fetchQuota = useCallback(async () => {
    try {
      const { data } = await getScanQuota();
      setQuota(data);
      setVisible(true);
      onQuotaChangeRef.current?.({
        quota_exceeded: data.quota_exceeded,
        concurrent_exceeded: data.concurrent_exceeded,
      });
    } catch {
      /* Silently hide — quota widget is non-critical */
      setVisible(false);
    }
  }, []);

  useEffect(() => {
    fetchQuota();
    intervalRef.current = setInterval(fetchQuota, 30_000);
    return () => clearInterval(intervalRef.current);
  }, [fetchQuota]);

  if (!visible || !quota) return null;

  const plan = PLAN_META[quota.plan] || PLAN_META.unknown;
  const isUnlimited = quota.scans_limit_24h === null;
  const isBlocked = quota.quota_exceeded || quota.concurrent_exceeded;

  return (
    <section
      className={["sq", isBlocked ? "sq--blocked" : "", className]
        .filter(Boolean)
        .join(" ")}
      aria-label="Scan quota usage"
    >
      {/* ── Header row ──────────────────────────────────────────────────── */}
      <div className="sq__header">
        <div className="sq__heading">
          <CcureBadge variant={plan.variant}>{plan.label}</CcureBadge>
          <span className="sq__title">Scan Quota</span>
        </div>

        <div className="sq__limits">
          <CcureBadge variant="neutral" title="Maximum IPs per scan target">
            Max {quota.max_ips_per_scan?.toLocaleString()} IPs/scan
          </CcureBadge>
          <CcureBadge
            variant={quota.concurrent_exceeded ? "danger" : "success"}
            title="Active concurrent scans"
          >
            {quota.concurrent_running}/{quota.concurrent_limit} running
          </CcureBadge>
        </div>
      </div>

      <UsageMeter
        label="Scans today (24 h)"
        count={
          isUnlimited
            ? `${quota.scans_used_24h} (unlimited)`
            : `${quota.scans_used_24h} / ${quota.scans_limit_24h ?? ""} used`
        }
        used={quota.scans_used_24h}
        limit={isUnlimited ? null : quota.scans_limit_24h}
        unit="scans used"
      />

      <UsageMeter
        label="Concurrent scans"
        count={`${quota.concurrent_running} / ${quota.concurrent_limit ?? ""} active`}
        used={quota.concurrent_running}
        limit={quota.concurrent_limit}
        unit="concurrent scans running"
      />

      {/* ── Blocked warning ─────────────────────────────────────────────── */}
      {isBlocked && (
        <CcureAlert variant="danger">
          {quota.quota_exceeded
            ? `Daily scan limit reached (${quota.scans_used_24h}/${quota.scans_limit_24h}). Please wait or upgrade your plan.`
            : `Concurrent scan limit reached (${quota.concurrent_running}/${quota.concurrent_limit}). Wait for a running scan to finish.`}
        </CcureAlert>
      )}
    </section>
  );
}
