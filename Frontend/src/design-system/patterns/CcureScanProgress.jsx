import { CcureProgress } from "../components/CcureFeedback";

/**
 * CcureScanProgress
 *
 * A scan's completion, and the honest representation of not knowing it.
 *
 * ── Why this exists, and it is not "a progress bar" ─────────────────────────
 * The survey found progress rendered at five sites with **three different
 * meanings**, which is why this component is narrow: it represents *scan
 * completion only*. A severity-distribution bar is a chart, not progress, and
 * must not use this.
 *
 * ── The defect this fixes ───────────────────────────────────────────────────
 * Two sites fabricate a number when the real progress is unknown:
 *
 *     SecurityDashboard.jsx   width: `${scan.progress_pct || 5}%`
 *     Phase1Results.jsx       width: phase2Polling ? "65%" : "50%"
 *
 * `|| 5` turns a null into "5% complete", and a hardcoded 65% asserts a
 * measurement that was never taken. Both are the same error the Phase 3A
 * `CcureProgress` decision addressed from the other side: an unknown value
 * must be **indeterminate**, with `aria-valuenow` omitted rather than set to a
 * number. A scan whose progress cannot be determined must not report that it
 * has made some.
 *
 * Passing `value={null}` or `undefined` therefore yields an indeterminate bar,
 * never a small one. That is the whole point of the component.
 *
 * ── Terminal states ─────────────────────────────────────────────────────────
 * A completed scan is 100% whatever the last reported percentage was, and a
 * failed or cancelled one stops animating — an indeterminate bar sliding
 * forever under a scan that failed ten minutes ago is actively misleading.
 * The caller passes `status`; this component does not infer it.
 */

const TERMINAL_SUCCESS = new Set(["complete", "completed"]);
const TERMINAL_UNSUCCESSFUL = new Set([
  "failed",
  "cancelled",
  "canceled",
  "unreachable",
]);

export default function CcureScanProgress({
  value = null,
  status,
  phase,
  label = "Scan progress",
  showValue = true,
  className = "",
}) {
  const key = status == null ? "" : String(status).trim().toLowerCase();

  const isDone = TERMINAL_SUCCESS.has(key);
  const isStopped = TERMINAL_UNSUCCESSFUL.has(key);

  // A finished scan reads 100% even if the last poll landed at 97 — the work
  // is over, and leaving it short suggests something is still outstanding.
  // A stopped scan holds whatever it reached; if that is unknown it stays
  // unknown rather than being rendered as zero progress.
  let resolved;
  if (isDone) resolved = 100;
  else if (value == null) resolved = null;
  else resolved = Math.min(Math.max(Number(value), 0), 100);

  const variant = isDone ? "success" : isStopped ? "danger" : "primary";

  return (
    <div className={className}>
      <CcureProgress
        // `resolved` stays null when the percentage is genuinely unknown — it
        // is never coerced to 0. `animated={false}` is what distinguishes a
        // stopped scan of unknown extent from a live one.
        value={resolved}
        animated={!isStopped}
        label={label}
        showValue={showValue}
        variant={variant}
      />
      {/* The phase caption is the one thing this adds over CcureProgress:
          "Phase 2 — port scan" is what an operator actually reads to know
          where a scan has got to. */}
      {phase ? <div className="cc-scan-progress__phase">{phase}</div> : null}
    </div>
  );
}
