import CcureBadge from "../components/CcureBadge";

/**
 * CcureSeverityBadge
 *
 * The canonical rendering of a vulnerability severity band.
 *
 * ── Why this exists ─────────────────────────────────────────────────────────
 * The survey for this checkpoint found severity painted eleven different ways,
 * and — worse — painted *differently for the same band*:
 *
 *   Critical   #ff4d4d  (Phase3Results, RiskBadge)
 *              #ef4444  (SecurityDashboard)
 *              #991b1b on #fee2e2  (ConfigurationChecks)
 *   Medium     #f59e0b  (Phase3Results)
 *              #eab308  (SecurityDashboard)
 *
 * Two operators comparing two screens were looking at different colours for
 * the same finding. Several of those literals also fail WCAG AA on white, and
 * none of them respond to the theme.
 *
 * ── The vocabulary is the application's, not an invention ───────────────────
 * `critical | high | medium | low | info | none | unscored`, measured from the
 * codebase. `none` and `unscored` are real states from the configuration-audit
 * path and are deliberately NOT folded into `info`: "no severity was assigned"
 * and "no rating has been published" are both weaker claims than
 * "informational", and on a compliance report the difference decides whether a
 * control counts.
 *
 * Case is normalised because the data carries both spellings — Phase3Results
 * ships a `getSevColor` helper that exists solely to try `Critical`, then
 * `critical`, then a fallback.
 *
 * ── What it does not do ─────────────────────────────────────────────────────
 * No calculation. It receives an already-decided band. Turning a CVSS number
 * into a band is business logic and stays in the application, where the
 * thresholds already differ per context (75/50/25 for asset risk, 9/7 for
 * CVSS).
 */

/** The application's severity vocabulary. Order is descending by seriousness,
 *  which is the order any list of these should be presented in. */
export const SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "none",
  "unscored",
];

const LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  none: "None",
  unscored: "Unscored",
};

/** Normalises the spellings the API actually returns. */
export function normalizeSeverity(value) {
  if (value == null) return "unscored";
  const key = String(value).trim().toLowerCase();
  if (key === "informational") return "info";
  return SEVERITIES.includes(key) ? key : "unscored";
}

export default function CcureSeverityBadge({
  severity,
  score,
  size = "sm",
  showLabel = true,
  className = "",
  ...rest
}) {
  const level = normalizeSeverity(severity);
  const label = LABELS[level];

  return (
    <CcureBadge
      size={size}
      mono
      // The colour comes from a `.cc-sev--*` class rather than a CcureBadge
      // variant: the badge has six variants and severity has seven states, so
      // Critical and High would collapse into "danger".
      className={`cc-sev cc-sev--${level} ${className}`.trim()}
      {...rest}
    >
      {score != null ? <span className="cc-sev__score">{score}</span> : null}
      {/* The label is always in the accessible name even when hidden
          visually. Colour alone must never carry the band — WCAG 1.4.1, and
          on a triage queue it is the difference between acting and not. */}
      <span className={showLabel ? undefined : "cc-sr-only"}>{label}</span>
    </CcureBadge>
  );
}
