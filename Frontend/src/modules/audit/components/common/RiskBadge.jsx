import { CcureSeverityBadge } from "../../../../design-system";

/**
 * src/modules/audit/components/common/RiskBadge.jsx
 *
 * **Deprecated adapter.** The canonical implementation is
 * `CcureSeverityBadge`; this file now only maps the old prop name and exists
 * so its two remaining consumers keep working unchanged.
 *
 *   src/pages/scan/CredentialedResults.jsx
 *   src/pages/ScanHistory.jsx
 *
 * Both are migrated in a later checkpoint, at which point this file is
 * deleted. Do not add features here and do not import it in new code.
 *
 * ── Why it was consolidated rather than left alone ──────────────────────────
 * It previously carried its own hardcoded palette, and every colour in it
 * failed WCAG AA against the surface it was drawn on:
 *
 *     Critical  #ff4d4d   3.27:1
 *     High      #f97316   2.80:1
 *     Medium    #f59e0b   2.15:1
 *     Low       #22c55e   2.28:1
 *     Info      #60a5fa   2.54:1
 *
 * The literals also ignored `data-theme`, so the badge rendered identically on
 * a dark background where it was least readable. Delegating replaces them with
 * the `--ccure-sev-*` tokens, which Phase 2 chose by measurement and which
 * invert with the theme.
 *
 * This is a deliberate visual change on those two pages — the colours are
 * darker in light mode — and it is the point: they are now legible.
 */
export default function RiskBadge({ level, score }) {
  // `level` is the old prop name; `severity` is the canonical one.
  // CcureSeverityBadge normalises case and maps anything unrecognised to
  // "unscored" rather than silently rendering it as Info, which is what the
  // old `MAP[level] || MAP.Info` fallback did.
  return <CcureSeverityBadge severity={level} score={score} />;
}
