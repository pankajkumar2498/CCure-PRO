/**
 * The two badges the remediation surface is read through.
 *
 * They are separate on purpose, because the two columns behind them answer
 * different questions and the backend keeps them apart for the same reason:
 * `status` is *detection* — is this finding present on the host —
 * and `remediation_state` is *workflow* — what are we doing about it. A
 * single badge folding them would have to pick one, and either choice loses
 * the fact a triager needs.
 */

import { CcureBadge } from "../../../../design-system";
import {
  SLA_LABELS,
  SLA_TONE,
  STATE_LABELS,
  STATE_TONE,
} from "@audit/api/remediation";

/** Workflow position. An unknown value is shown, never swallowed. */
export function RemediationStateBadge({ state }) {
  const key = String(state || "open");
  return (
    <CcureBadge variant={STATE_TONE[key] || "neutral"}>
      {STATE_LABELS[key] || key}
    </CcureBadge>
  );
}

/**
 * SLA position. `not_applicable` renders as "No deadline" rather than as a
 * blank or as a pass: a finding with no published rating carries no
 * obligation, which is a different fact from one comfortably inside its
 * deadline.
 */
export function SlaStateBadge({ state }) {
  if (!state) return <span className="rm-muted">—</span>;
  const key = String(state);
  return (
    <CcureBadge variant={SLA_TONE[key] || "neutral"}>
      {SLA_LABELS[key] || key}
    </CcureBadge>
  );
}

const SEVERITY_TONE = {
  critical: "danger",
  high: "danger",
  medium: "warning",
  low: "info",
  none: "neutral",
  unscored: "neutral",
};

/** Severity, which is also the SLA basis, so the two must read the same. */
export function SeverityBadge({ severity }) {
  if (!severity) return <span className="rm-muted">Unscored</span>;
  const key = String(severity).toLowerCase();
  return (
    <CcureBadge variant={SEVERITY_TONE[key] || "neutral"}>
      {key.charAt(0).toUpperCase() + key.slice(1)}
    </CcureBadge>
  );
}
