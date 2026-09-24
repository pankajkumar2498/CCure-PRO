/**
 * What changed between one scan and a baseline.
 *
 * `GET /scans/{id}/comparison` is the only endpoint in this feature, and it is
 * governed by `scans:read` — not the `reports:read` that Phase 2's export
 * paths need. Both scans go through the same visibility check every other scan
 * route uses, so a baseline in another tenant is unreachable by naming its id.
 *
 * Three properties of the contract that the UI has to respect rather than
 * paper over:
 *
 * * **`limit` bounds the rows, never the counts.** An estate with thousands of
 *   findings still gets accurate totals and a short list. A UI that paged on
 *   the row count would report a wrong number; the counts are authoritative
 *   and the table is a sample of them.
 *
 * * **The classification vocabulary is exactly five.** `new`, `still_open`,
 *   `fixed`, `reappeared`, `not_assessed`. There is no "changed" class and no
 *   separate "unchanged" — `still_open` *is* unchanged. `not_assessed` is the
 *   one this feature exists to keep visible: a finding absent from a scan that
 *   never looked for it is not fixed, and a summary that omits it reports
 *   progress nothing established.
 *
 * * **An asset filter that matches nothing becomes no filter.** The backend
 *   intersects the requested ids with the scans' shared assets and, when the
 *   intersection is empty, skips the asset predicate entirely — so a
 *   nonexistent id returns *more* rows, reclassified into `not_assessed`
 *   (measured: 1,869 → 2,878). `assetOptions` exists so the picker can only
 *   offer ids the response itself returned, which makes that unreachable from
 *   the UI. It is documented rather than worked around.
 */

import api from "./axiosInstance";

/** The backend's five classes, in the order an operator reads them. */
export const CLASSIFICATIONS = [
  {
    value: "new",
    label: "New",
    tone: "danger",
    hint: "Not present at the baseline.",
  },
  {
    value: "reappeared",
    label: "Reappeared",
    tone: "danger",
    hint: "Fixed before, present again.",
  },
  {
    value: "still_open",
    label: "Unchanged",
    tone: "warning",
    hint: "Open at the baseline and still open.",
  },
  {
    value: "fixed",
    label: "Fixed",
    tone: "success",
    hint: "Open at the baseline, and this scan established it is gone.",
  },
  {
    value: "not_assessed",
    label: "Not assessed",
    tone: "neutral",
    hint: "This scan did not look, so nothing can be said either way.",
  },
];

export const CLASSIFICATION_LABEL = Object.fromEntries(
  CLASSIFICATIONS.map((c) => [c.value, c.label]),
);

export const SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unscored",
];

/**
 * Whether the two scans were assessed the same way — as three states, not two.
 *
 * `policies_match` is a boolean over a three-valued question. The backend
 * returns `false` both when the fingerprints genuinely differ and when either
 * snapshot was never recorded, and its own docstring says the unrecorded case
 * is "reported as unknown rather than as equivalent". Rendering that as "the
 * policies differ" would assert something the backend deliberately refused to.
 *
 * Both scans predating GAP-12 is the common case, so this is not an edge.
 */
export function policyAgreement(comparison) {
  const current = comparison?.current_policy || {};
  const baseline = comparison?.baseline_policy || {};
  if (!current.recorded || !baseline.recorded) {
    return {
      state: "unknown",
      label: "Not recorded",
      detail:
        "At least one of these scans has no policy snapshot, so whether they " +
        "assessed the same things cannot be established. It is not a " +
        "statement that they differ.",
    };
  }
  if (comparison?.policies_match) {
    return {
      state: "same",
      label: "Same configuration",
      detail: "Both scans ran under the same scan policy.",
    };
  }
  return {
    state: "different",
    label: "Different configuration",
    detail:
      "These scans assessed different things, so part of this delta reflects " +
      "a change in scope rather than a change in the estate.",
  };
}

/** Asset ids the response itself returned — the only ones safe to offer. */
export function assetOptions(comparison) {
  return [...(comparison?.assets || [])];
}

export const getComparison = (scanId, options = {}) => {
  const {
    baseline,
    severity,
    assetId,
    limit = 500,
    includeFindings = true,
  } = options;

  const params = { limit };
  if (baseline) params.baseline = baseline;
  if (severity?.length) params.severity = severity;
  if (assetId?.length) params.asset_id = assetId;
  if (includeFindings === false) params.include_findings = false;

  return api.get(`/scans/${encodeURIComponent(scanId)}/comparison`, {
    params,
    // Repeated bare names, not `severity[]`. FastAPI binds a list[str] Query
    // from the former and silently ignores the latter — the same defect Phase 2
    // measured on the export route, where the bracketed form returned 1,862
    // rows instead of 154 and still looked like a successful filtered call.
    paramsSerializer: { indexes: null },
  });
};

/**
 * Scans that can serve as a baseline for this one.
 *
 * Constrained to the same `pipeline_mode`, because that is what the backend's
 * own default (`previous_scan_for`) uses: comparing a credentialed audit
 * against a host discovery would produce a delta made almost entirely of
 * `not_assessed`. Completed only, for the same reason a running scan has no
 * findings to compare.
 */
export const getBaselineCandidates = (pipelineMode, { limit = 50 } = {}) =>
  api.get("/scans", {
    params: {
      limit,
      scope: "active",
      status: "complete",
      ...(pipelineMode ? { pipeline_mode: pipelineMode } : {}),
      sort_by: "created_at",
      sort_dir: "desc",
    },
  });
