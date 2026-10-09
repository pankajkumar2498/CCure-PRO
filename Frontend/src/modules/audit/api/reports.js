/**
 * The reports and export API surface.
 *
 * Three endpoints, and the distinction between the first two is the one a
 * caller keeps getting wrong:
 *
 * * `/reports/download/{id}` serves the **whole-scan deliverables** — the two
 *   PDFs a person reads, the host-inventory CSV, and the unfiltered workbook.
 *   It takes no filters; its counts are the scan's own.
 *
 * * `/reports/export/{id}` assembles a **dataset** and can narrow it. Filters
 *   only ever narrow: a framework the scan's policy excluded cannot be named
 *   back in, because the rest of it was never assessed.
 *
 * * `DELETE /reports/{id}` removes the stored artefacts and needs a different
 *   permission from reading them.
 *
 * The vocabularies below are copied from the backend rather than invented, and
 * the invalid combination is declared rather than discovered at runtime: the
 * API refuses `csv` + `all` with "A CSV holds one table", so the UI disables
 * it instead of letting the operator earn a 400.
 */

import api from "@shell/api/axiosInstance";

/** What `/reports/download` serves. Left of the arrow is what the API calls it. */
export const DOWNLOAD_FORMATS = [
  {
    value: "JSON",
    label: "Executive report",
    ext: "pdf",
    hint: "PDF for a reader who wants the conclusion.",
  },
  {
    value: "XML",
    label: "Technical report",
    ext: "pdf",
    hint: "PDF with the full finding detail.",
  },
  {
    value: "CSV",
    label: "Host inventory",
    ext: "csv",
    hint: "One row per host, as the scan recorded it.",
  },
  {
    value: "XLSX",
    label: "Full workbook",
    ext: "xlsx",
    hint: "Verdicts, findings and the comparison as separate sheets.",
  },
];

/**
 * `fmt=JSON` is the *executive PDF* and `fmt=XML` is the *technical PDF* —
 * historical names the API still speaks. Kept here so no caller has to know
 * that, and so nobody "fixes" the label into something the backend rejects.
 */
export const EXPORT_FORMATS = [
  { value: "xlsx", label: "Excel workbook (.xlsx)" },
  { value: "csv", label: "CSV (.csv)" },
  { value: "json", label: "JSON (.json)" },
];

export const EXPORT_DATASETS = [
  {
    value: "all",
    label: "Everything",
    hint: "Compliance verdicts, findings and the comparison.",
  },
  {
    value: "compliance",
    label: "Compliance verdicts",
    hint: "One row per configuration check, with its verdict and evidence.",
  },
  {
    value: "findings",
    label: "Findings",
    hint: "Vulnerability and configuration findings with their remediation record.",
  },
  {
    value: "comparison",
    label: "Change since the previous scan",
    hint: "New, resolved, unchanged and reappeared findings.",
  },
];

/** Findings are held against the scan, or against the assets it touched. */
export const EXPORT_SCOPES = [
  {
    value: "scan",
    label: "This scan",
    hint: "The findings this scan reported.",
  },
  {
    value: "asset",
    label: "These assets",
    hint: "Every finding currently held against the assets this scan touched.",
  },
];

/**
 * Combinations the backend refuses, so the UI can disable rather than fail.
 * Measured against the live API, not inferred from the route signature.
 */
export function isUnsupportedCombination(fmt, dataset) {
  return fmt === "csv" && dataset === "all";
}

export const UNSUPPORTED_REASON =
  "A CSV holds one table. Choose a single dataset, or export as XLSX, which carries all three as separate worksheets.";

/** A whole-scan deliverable. `fmt` is a value from DOWNLOAD_FORMATS. */
export const downloadReport = (scanId, fmt) =>
  api.get(`/reports/download/${encodeURIComponent(scanId)}`, {
    params: { fmt },
    responseType: "blob",
  });

/**
 * A filterable dataset.
 *
 * Empty filters are dropped rather than sent as empty strings: the backend
 * reads `severity=` as a severity literally named "", which matches nothing
 * and would silently return an empty export.
 */
export const exportScanDataset = (scanId, options = {}) => {
  const {
    fmt = "xlsx",
    dataset = "all",
    severity,
    verdict,
    status,
    remediationState,
    overdueOnly,
    scope,
    includeComparison,
    host,
    assetId,
    frameworkId,
    baseline,
  } = options;

  const params = { fmt, dataset };
  if (severity?.length) params.severity = severity;
  if (verdict?.length) params.verdict = verdict;
  if (status?.length) params.status = status;
  if (remediationState?.length) params.remediation_state = remediationState;
  if (overdueOnly) params.overdue_only = true;
  if (scope && scope !== "scan") params.scope = scope;
  if (includeComparison === false) params.include_comparison = false;
  if (host) params.host = host;
  if (assetId) params.asset_id = assetId;
  if (frameworkId) params.framework_id = frameworkId;
  if (baseline) params.baseline = baseline;

  return api.get(`/reports/export/${encodeURIComponent(scanId)}`, {
    params,
    // Even `fmt=json` is fetched as a Blob: the operator asked for a file, and
    // reading it as a parsed object would mean re-serialising it to save it.
    responseType: "blob",
    // Repeated keys, not `severity[]=a&severity[]=b` — FastAPI binds a
    // `list[str]` Query from repeated bare names, and the bracketed form
    // arrives as one parameter literally named "severity[]".
    paramsSerializer: { indexes: null },
  });
};

/** Removes the stored report artefacts. Needs `reports:delete`, not `read`. */
export const deleteStoredReport = (scanId) =>
  api.delete(`/reports/${encodeURIComponent(scanId)}`);
