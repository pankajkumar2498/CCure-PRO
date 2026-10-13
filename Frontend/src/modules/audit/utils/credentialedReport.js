/**
 * Where a credentialed report lives inside a stored scan.
 *
 * The same record reaches three shapes, and reading one of them is how the
 * results page came to spin for ever on a scan that had worked:
 *
 *   1. `results.credentialed.report` (+ `results.credentialed.reports[]`)
 *        — the standalone credentialed scan.
 *   2. `results.phase3.data[].credentialed_report`
 *        — the vulnerability-audit pipeline, one report per host.
 *   3. `options.credentialed_report`
 *        — the standalone scan's own copy on the scan record.
 *
 * `reporting/exports.py::_collect_host_audits` already walks for exactly this
 * reason, and its docstring names the same three shapes. This is the frontend
 * half of that decision; it is deliberately a *walk* rather than three reads,
 * so a fourth shape does not silently return nothing.
 *
 * Two properties the page depends on:
 *
 * * **A report is only a report when it carries evidence.** A truthy object is
 *   not enough — the vulnerability-audit pipeline writes a `credentialed_report`
 *   key on every host it attempted, including ones where nothing was collected.
 *   `hasReportContent` decides, and it is the same question the caller's
 *   `hasReport` guard asks of navigation state.
 *
 * * **"No report anywhere" is an answer, not a reason to keep waiting.** The
 *   resolver returns an empty list and the caller renders a terminal state.
 *   Returning null and letting the poll continue is what produced an
 *   indefinite spinner.
 */

/** The keys that mean a report actually carries something to show. */
const CONTENT_KEYS = [
  "system_info",
  "cves",
  "packages",
  "config_audit",
  "coverage",
  "hardening_audits",
  "running_services",
  "collection_errors",
  "access",
];

/**
 * True when this object looks like a credentialed report with content.
 *
 * Deliberately not `Boolean(report)`: an empty object and a report are
 * different answers, and treating the first as the second puts an empty page
 * in front of an operator who would otherwise be told nothing was collected.
 */
export function hasReportContent(report) {
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    return false;
  }
  return CONTENT_KEYS.some((key) => {
    const value = report[key];
    if (value == null) return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === "object") return Object.keys(value).length > 0;
    return true;
  });
}

/** A host label for a report, taken from the record's own container. */
const hostOf = (container, report) =>
  report?.target ||
  report?.ip_address ||
  container?.ip_address ||
  container?.target ||
  "";

/**
 * A pipeline host's report, with the host's own findings where it has none.
 *
 * The vulnerability-audit pipeline stores posture in `credentialed_report`
 * and the findings beside it on the host record — `cves`, `suppressed_cves`,
 * `vulnerability_counts` — which is what the database, the findings API and
 * the exports all report. Read from the report alone, absent became empty:
 * scan #17 (13 Oct 2026) showed "0 CVEs" and "Suppressed Findings (0)" for a
 * host with 2,287 findings and 3,677 suppressed candidates. A key the report
 * already carries is never replaced.
 */
export function withHostFindings(report, host) {
  if (!hasReportContent(report) || !host || typeof host !== "object") {
    return report;
  }
  const merged = { ...report };
  if (merged.cves === undefined && Array.isArray(host.cves)) {
    merged.cves = host.cves;
    if (merged.cve_count === undefined) merged.cve_count = host.cves.length;
    if (
      merged.severity_summary === undefined &&
      host.vulnerability_counts &&
      typeof host.vulnerability_counts === "object"
    ) {
      merged.severity_summary = host.vulnerability_counts;
    }
  }
  if (
    merged.suppressed_cves === undefined &&
    Array.isArray(host.suppressed_cves)
  ) {
    merged.suppressed_cves = host.suppressed_cves;
  }
  if (
    merged.candidates_evaluated === undefined &&
    host.candidates_evaluated != null
  ) {
    merged.candidates_evaluated = host.candidates_evaluated;
  }
  return merged;
}

/**
 * Every credentialed report in a scan detail, in the order an operator should
 * see them: the standalone shape first, then the per-host nested ones.
 *
 * Returns `[]` when a scan carries none — which for a completed scan is a
 * terminal answer.
 */
export function collectCredentialedReports(detail) {
  const out = [];
  const seen = new Set();

  const push = (report, container) => {
    if (!hasReportContent(report)) return;
    // One entry per host. A multi-host credentialed scan stores the first
    // host's report twice — once as `report` for consumers written before
    // multi-host support and once inside `reports` — and showing it twice
    // would make the host selector disagree with the scan.
    const host = hostOf(container, report);
    const key = `${host}::${report.scan_id || ""}::${
      (report.cves || []).length
    }::${Object.keys(report).length}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ ...report, _host: host });
  };

  const results = detail?.results;

  // 1. The standalone credentialed scan.
  const credentialed = results?.credentialed;
  if (credentialed) {
    const list = Array.isArray(credentialed.reports)
      ? credentialed.reports
      : [];
    if (list.length) {
      list.forEach((r) => push(r, credentialed));
    }
    push(credentialed.report, credentialed);
  }

  // 2. The vulnerability-audit pipeline, one report per host. `phase3` is the
  //    shape this deployment stores; `_phase_data` is the name the export
  //    layer's docstring uses for the same thing on other pipelines.
  for (const phase of [results?.phase3, results?._phase_data]) {
    const rows = Array.isArray(phase) ? phase : phase?.data;
    if (!Array.isArray(rows)) continue;
    rows.forEach((host) =>
      push(withHostFindings(host?.credentialed_report, host), host),
    );
  }

  // 3. The scan record's own copy.
  push(detail?.options?.credentialed_report, detail?.options);

  return out;
}

/**
 * The failed hosts a credentialed scan recorded, wherever it recorded them.
 * A host that could not be authenticated to is not a host with no findings.
 */
export function collectFailedHosts(detail) {
  const failed = detail?.results?.credentialed?.hosts_failed;
  return Array.isArray(failed) ? failed : [];
}
