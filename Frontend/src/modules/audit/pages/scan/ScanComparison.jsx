/**
 * What changed between two scans.
 *
 * GAP-13 has produced this since before Phase 19 and nothing in the frontend
 * referenced it. The report embeds a copy at scan time; an operator who wanted
 * to ask the question afterwards could not.
 *
 * The three things this page exists to get right, all of which are ways of
 * reporting less than the data appears to offer:
 *
 * * **`not_assessed` is shown as loudly as `fixed`.** A finding absent from a
 *   scan that never looked for it is not fixed. On real data the two counts
 *   are 1,869 and 24 — a summary that omitted the first would be reporting
 *   progress nothing established. It is a summary card, not a footnote.
 *
 * * **Policy agreement is three states.** `policies_match` is a boolean over a
 *   three-valued question and the backend returns `false` for "unknown" as
 *   well as "different". Rendering the unrecorded case as a mismatch would
 *   assert what the backend refused to.
 *
 * * **Counts are authoritative; the table is a sample.** `limit` bounds rows
 *   and never counts, so the totals come from `counts` and the pagination runs
 *   over whatever rows arrived. Paging on the row count would show a wrong
 *   number the moment an estate exceeded the limit.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureInput,
  CcurePagination,
  CcureSelect,
  CcureTable,
  CcureToastProvider,
  CcureCheckbox,
  CcurePage,
  CcurePageHeader,
} from "../../../../design-system";
import usePagedRows from "@audit/hooks/usePagedRows";
import ReportExportPanel from "@audit/components/common/ReportExportPanel";
import { getScan } from "@audit/api/scans";
import {
  CLASSIFICATIONS,
  CLASSIFICATION_LABEL,
  SEVERITIES,
  assetOptions,
  getBaselineCandidates,
  getComparison,
  policyAgreement,
} from "@audit/api/comparison";
import "../../styles/scan-comparison.css";

const BADGE_VARIANT = {
  new: "danger",
  reappeared: "danger",
  still_open: "warning",
  fixed: "success",
  not_assessed: "neutral",
  ruled_out: "neutral",
};

function scanLabel(scan) {
  if (!scan) return "";
  const no = scan.scan_no ?? scan.display_id ?? scan.id;
  const target = scan.target || scan.targets?.[0] || "";
  const when = scan.completed_at || scan.started_at || scan.created_at || "";
  const date = when ? String(when).slice(0, 16).replace("T", " ") : "";
  return `#${no}${target ? ` · ${target}` : ""}${date ? ` · ${date}` : ""}`;
}

/** One class, its count, and the severities inside it. */
function CountCard({ spec, count, severities }) {
  const bands = Object.entries(severities || {}).filter(([, n]) => n > 0);
  return (
    <div className={`sc-count sc-count--${spec.tone}`}>
      <dt className="sc-count__label">{spec.label}</dt>
      <dd className="sc-count__value">{Number(count || 0).toLocaleString()}</dd>
      <p className="sc-count__hint">{spec.hint}</p>
      {bands.length > 0 && (
        <ul className="sc-bands" aria-label={`${spec.label} by severity`}>
          {bands.map(([sev, n]) => (
            <li key={sev} className="sc-band">
              <span className={`sc-dot sc-dot--${sev}`} aria-hidden="true" />
              {n} {sev}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** What each scan actually assessed — the denominator for every count above. */
function ScopePanel({ title, scope }) {
  const detail = scope?.detail || {};
  if (!scope?.recorded) {
    return (
      <div className="sc-scope">
        <h3 className="sc-scope__title">{title}</h3>
        <p className="sc-note">
          No assessment scope was recorded for this scan, so what it looked for
          cannot be established. Nothing can be reported as fixed from it.
        </p>
      </div>
    );
  }
  return (
    <div className="sc-scope">
      <h3 className="sc-scope__title">{title}</h3>
      <dl className="sc-scope__grid">
        <div>
          <dt>Families</dt>
          <dd>{(scope.families || []).join(", ") || "—"}</dd>
        </div>
        <div>
          <dt>Assets</dt>
          <dd>{(scope.assets || []).length}</dd>
        </div>
        {detail.checks_assessed !== undefined && (
          <div>
            <dt>Checks assessed</dt>
            <dd>{Number(detail.checks_assessed).toLocaleString()}</dd>
          </div>
        )}
        {detail.config_audit_assessed !== undefined && (
          <div>
            <dt>Configuration audit</dt>
            <dd>{detail.config_audit_assessed ? "ran" : "did not run"}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

/**
 * Where "Back to results" goes: the page that shows this scan.
 *
 * It always went to the credentialed results page, so comparing a
 * vulnerability audit sent the reader to a page built for another scan
 * kind — which, for a pipeline audit with credentials, read its absent
 * fields as "0 CVEs" (scan #17, 13 Oct 2026).
 */
const FINAL_PHASE = { basic: 1, asset: 2, vulnerability_audit: 3 };
export function resultsPathFor(scan, scanId) {
  if (scan?.scan_type === "credentialed") {
    return `/scan/credentialed/results?scan_id=${encodeURIComponent(scanId)}`;
  }
  const phase = FINAL_PHASE[scan?.pipeline_mode] ?? 1;
  return `/scan/${encodeURIComponent(scanId)}/phase${phase}`;
}

export default function ScanComparison() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();

  const scanId = searchParams.get("scan_id") || location.state?.scanId || "";
  const baselineParam = searchParams.get("baseline") || "";

  const [scan, setScan] = useState(null);
  const [candidates, setCandidates] = useState([]);
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [baseline, setBaseline] = useState(baselineParam);
  const [severity, setSeverity] = useState([]);
  const [assetId, setAssetId] = useState("");
  const [classFilter, setClassFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState(() => new Set());

  // ── Load the current scan, then the baselines it can be compared against ──
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    (async () => {
      try {
        const { data } = await getScan(scanId);
        if (cancelled) return;
        setScan(data);
        const { data: list } = await getBaselineCandidates(data?.pipeline_mode);
        if (cancelled) return;
        const rows = Array.isArray(list)
          ? list
          : list?.scans || list?.items || [];
        // The scan cannot be its own baseline.
        setCandidates(rows.filter((s) => s.id !== scanId));
      } catch {
        if (!cancelled) setCandidates([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const load = useCallback(async () => {
    if (!scanId) return;
    setLoading(true);
    setError("");
    try {
      const { data } = await getComparison(scanId, {
        baseline: baseline || undefined,
        severity,
        assetId: assetId ? [assetId] : undefined,
      });
      setComparison(data);
    } catch (err) {
      const status = err?.response?.status;
      const body = err?.response?.data;
      const fromServer = body?.message || body?.detail;
      if (status === 403) {
        setError(
          fromServer ||
            "You do not have permission to read these scans. Comparing needs scans:read.",
        );
      } else if (status === 404) {
        setError(fromServer || "That scan no longer exists.");
      } else if (status === 429) {
        const wait = body?.retry_after_seconds;
        setError(
          wait
            ? `Too many comparison requests. Try again in ${wait} seconds.`
            : "Too many comparison requests. Try again shortly.",
        );
      } else {
        setError(fromServer || "The comparison could not be built.");
      }
      setComparison(null);
    } finally {
      setLoading(false);
    }
  }, [scanId, baseline, severity, assetId]);

  useEffect(() => {
    load();
  }, [load]);

  const counts = comparison?.counts || {};
  const severityCounts = comparison?.severity_counts || {};
  const findings = useMemo(() => comparison?.findings || [], [comparison]);
  const needle = search.trim().toLowerCase();

  const paged = usePagedRows(findings, {
    filter: (row) => {
      if (classFilter !== "all" && row.classification !== classFilter)
        return false;
      if (!needle) return true;
      return (
        String(row.vuln_id || "")
          .toLowerCase()
          .includes(needle) ||
        String(row.title || "")
          .toLowerCase()
          .includes(needle) ||
        String(row.asset_id || "")
          .toLowerCase()
          .includes(needle)
      );
    },
    resetKey: `${classFilter}|${needle}|${comparison?.baseline_scan_id || ""}`,
  });

  const agreement = comparison ? policyAgreement(comparison) : null;
  const assets = assetOptions(comparison);

  const applyBaseline = (value) => {
    setBaseline(value);
    const next = new URLSearchParams(searchParams);
    if (value) next.set("baseline", value);
    else next.delete("baseline");
    setSearchParams(next, { replace: true });
  };

  const toggle = (id) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  if (!scanId) {
    return (
      <AppLayout>
        <CcurePage className="sc-page">
          <CcurePageHeader title="Scan Comparison" />
          <CcureAlert variant="info" title="No scan selected">
            Open a scan and choose <strong>Compare with a previous scan</strong>{" "}
            to see what changed.
          </CcureAlert>
          <CcureButton
            variant="secondary"
            onClick={() => navigate("/scan-history")}
          >
            Go to Scan History
          </CcureButton>
        </CcurePage>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <CcurePage className="sc-page">
        <CcurePageHeader
          title="Scan Comparison"
          subtitle={
            <>
              {scan ? scanLabel(scan) : scanId}
              {comparison?.baseline_scan_id ? (
                <>
                  {" "}
                  compared against{" "}
                  <code className="sc-code">{comparison.baseline_scan_id}</code>
                </>
              ) : null}
            </>
          }
          actions={
            <div className="sc-header__actions">
              <CcureButton
                variant="secondary"
                onClick={() => navigate(resultsPathFor(scan, scanId))}
              >
                Back to results
              </CcureButton>
            </div>
          }
        />

        {/* Baseline selection. Only completed scans of the same pipeline mode
            are offered — comparing a credentialed audit against a host
            discovery produces a delta made almost entirely of not_assessed. */}
        <section className="sc-controls">
          <CcureSelect
            label="Compare against"
            value={baseline}
            onChange={(e) => applyBaseline(e.target.value)}
            disabled={loading}
            fieldClassName="sc-field"
            hint="Defaults to the most recent completed scan of the same kind."
          >
            <option value="">Most recent comparable scan (default)</option>
            {candidates.map((c) => (
              <option key={c.id} value={c.id}>
                {scanLabel(c)}
              </option>
            ))}
          </CcureSelect>

          <CcureSelect
            label="Asset"
            value={assetId}
            onChange={(e) => setAssetId(e.target.value)}
            disabled={loading || assets.length === 0}
            fieldClassName="sc-field"
            hint={
              assets.length === 0
                ? "No shared assets reported."
                : "Only assets both scans covered."
            }
          >
            <option value="">All assets</option>
            {assets.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </CcureSelect>

          <fieldset className="sc-sevfilter" disabled={loading}>
            <legend className="sc-sevfilter__legend">Severity</legend>
            <div className="sc-sevfilter__options">
              {SEVERITIES.map((s) => (
                <CcureCheckbox
                  key={s}
                  className="sc-check"
                  checked={severity.includes(s)}
                  onChange={(e) =>
                    setSeverity(
                      e.target.checked
                        ? [...severity, s]
                        : severity.filter((v) => v !== s),
                    )
                  }
                >
                  {s}
                </CcureCheckbox>
              ))}
            </div>
          </fieldset>
        </section>

        {error ? (
          <CcureAlert variant="danger" title="Comparison failed">
            {error}
          </CcureAlert>
        ) : null}

        {loading ? (
          <p className="sc-note" role="status">
            Building the comparison…
          </p>
        ) : null}

        {!loading && comparison && !comparison.comparable ? (
          /* Not an error. A first scan has nothing to compare against, and the
             backend answers with the shape the caller expects and the reason
             filled in rather than failing. Rendering a table of zeroes here
             would read as "nothing changed". */
          <CcureAlert variant="info" title="Not comparable">
            {comparison.reason ||
              "These scans cannot be compared against each other."}
          </CcureAlert>
        ) : null}

        {!loading && comparison?.comparable ? (
          <>
            <p className="sc-summary">{comparison.summary}</p>

            {comparison.reason ? (
              /* A comparable comparison can still carry a caveat — most often
                 that the current scan recorded no scope, so nothing can be
                 called fixed. It is the reason the fixed count is what it is. */
              <CcureAlert
                variant="warning"
                live={false}
                title="Read this with the counts"
              >
                {comparison.reason}
              </CcureAlert>
            ) : null}

            {agreement ? (
              <CcureAlert
                variant={
                  agreement.state === "same"
                    ? "success"
                    : agreement.state === "different"
                      ? "warning"
                      : "info"
                }
                live={false}
                title={`Scan policy — ${agreement.label}`}
              >
                {agreement.detail}
              </CcureAlert>
            ) : null}

            <dl className="sc-counts">
              {CLASSIFICATIONS.map((spec) => (
                <CountCard
                  key={spec.value}
                  spec={spec}
                  count={counts[spec.value]}
                  severities={severityCounts[spec.value]}
                />
              ))}
            </dl>

            <section className="sc-scopes">
              <ScopePanel
                title="This scan assessed"
                scope={comparison.current_scope}
              />
              <ScopePanel
                title="The baseline assessed"
                scope={comparison.baseline_scope}
              />
            </section>

            <section className="sc-findings">
              <div className="sc-toolbar">
                <div
                  className="sc-chips"
                  role="group"
                  aria-label="Filter by change"
                >
                  <CcureButton
                    variant="ghost"
                    size="sm"
                    type="button"
                    className={`sc-chip ${classFilter === "all" ? "is-active" : ""}`}
                    aria-pressed={classFilter === "all"}
                    onClick={() => setClassFilter("all")}
                  >
                    All ({findings.length})
                  </CcureButton>
                  {CLASSIFICATIONS.map((spec) => (
                    <CcureButton
                      variant="ghost"
                      size="sm"
                      key={spec.value}
                      type="button"
                      className={`sc-chip sc-chip--${spec.tone} ${classFilter === spec.value ? "is-active" : ""}`}
                      aria-pressed={classFilter === spec.value}
                      onClick={() => setClassFilter(spec.value)}
                    >
                      {spec.label} ({counts[spec.value] ?? 0})
                    </CcureButton>
                  ))}
                </div>
                <CcureInput
                  type="search"
                  label="Search changes"
                  placeholder="Identifier, title or asset…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  fieldClassName="sc-search"
                />
              </div>

              {/* The counts above are the whole delta; these rows are the
                  sample the API returned under `limit`. Said out loud so the
                  two numbers disagreeing does not look like a bug. */}
              {findings.length > 0 &&
              findings.length <
                Object.values(counts).reduce((a, b) => a + (b || 0), 0) ? (
                <p className="sc-note">
                  Showing {findings.length.toLocaleString()} of{" "}
                  {Object.values(counts)
                    .reduce((a, b) => a + (b || 0), 0)
                    .toLocaleString()}{" "}
                  changes. The counts above are complete; this list is a sample
                  bounded by the API&apos;s row limit.
                </p>
              ) : null}

              {paged.total === 0 ? (
                <p className="sc-note">
                  {findings.length === 0
                    ? "No individual changes were returned for this comparison."
                    : "No changes match the current filter."}
                </p>
              ) : (
                <>
                  <CcureTable
                    caption="Findings that changed between the two scans"
                    density="compact"
                    rows={paged.rows}
                    rowKey={(row, i) => `${row.finding_id || "f"}-${i}`}
                    columns={[
                      {
                        key: "classification",
                        header: "Change",
                        cell: (row) => (
                          <CcureBadge
                            variant={
                              BADGE_VARIANT[row.classification] || "neutral"
                            }
                          >
                            {CLASSIFICATION_LABEL[row.classification] ||
                              row.classification}
                          </CcureBadge>
                        ),
                      },
                      {
                        key: "vuln_id",
                        header: "Identifier",
                        isRowHeader: true,
                        mono: true,
                      },
                      {
                        key: "severity",
                        header: "Severity",
                        cell: (row) => (
                          <span
                            className={`sc-sev sc-sev--${String(row.severity || "none").toLowerCase()}`}
                          >
                            {row.severity || "—"}
                          </span>
                        ),
                      },
                      {
                        key: "source_family",
                        header: "Source",
                        cell: (row) => (
                          <span className="sc-muted">
                            {row.source_family || "—"}
                          </span>
                        ),
                      },
                      {
                        key: "asset_id",
                        header: "Asset",
                        mono: true,
                        cell: (row) => (
                          <span className="sc-muted">
                            {row.asset_id || "—"}
                          </span>
                        ),
                      },
                      {
                        key: "details",
                        header: "Details",
                        cell: (row) => (
                          <CcureButton
                            variant="ghost"
                            size="sm"
                            type="button"
                            className="sc-expand"
                            aria-expanded={expanded.has(row.finding_id)}
                            onClick={() => toggle(row.finding_id)}
                          >
                            {expanded.has(row.finding_id) ? "Hide" : "Show"}
                          </CcureButton>
                        ),
                      },
                    ]}
                  />

                  {paged.rows
                    .filter((row) => expanded.has(row.finding_id))
                    .map((row) => (
                      <section key={row.finding_id} className="sc-detail">
                        <h3 className="sc-detail__title">
                          {row.vuln_id}
                          {row.title ? ` — ${row.title}` : ""}
                        </h3>
                        <dl className="sc-detail__grid">
                          <div>
                            <dt>First found</dt>
                            <dd>{row.first_found_at || "—"}</dd>
                          </div>
                          <div>
                            <dt>Last found</dt>
                            <dd>{row.last_found_at || "—"}</dd>
                          </div>
                          <div>
                            <dt>Fixed at</dt>
                            <dd>{row.fixed_at || "—"}</dd>
                          </div>
                          <div>
                            <dt>Finding id</dt>
                            <dd className="sc-mono">{row.finding_id}</dd>
                          </div>
                        </dl>
                        {row.evidence ? (
                          <>
                            <h4 className="sc-detail__sub">Evidence</h4>
                            <pre className="sc-evidence">{row.evidence}</pre>
                          </>
                        ) : null}
                      </section>
                    ))}

                  <CcurePagination
                    page={paged.page}
                    pageSize={paged.pageSize}
                    total={paged.total}
                    onPageChange={paged.setPage}
                    onPageSizeChange={paged.setPageSize}
                    itemNoun="changes"
                  />
                </>
              )}
            </section>

            {/* Exporting the comparison the operator is actually looking at.
                Phase 2 could not offer this: `baseline` needs a scan picker,
                and there was none until this page. Without it an exported
                comparison would silently use the backend's default baseline
                rather than the one on screen. */}
            <section className="sc-export">
              <h2 className="sc-export__title">Export this comparison</h2>
              <CcureToastProvider>
                <ReportExportPanel
                  scanId={scanId}
                  scanNo={scan?.scan_no}
                  baselineScanId={comparison.baseline_scan_id}
                />
              </CcureToastProvider>
            </section>
          </>
        ) : null}
      </CcurePage>
    </AppLayout>
  );
}
