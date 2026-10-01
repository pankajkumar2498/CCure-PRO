/**
 * modules/web-scanning/pages/AllFindings.jsx
 * Org-wide findings, filtered by whatever the dashboard number the user clicked
 * represents (severity / OWASP category / trend date). The filters come from the
 * URL query string, so a dashboard link like ?severity=critical&status=open
 * lands here showing exactly those records — the count on the card and the rows
 * shown are the same query.
 */
import { useState, useEffect } from "react";
import { useSearchParams, Link } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { webDashboardApi } from "../api/webScansApi";
import {
  CcureBadge,
  CcureCard,
  CcureEmptyState,
  CcureSeverityBadge,
  CcureSkeleton,
  CcureTable,
} from "../../../../design-system";
import "../styles/web-scanning-pages.css";

const FILTER_LABELS = {
  severity: "Severity",
  owasp: "OWASP",
  finding_type: "Type",
  detected_by: "Detected by",
  status: "Status",
  date: "Scan date",
  scan_id: "Scan",
};

export default function AllFindings() {
  const [searchParams] = useSearchParams();
  const [findings, setFindings] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // The active filters, straight from the URL — this is the click context.
  const activeFilters = {};
  for (const key of Object.keys(FILTER_LABELS)) {
    const v = searchParams.get(key);
    if (v) activeFilters[key] = v;
  }
  const filterKey = searchParams.toString();

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      try {
        const params = { per_page: 500, ...Object.fromEntries(searchParams) };
        const res = await webDashboardApi.getAllFindings(params);
        if (!active) return;
        setFindings(res.data?.data || []);
        setTotal(res.data?.pagination?.total ?? (res.data?.data || []).length);
      } catch (err) {
        console.error("Failed to load findings", err);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterKey]);

  const columns = [
    {
      key: "severity",
      header: "Severity",
      nowrap: true,
      cell: (f) => <CcureSeverityBadge severity={f.severity} />,
    },
    {
      key: "title",
      header: "Finding",
      isRowHeader: true,
      cell: (f) => (
        <Link
          to={`/web-scans/${f.scan_id}/findings`}
          className="wsp-finding-link"
        >
          {f.title}
        </Link>
      ),
    },
    {
      key: "finding_type",
      header: "Type",
      cell: (f) => <span className="wsp-muted">{f.finding_type}</span>,
    },
    {
      key: "owasp",
      header: "OWASP",
      cell: (f) => <span className="wsp-muted">{f.owasp_category || "-"}</span>,
    },
    {
      key: "scan",
      header: "Scan",
      cell: (f) => (
        <Link to={`/web-scans/${f.scan_id}`} className="wsp-muted">
          {f.scan_name || f.target_domain || f.scan_id}
        </Link>
      ),
    },
    {
      key: "status",
      header: "Status",
      nowrap: true,
      cell: (f) => <CcureBadge variant="neutral">{f.status}</CcureBadge>,
    },
  ];

  return (
    <AppLayout pageTitle="Findings">
      <div className="page-inner wsp-page wsp-page--wide">
        <div className="wsp-header">
          <div>
            <Link to="/web-scans/dashboard" className="wsp-back">
              ← Back to Dashboard
            </Link>
            <h1 className="page-title">Findings</h1>
            <p className="page-subtitle">
              {Object.keys(activeFilters).length
                ? "Filtered from the dashboard"
                : "All discovered vulnerabilities across scans"}
            </p>
          </div>
        </div>

        {Object.keys(activeFilters).length > 0 && (
          <div className="wsp-meta wsp-filter-bar">
            <span className="wsp-muted">Filtered by:</span>
            {Object.entries(activeFilters).map(([k, v]) => (
              <CcureBadge key={k} variant="info">
                {FILTER_LABELS[k]}: {v}
              </CcureBadge>
            ))}
          </div>
        )}

        <div className="wsp-panel">
          {loading ? (
            <div className="wsp-loading" role="status" aria-live="polite">
              <span className="cc-sr-only">Loading findings…</span>
              <CcureSkeleton height="44px" radius="8px" />
              <CcureSkeleton height="44px" radius="8px" />
              <CcureSkeleton height="44px" radius="8px" />
            </div>
          ) : findings.length === 0 ? (
            <CcureEmptyState
              title="No findings match"
              description="No findings match the current filters."
            />
          ) : (
            <CcureCard
              title={`Findings (${total})`}
              headingLevel={2}
              flush
              bodyFlush
            >
              <CcureTable
                caption={`Findings — ${total}`}
                columns={columns}
                rows={findings}
                rowKey={(f) => f.id}
                density="comfortable"
              />
            </CcureCard>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
