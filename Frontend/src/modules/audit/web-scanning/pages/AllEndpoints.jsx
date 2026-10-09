/**
 * modules/web-scanning/pages/AllEndpoints.jsx
 * Org-wide discovered endpoints — the destination for the dashboard's
 * "Total Endpoints Discovered" card. Scoped by URL filters (source / is_api /
 * scan_id) so the count clicked and the rows shown are the same query.
 */
import { useState, useEffect } from "react";
import { useSearchParams, Link } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { webDashboardApi } from "../api/webScansApi";
import {
  CcureBadge,
  CcureCard,
  CcureEmptyState,
  CcureInput,
  CcureSkeleton,
  CcureTable,
  CcurePage,
  CcurePageHeader,
} from "../../../../design-system";
import "../styles/web-scanning-pages.css";

const METHOD_VARIANT = {
  GET: "info",
  POST: "success",
  PUT: "warning",
  PATCH: "warning",
  DELETE: "danger",
};

export default function AllEndpoints() {
  const [searchParams] = useSearchParams();
  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [term, setTerm] = useState("");
  const filterKey = searchParams.toString();

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      try {
        const params = { per_page: 500, ...Object.fromEntries(searchParams) };
        const res = await webDashboardApi.getAllEndpoints(params);
        if (!active) return;
        setAssets(res.data?.data || []);
        setTotal(res.data?.pagination?.total ?? (res.data?.data || []).length);
      } catch (err) {
        console.error("Failed to load endpoints", err);
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

  const filtered = assets.filter((a) =>
    a.url?.toLowerCase().includes(term.toLowerCase()),
  );

  const columns = [
    {
      key: "method",
      header: "Method",
      nowrap: true,
      cell: (a) => (
        <CcureBadge
          variant={
            METHOD_VARIANT[(a.method || "GET").toUpperCase()] || "neutral"
          }
          mono
        >
          {(a.method || "GET").toUpperCase()}
        </CcureBadge>
      ),
    },
    {
      key: "url",
      header: "URL",
      isRowHeader: true,
      mono: true,
      cell: (a) => <span className="wsp-target">{a.url}</span>,
    },
    {
      key: "flags",
      header: "Flags",
      cell: (a) => {
        const flags = [];
        if (a.is_api)
          flags.push(
            <CcureBadge key="api" variant="info">
              API
            </CcureBadge>,
          );
        if (a.is_form)
          flags.push(
            <CcureBadge key="form" variant="neutral">
              Form
            </CcureBadge>,
          );
        if (a.has_file_upload)
          flags.push(
            <CcureBadge key="up" variant="danger">
              File upload
            </CcureBadge>,
          );
        return flags.length ? <div className="wsp-flags">{flags}</div> : null;
      },
    },
    {
      key: "scan",
      header: "Scan",
      cell: (a) => (
        <Link to={`/web-scans/${a.scan_id}`} className="wsp-muted">
          {a.scan_name || a.scan_id}
        </Link>
      ),
    },
  ];

  return (
    <AppLayout pageTitle="Discovered Endpoints">
      <CcurePage>
        <CcurePageHeader
          title="Discovered Endpoints"
          subtitle={<>Every endpoint discovered across scans</>}
          breadcrumb={
            <Link to="/web-scans/dashboard" className="wsp-back">
              ← Back to Dashboard
            </Link>
          }
          actions={
            <CcureInput
              type="search"
              label="Search endpoints"
              placeholder="Search URLs…"
              value={term}
              onChange={(e) => setTerm(e.target.value)}
              fieldClassName="wsp-search"
            />
          }
        />

        <div className="wsp-panel">
          {loading ? (
            <div className="wsp-loading" role="status" aria-live="polite">
              <span className="cc-sr-only">Loading endpoints…</span>
              <CcureSkeleton height="44px" radius="8px" />
              <CcureSkeleton height="44px" radius="8px" />
              <CcureSkeleton height="44px" radius="8px" />
            </div>
          ) : filtered.length === 0 ? (
            <CcureEmptyState
              title="No endpoints"
              description="No discovered endpoints match."
            />
          ) : (
            <CcureCard
              title={`Endpoints (${total})`}
              headingLevel={2}
              flush
              bodyFlush
            >
              <CcureTable
                caption={`Discovered endpoints — ${total}`}
                columns={columns}
                rows={filtered}
                rowKey={(a) => a.id}
                density="comfortable"
              />
            </CcureCard>
          )}
        </div>
      </CcurePage>
    </AppLayout>
  );
}
