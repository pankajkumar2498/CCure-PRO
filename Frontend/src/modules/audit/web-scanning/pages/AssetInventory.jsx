/**
 * modules/web-scanning/pages/AssetInventory.jsx
 * The endpoints a DAST scan discovered on its target.
 *
 * ── Contract, unchanged by the Checkpoint 3C batch-6 migration ──────────────
 * Every request, filter rule and state transition below is what it was before.
 * The migration changed presentation only. Specifically preserved:
 *
 *   * `getAssets(id, { per_page: 200 })`, where `id` is the route parameter.
 *     That id is the whole scoping: an inventory rendered against a different
 *     scan's id would show one customer's discovered endpoints under another's
 *     scan;
 *   * the client-side filter still matches on `url` and `content_type` only,
 *     case-insensitively;
 *   * both response shapes are still accepted; a failed load still leaves the
 *     list empty rather than throwing;
 *   * the page does not poll.
 *
 * ── What the migration changed ──────────────────────────────────────────────
 * The flag column. `auth_required`, `is_api`, `is_form` and `has_file_upload`
 * are the security facts on this page — a discovered file-upload endpoint is
 * the most useful row here — and each was an emoji in a bare `<span>` with a
 * `title` attribute. `title` is not an accessible name on a span: most screen
 * readers ignore it there, and it is unreachable by keyboard and by touch. They
 * are labelled badges now.
 */
import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";
import {
  CcureBadge,
  CcureEmptyState,
  CcureInput,
  CcureSkeleton,
  CcureTable,
  CcurePage,
  CcurePageHeader,
} from "../../../../design-system";
import "../styles/web-scanning-pages.css";

/* An HTTP method is a small closed vocabulary and maps one-to-one onto the
   badge variants, so it needs no pattern of its own — the Batch 5 rule that a
   new design-system pattern must be earned by reuse, not by a single page. */
const METHOD_VARIANT = {
  GET: "info",
  POST: "success",
  PUT: "warning",
  PATCH: "warning",
  DELETE: "danger",
};

/* A response code band. 2xx is not "good news" on this page — it means the
   endpoint answered — so the vocabulary is deliberately neutral except where
   the server actually reported a problem. */
const codeVariant = (code) => {
  const n = Number(code);
  if (n >= 500) return "danger";
  if (n === 401 || n === 403) return "warning";
  if (n >= 400) return "neutral";
  return "success";
};

export default function AssetInventory() {
  const { id } = useParams();
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    async function fetchAssets() {
      try {
        setLoading(true);
        const res = await webScansApi.getAssets(id, { per_page: 200 });
        setAssets(res.data?.data || res.data?.items || []);
      } catch (err) {
        console.error("Failed to load assets", err);
      } finally {
        setLoading(false);
      }
    }
    fetchAssets();
  }, [id]);

  const filteredAssets = assets.filter(
    (a) =>
      a.url?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.content_type?.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  const columns = [
    {
      key: "method",
      header: "Method",
      nowrap: true,
      cell: (asset) => {
        const method = (asset.method || "GET").toUpperCase();
        return (
          <CcureBadge variant={METHOD_VARIANT[method] || "neutral"} mono>
            {method}
          </CcureBadge>
        );
      },
    },
    {
      key: "url",
      header: "URL",
      isRowHeader: true,
      mono: true,
      /* Deliberately not an anchor: this is a URL discovered on a target
         somebody named, and making it followable invites a click straight at
         it from inside the console. */
      cell: (asset) => <span className="wsp-target">{asset.url}</span>,
    },
    {
      key: "response_code",
      header: "Status",
      nowrap: true,
      cell: (asset) => {
        const code = asset.response_code || 200;
        return (
          <CcureBadge variant={codeVariant(code)} mono>
            {code}
          </CcureBadge>
        );
      },
    },
    {
      key: "content_type",
      header: "Content type",
      cell: (asset) => (
        <span className="wsp-muted">{asset.content_type || "text/html"}</span>
      ),
    },
    {
      key: "flags",
      header: "Flags",
      cell: (asset) => {
        const flags = [];
        if (asset.auth_required) {
          flags.push(
            <CcureBadge key="auth" variant="warning">
              Auth required
            </CcureBadge>,
          );
        }
        if (asset.is_api) {
          flags.push(
            <CcureBadge key="api" variant="info">
              API
            </CcureBadge>,
          );
        }
        if (asset.is_form) {
          flags.push(
            <CcureBadge key="form" variant="neutral">
              Form
            </CcureBadge>,
          );
        }
        if (asset.has_file_upload) {
          flags.push(
            <CcureBadge key="upload" variant="danger">
              File upload
            </CcureBadge>,
          );
        }
        // No flags means no flags. An empty cell says that; a dash would read
        // as "not assessed".
        return flags.length ? <div className="wsp-flags">{flags}</div> : null;
      },
    },
    {
      key: "size_time",
      header: "Size / time",
      align: "end",
      nowrap: true,
      mono: true,
      cell: (asset) => (
        <span className="wsp-muted">
          <span className="wsp-size">
            {asset.response_size
              ? `${(asset.response_size / 1024).toFixed(1)} KB`
              : "-"}
          </span>
          <span className="wsp-time">
            {asset.response_time ? `${asset.response_time}s` : "-"}
          </span>
        </span>
      ),
    },
  ];

  return (
    <AppLayout pageTitle="Asset Inventory">
      <CcurePage>
        <CcurePageHeader
          title="Asset Inventory"
          subtitle={<>Discovered endpoints, APIs, and technologies</>}
          breadcrumb={
            <Link to={`/web-scans/${id}`} className="wsp-back">
              ← Back to Scan Detail
            </Link>
          }
          actions={
            <CcureInput
              type="search"
              label="Search assets"
              placeholder="Search URLs or Content-Types..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              fieldClassName="wsp-search"
            />
          }
        />

        <div className="wsp-panel">
          {loading ? (
            <div className="wsp-loading" role="status" aria-live="polite">
              <span className="cc-sr-only">Loading discovered assets…</span>
              <CcureSkeleton height="40px" radius="8px" />
              <CcureSkeleton height="50px" radius="8px" />
              <CcureSkeleton height="50px" radius="8px" />
              <CcureSkeleton height="50px" radius="8px" />
              <CcureSkeleton height="50px" radius="8px" />
            </div>
          ) : filteredAssets.length === 0 ? (
            <CcureEmptyState
              title="No Assets Found"
              description="No discovered endpoints match the current search."
            />
          ) : (
            <CcureTable
              caption={`Discovered assets — ${filteredAssets.length} endpoint${filteredAssets.length !== 1 ? "s" : ""}`}
              columns={columns}
              rows={filteredAssets}
              rowKey={(asset) => asset.id}
              density="comfortable"
            />
          )}
        </div>
      </CcurePage>
    </AppLayout>
  );
}
