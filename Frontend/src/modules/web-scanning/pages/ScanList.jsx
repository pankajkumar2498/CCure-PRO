/**
 * modules/web-scanning/pages/ScanList.jsx
 * The index of DAST scans.
 *
 * ── Contract, unchanged by the Checkpoint 3C batch-6 migration ──────────────
 * Every request, payload, navigation target and state transition below is what
 * it was before. The migration changed presentation only. Specifically
 * preserved:
 *
 *   * `getScans({ per_page: 100 })` is the whole request. No scope, org or
 *     filter parameter is added client-side — the API decides what this
 *     account may see, and narrowing results in the browser would be inventing
 *     an authorisation boundary where none exists;
 *   * both response shapes are still accepted (`data.data` and `data.items`);
 *   * a failed load still leaves the list empty rather than throwing;
 *   * the page does not poll.
 *
 * ── What the migration changed ──────────────────────────────────────────────
 * `getStatusColor` is gone. Beyond its inline styling it had a defect that is
 * invisible in review and obvious once measured: the badge was built as
 *
 *     border: `1px solid ${getStatusColor(scan.status)}40`
 *
 * and `getStatusColor` returns `var(--ok)`, so the value was `var(--ok)40` —
 * not a colour. The browser drops the whole declaration, so every status badge
 * on this page silently had no border and no background. `CcureScanStatus`
 * carries the same vocabulary and reports an unrecognised status as "Unknown"
 * rather than guessing.
 *
 * The finding counts were `2 C` / `3 H`, which a screen reader announces as
 * "two see" and "three aitch". They are `CcureSeverityBadge` now, which puts
 * the band's name in the accessible name.
 */
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../../components/layout/AppLayout";
import { webScansApi } from "../api/webScansApi";
import {
  CcureButton,
  CcureEmptyState,
  CcureScanStatus,
  CcureSeverityBadge,
  CcureSkeleton,
  CcureTable,
} from "../../../design-system";
import "../styles/web-scanning-pages.css";

export default function ScanList() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchScans() {
      try {
        setLoading(true);
        const res = await webScansApi.getScans({ per_page: 100 });
        setScans(res.data?.data || res.data?.items || []);
      } catch (err) {
        console.error("Failed to load scans", err);
      } finally {
        setLoading(false);
      }
    }
    fetchScans();
  }, []);

  /* Declared columns, so CcureTable owns the caption, `scope="col"` on every
     header and `scope="row"` on the scan name — the row's identity, and what a
     reader needs announced beside every other cell. */
  const columns = [
    {
      key: "scan_name",
      header: "Scan name",
      isRowHeader: true,
      cell: (scan) => (
        <CcureButton
          variant="ghost"
          size="sm"
          className="wsp-linklike"
          onClick={() => navigate(`/web-scans/${scan.id}`)}
        >
          {scan.scan_name}
        </CcureButton>
      ),
    },
    {
      key: "target_url",
      header: "Target",
      mono: true,
      /* Deliberately not an anchor. The target is whatever URL somebody asked
         the scanner to hit; making it followable invites a click straight at it
         from inside the console. */
      cell: (scan) => <span className="wsp-target">{scan.target_url}</span>,
    },
    {
      key: "status",
      header: "Status",
      cell: (scan) => <CcureScanStatus status={scan.status} />,
    },
    {
      key: "pipeline_phase",
      header: "Phase",
      cell: (scan) => (
        <span className="wsp-muted">{scan.pipeline_phase || "-"}</span>
      ),
    },
    {
      key: "findings",
      header: "Findings",
      cell: (scan) => {
        const bands = [];
        if (scan.critical_count > 0) {
          bands.push(
            <CcureSeverityBadge
              key="critical"
              severity="critical"
              score={scan.critical_count}
            />,
          );
        }
        if (scan.high_count > 0) {
          bands.push(
            <CcureSeverityBadge
              key="high"
              severity="high"
              score={scan.high_count}
            />,
          );
        }
        if (bands.length === 0) {
          return <span className="wsp-muted">-</span>;
        }
        return <div className="wsp-bands">{bands}</div>;
      },
    },
    {
      key: "created_at",
      header: "Date",
      nowrap: true,
      cell: (scan) => (
        <span className="wsp-muted">
          {new Date(scan.created_at).toLocaleDateString()}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      cell: (scan) => (
        <CcureButton
          variant="secondary"
          size="sm"
          onClick={() => navigate(`/web-scans/${scan.id}`)}
          /* "View" repeats once per row, so a reader listing controls gets N
             identical entries and no way to tell which scan each opens. */
          aria-label={`View ${scan.scan_name}`}
        >
          View
        </CcureButton>
      ),
    },
  ];

  return (
    <AppLayout pageTitle="Web Scans">
      <div className="page-inner wsp-page">
        <div className="wsp-header">
          <div>
            <h1 className="page-title">Web Scans</h1>
            <p className="page-subtitle">Manage and monitor DAST assessments</p>
          </div>
          <CcureButton onClick={() => navigate("/web-scans/new")}>
            + New Scan
          </CcureButton>
        </div>

        <div className="wsp-panel">
          {loading ? (
            /* The skeletons are `aria-hidden`, which is right — they carry no
               information. That makes an announcement necessary rather than
               optional: without it a screen-reader user is told nothing at all
               while the page loads. */
            <div className="wsp-loading" role="status" aria-live="polite">
              <span className="cc-sr-only">Loading web scans…</span>
              <CcureSkeleton height="40px" radius="8px" />
              <CcureSkeleton height="60px" radius="8px" />
              <CcureSkeleton height="60px" radius="8px" />
              <CcureSkeleton height="60px" radius="8px" />
            </div>
          ) : scans.length === 0 ? (
            <CcureEmptyState
              title="No Web Scans Found"
              description="Create your first scan to begin vulnerability assessment."
            />
          ) : (
            <CcureTable
              caption={`Web scans — ${scans.length} scan${scans.length !== 1 ? "s" : ""}`}
              columns={columns}
              rows={scans}
              rowKey={(scan) => scan.id}
              density="comfortable"
            />
          )}
        </div>
      </div>
    </AppLayout>
  );
}
