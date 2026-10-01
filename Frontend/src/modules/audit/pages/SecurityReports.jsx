/**
 * src/modules/audit/pages/SecurityReports.jsx
 *
 * The "Cabinet": a repository for all generated security audit reports.
 * Search, filter and download historical reports for compliance.
 *
 * ── Three properties this page holds, unchanged by the migration ────────────
 *
 * **The listing spans three scopes — active, archived AND deleted.** Reports
 * stay reachable until permanent deletion, so dropping a scope would silently
 * hide reports that still exist.
 *
 * **The download is an authenticated fetch, not a link.** `/reports/download/
 * {id}` is bearer-authenticated, so a bare `<a href>` would be an
 * unauthenticated request and answer 403. It is fetched as an arraybuffer and
 * saved through a blob, with the filename taken from Content-Disposition. The
 * `fmt` values are historical: `JSON` is the executive PDF, `XML` the technical
 * one.
 *
 * **Deletion is gated three ways and says what it does.** The control is not
 * rendered without `reports:delete`; the opener refuses; and the confirm
 * handler refuses again. The wording names the scan and states that the scan
 * record and its report are removed — a destructive warning is not softened
 * into a generic "Are you sure?".
 *
 * ── Migration note (Checkpoint 3C, batch 10) ────────────────────────────────
 * The in-file `ConfirmDialog` is now `CcureConfirmDialog`, which focuses
 * Cancel rather than the destructive action on open. Its wording is carried
 * over verbatim.
 */
import { useEffect, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { getScans, deleteReport } from "@audit/api/scans";
import { useAuth } from "@shell/auth/AuthContext";
import { DOWNLOAD_FORMATS, downloadReport } from "@audit/api/reports";
import { saveResponseAsFile } from "@audit/utils/download";
import { dateTimeMs, formatDateTime } from "@shell/utils/date";
import { can, denyMessage } from "@shell/auth/permissions";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
  CcureEmptyState,
  CcureInput,
  CcureLoader,
  CcureSelect,
  CcureTabs,
  CcureToastProvider,
  useCcureToast,
} from "../../../design-system";
import "../styles/SecurityReports.css";

/* ── Constants & Helpers ─────────────────────────────────────────────────── */

const REPORT_TYPE_LABELS = {
  basic: "Host Discovery",
  asset: "Asset Discovery",
  advanced: "Vulnerability Audit",
  vulnerability_audit: "Vulnerability Audit",
  credentialed: "SSH Credentialed Audit",
};

const TABS = [
  { id: "", label: "Report Cabinet" },
  { id: "executive", label: "Executive Report" },
  { id: "compliance", label: "Compliance" },
  { id: "trends", label: "Risk Trends" },
];

const PLACEHOLDER_TABS = {
  executive: {
    icon: "📊",
    title: "Executive Report Generation",
    body: "Generate high-level, business-focused security posture summaries for stakeholders.",
  },
  compliance: {
    icon: "✅",
    title: "Compliance Auditing",
    body: "Map scan findings to standard compliance frameworks (CIS, SOC 2, ISO 27001).",
  },
  trends: {
    icon: "📈",
    title: "Risk Trends Analytics",
    body: "Visualize organizational risk over time, MTTR (Mean Time to Remediate), and vulnerability velocity.",
  },
};

const scanNo = (scan) => scan.scan_no ?? scan.display_id ?? "-";

const fmtDur = (sec) =>
  !sec
    ? "—"
    : sec < 60
      ? `${sec.toFixed(1)}s`
      : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;

/* ── Main Component ──────────────────────────────────────────────────────── */

/* The provider wraps the view so the view can consume it — a hook cannot read a
   context its own component provides.
   This page uses the design system's toaster rather than the legacy one because
   of a property, not a preference: the legacy container renders no `aria-live`
   at all, so a failed download was shown and never announced. CcureToastProvider
   keeps two always-mounted regions, assertive for danger and polite for the
   rest, which is what makes a message that arrives after the page has settled
   reach a screen reader. */
export default function SecurityReports() {
  return (
    <CcureToastProvider>
      <ReportsView />
    </CcureToastProvider>
  );
}

function ReportsView() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const currentTab = searchParams.get("tab") || "";
  const canReadReports = can(user, "reports", "read");
  const canDeleteReports = can(user, "reports", "delete");
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [modal, setModal] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const toast = useCcureToast();

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      // Fetch scans from all statuses: active, archived, and deleted
      // This ensures reports remain accessible until permanent deletion
      const [activeRes, archivedRes, deletedRes] = await Promise.all([
        getScans(0, 200, "active"),
        getScans(0, 200, "archived"),
        getScans(0, 200, "deleted"),
      ]);

      const allScans = [
        ...(activeRes.data?.scans || []),
        ...(archivedRes.data?.scans || []),
        ...(deletedRes.data?.scans || []),
      ];

      // Filter for scans that actually completed and have reports
      const reportableScans = allScans.filter(
        (s) =>
          s.status === "complete" ||
          s.has_executive_report ||
          s.has_technical_report,
      );

      setScans(reportableScans);
    } catch {
      setError("Failed to synchronize with the report repository.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleDownload = async (scanId, format) => {
    if (!canReadReports) {
      toast.danger(denyMessage);
      return;
    }
    try {
      // Shared with the scan-results export panel: one place that honours
      // the server's Content-Disposition and releases the object URL. The
      // filename matters -- it carries the scan number, and an artefact that
      // ends up attached to an audit must keep the scan it came from.
      const response = await downloadReport(scanId, format);
      const spec = DOWNLOAD_FORMATS.find((f) => f.value === format);
      saveResponseAsFile(
        response,
        `scan_${scanId}_${format.toLowerCase()}.${spec?.ext ?? "pdf"}`,
      );
    } catch {
      toast.danger("Failed to download report. The session may have expired.");
    }
  };

  const handleDelete = (scanId) => {
    if (!canDeleteReports) {
      toast.danger(denyMessage);
      return;
    }
    const scan = scans.find((s) => s.id === scanId);
    if (!scan) return;

    setModal({
      config: {
        title: `Permanently Delete Report for Scan No. ${scanNo(scan)}?`,
        subtitle:
          "This action cannot be undone. The scan record and its report will be completely removed.",
        warning:
          "Once deleted, you cannot recover this report or its associated data. This is irreversible.",
        confirmLabel: "Delete Permanently",
      },
      scanId: scanId,
    });
  };

  const handleConfirmDelete = async () => {
    if (!canDeleteReports) {
      setModal(null);
      toast.danger(denyMessage);
      return;
    }
    if (!modal?.scanId) return;

    const scanId = modal.scanId;
    setDeleting(true);
    try {
      await deleteReport(scanId);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
      setModal(null);
    } catch {
      setModal(null);
      toast.danger("Failed to delete report.");
    } finally {
      setDeleting(false);
    }
  };

  const filtered = scans.filter((s) => {
    const searchText = search.toLowerCase();
    const matchesSearch =
      s.target.toLowerCase().includes(searchText) ||
      String(s.scan_no ?? s.display_id ?? "").includes(searchText);
    const matchesType =
      filterType === "all" ||
      s.pipeline_mode === filterType ||
      (filterType === "credentialed" && s.scan_type === "credentialed");
    return matchesSearch && matchesType;
  });

  const placeholder = PLACEHOLDER_TABS[currentTab];

  return (
    <AppLayout>
      <div className="page-inner">
        {/* Header Section */}
        <div className="reports-header-box">
          <div className="rh-left">
            <h1 className="page-title">Digital Report Cabinet</h1>
            <p className="page-subtitle">
              Securely store and retrieve historical audit archives for
              compliance and sharing.
            </p>
          </div>
          <div className="rh-stats">
            <div className="rh-stat-item">
              <span className="rh-stat-val">{scans.length}</span>
              <span className="rh-stat-lab">Total Reports</span>
            </div>
            <div className="rh-stat-item">
              <span className="rh-stat-val">
                {
                  scans.filter(
                    (s) => dateTimeMs(s.created_at) > Date.now() - 8.64e7,
                  ).length
                }
              </span>
              <span className="rh-stat-lab">New Today</span>
            </div>
          </div>
        </div>

        {/* The tab strip was `<div onClick>`: no role, no tabindex, no key
            handler, so three of the four sections could not be reached without
            a mouse. CcureTabs implements the WAI-ARIA pattern, and the URL
            stays the source of truth exactly as before. */}
        <CcureTabs
          tabs={TABS}
          value={currentTab}
          onChange={(id) => setSearchParams(id ? { tab: id } : {})}
          label="Report sections"
          className="reports-tabs"
        />

        {currentTab === "" && (
          <>
            {/* Search & Filter Bar */}
            <div className="reports-filter-bar">
              <CcureInput
                label="Search reports"
                type="search"
                placeholder="Search by target IP or Scan No..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                fieldClassName="reports-search-field"
              />
              <CcureSelect
                label="Report type"
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                fieldClassName="reports-type-field"
              >
                <option value="all">All Report Types</option>
                <option value="basic">Host Discovery</option>
                <option value="asset">Asset Discovery</option>
                <option value="vulnerability_audit">
                  Vulnerability Audits
                </option>
                <option value="credentialed">Credentialed Audits</option>
              </CcureSelect>
              <CcureButton
                variant="secondary"
                onClick={load}
                loading={loading}
                className="reports-refresh"
              >
                {loading ? "Syncing..." : "Refresh Cabinet"}
              </CcureButton>
            </div>

            {error && <CcureAlert variant="danger">{error}</CcureAlert>}

            {loading ? (
              <div className="reports-loading-state">
                <CcureLoader label="Accessing secure storage…" />
              </div>
            ) : filtered.length === 0 ? (
              <CcureEmptyState
                icon="📁"
                title="No reports found in this section."
                description="Complete a scan to automatically generate and store a report here."
              />
            ) : (
              <div className="reports-grid">
                {filtered.map((scan) => (
                  <ReportCard
                    key={scan.id}
                    scan={scan}
                    onDownload={handleDownload}
                    onDelete={handleDelete}
                    canReadReports={canReadReports}
                    canDeleteReports={canDeleteReports}
                  />
                ))}
              </div>
            )}
          </>
        )}

        {placeholder && (
          <div className="reports-placeholder">
            <div className="rp-icon" aria-hidden="true">
              {placeholder.icon}
            </div>
            <h2 className="rp-title">{placeholder.title}</h2>
            <p>{placeholder.body}</p>
            <CcureBadge variant="info" className="rp-soon">
              AVAILABLE SOON
            </CcureBadge>
          </div>
        )}
      </div>

      {/* Confirmation modal for permanent deletion. The wording is carried over
          verbatim — a destructive warning must not be softened in a migration. */}
      <CcureConfirmDialog
        open={Boolean(modal)}
        title={modal?.config.title || "Delete report?"}
        subtitle={modal?.config.subtitle}
        warning={modal?.config.warning}
        confirmLabel={modal?.config.confirmLabel || "Delete Permanently"}
        tone="danger"
        busy={deleting}
        onConfirm={handleConfirmDelete}
        onCancel={() => setModal(null)}
      />
    </AppLayout>
  );
}

function ReportCard({
  scan,
  onDownload,
  onDelete,
  canReadReports,
  canDeleteReports,
}) {
  const typeLabel =
    (scan.scan_type === "credentialed"
      ? REPORT_TYPE_LABELS.credentialed
      : null) ||
    REPORT_TYPE_LABELS[scan.pipeline_mode] ||
    "Security Audit";

  const no = scanNo(scan);

  return (
    <div className="report-card">
      <div className="rc-top">
        <span className="rc-type-tag">{typeLabel}</span>
        <span className="rc-id">Scan No. {no}</span>
      </div>

      <div className="rc-body">
        <div className="rc-target">{scan.target}</div>
        <div className="rc-date">
          {formatDateTime(scan.created_at, {
            month: "short",
            day: "numeric",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
          })}
        </div>
      </div>

      <div className="rc-meta">
        <div className="rc-meta-item">
          <span aria-hidden="true">⏱️</span> {fmtDur(scan.scan_duration)}
        </div>
        <div className="rc-meta-item">
          <span aria-hidden="true">🎯</span> {scan.summary?.active_hosts || 0}{" "}
          Hosts
        </div>
        {scan.summary?.cve_count !== undefined && (
          <div className="rc-meta-item">
            <span aria-hidden="true">🛡️</span> {scan.summary.cve_count} Findings
          </div>
        )}
      </div>

      {/* Every control names its scan. Three cards each offering "Official
          Report" is three identical entries in a reader's control list, and
          picking the wrong one downloads — or destroys — the wrong scan's
          report. The delete control was previously a bare 🗑️ with only a
          `title`, which is not a reliable accessible name. */}
      <div className="rc-actions">
        <CcureButton
          variant="secondary"
          size="sm"
          className="rc-action"
          onClick={() => onDownload(scan.id, "JSON")}
          disabled={!canReadReports}
          aria-label={`Download the official report for scan number ${no}`}
          title="Download Professional PDF Report with formatted tables"
        >
          <span aria-hidden="true">📄</span> Official Report
        </CcureButton>
        <CcureButton
          variant="secondary"
          size="sm"
          className="rc-action"
          onClick={() => onDownload(scan.id, "XML")}
          disabled={!canReadReports}
          aria-label={`Download the technical data report for scan number ${no}`}
          title="Download Technical PDF containing raw audit data"
        >
          <span aria-hidden="true">📝</span> Technical Data
        </CcureButton>
        <CcureButton
          variant="secondary"
          size="sm"
          className="rc-action"
          onClick={() => onDownload(scan.id, "CSV")}
          disabled={!canReadReports}
          aria-label={`Download the host inventory for scan number ${no}`}
          title="Download the host inventory as CSV"
        >
          <span aria-hidden="true">📇</span> Host inventory
        </CcureButton>
        <CcureButton
          variant="secondary"
          size="sm"
          className="rc-action"
          onClick={() => onDownload(scan.id, "XLSX")}
          disabled={!canReadReports}
          aria-label={`Download the full workbook for scan number ${no}`}
          title="Download verdicts, findings and the comparison as one workbook"
        >
          <span aria-hidden="true">📊</span> Full workbook
        </CcureButton>
        {canDeleteReports && (
          <CcureButton
            variant="danger"
            size="sm"
            className="rc-action rc-action--delete"
            onClick={() => onDelete(scan.id)}
            aria-label={`Delete the report for scan number ${no}`}
            title="Delete report artifacts"
          >
            <span aria-hidden="true">🗑️</span>
          </CcureButton>
        )}
      </div>
    </div>
  );
}
