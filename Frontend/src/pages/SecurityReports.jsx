/**
 * src/pages/SecurityReports.jsx
 *
 * The "Cabinet": A production-grade repository for all generated security audit reports.
 * Allows users to search, filter, and download historical reports (PDF/XML) for compliance.
 */
import { useEffect, useState, useCallback, useRef } from "react";
import AppLayout from "../components/layout/AppLayout";
import { getScans, deleteReport } from "../api/scans";
import { useAuth } from "../context/AuthContext";
import api from "../api/axiosInstance";
import { dateTimeMs, formatDateTime } from "../utils/date";
import { useToasts, ToastContainer } from "../components/common/Toast";
import { can, denyMessage } from "../auth/permissions";
import "../styles/SecurityReports.css";


/* ── Constants & Helpers ─────────────────────────────────────────────────── */

const REPORT_TYPE_LABELS = {
  basic:    "Host Discovery",
  asset:    "Asset Discovery",
  advanced: "Advanced Vulnerability Audit",
  credentialed: "SSH Credentialed Audit"
};

const scanNo = scan => scan.scan_no ?? scan.display_id ?? "-";

const fmtDate = iso => 
  iso ? new Date(iso).toLocaleString(undefined, { 
    month: "short", day: "numeric", year: "numeric", 
    hour: "2-digit", minute: "2-digit" 
  }) : "—";

const fmtDur = sec =>
  !sec ? "—" : sec < 60 ? `${sec.toFixed(1)}s` : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;

/* ── CONFIRMATION DIALOG COMPONENT ──────────────────────────────────────── */
function ConfirmDialog({ config, onConfirm, onCancel }) {
  const { title, subtitle, warning, confirmLabel, confirmClass, icon, iconClass } = config;
  const [busy, setBusy] = useState(false);
  const btnRef = useRef(null);

  useEffect(() => { btnRef.current?.focus(); }, []);

  useEffect(() => {
    const onKey = e => { if (e.key === "Escape") onCancel(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const handleConfirm = async () => {
    setBusy(true);
    try { await onConfirm(); }
    finally { setBusy(false); }
  };

  return (
    <div className="confirm-overlay" onClick={e => e.target === e.currentTarget && onCancel()}>
      <div className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="cdlg-title">
        <div className="confirm-dialog-header">
          <div className={`confirm-dialog-icon confirm-dialog-icon--${iconClass}`}>
            {icon}
          </div>
          <div className="confirm-dialog-titles">
            <div className="confirm-dialog-title" id="cdlg-title">{title}</div>
            <div className="confirm-dialog-subtitle">{subtitle}</div>
          </div>
        </div>

        {warning && (
          <div className={`confirm-dialog-warning confirm-dialog-warning--danger`}>
            <span style={{ flexShrink: 0 }}>⚠️</span>
            <span>{warning}</span>
          </div>
        )}

        <div className="confirm-dialog-footer">
          <button className="confirm-btn confirm-btn--cancel" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            ref={btnRef}
            className={`confirm-btn confirm-btn--${confirmClass}`}
            onClick={handleConfirm}
            disabled={busy}
          >
            {busy ? <span className="confirm-btn-spinner" /> : null}
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Main Component ──────────────────────────────────────────────────────── */

export default function SecurityReports() {
  const { user } = useAuth();
  const canReadReports = can(user, "reports", "read");
  const canDeleteReports = can(user, "reports", "delete");
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [modal, setModal] = useState(null);
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

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
      const reportableScans = allScans.filter(s => 
        (s.status === "complete" || s.has_json_report || s.has_xml_report)
      );
      
      setScans(reportableScans);
    } catch (err) {
      console.error("Failed to load reports:", err);
      setError("Failed to synchronize with the report repository.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDownload = async (scanId, format) => {
    if (!canReadReports) {
      pushToast(denyMessage, "error");
      return;
    }
    try {
      const response = await api.get(`/reports/download/${scanId}`, {
        params: { fmt: format },
        responseType: 'blob'
      });

      // Create a blob URL and trigger download
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      // Filename from header or fallback
      const contentDisposition = response.headers['content-disposition'];
      let fileName = `report_${scanId}_${format.toLowerCase()}.pdf`;
      if (contentDisposition) {
        const matches = /filename="?([^"]+)"?/.exec(contentDisposition);
        if (matches && matches[1]) fileName = matches[1];
      }
      
      link.setAttribute('download', fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download failed:", err);
      pushToast("Failed to download report. The session may have expired.", "error");
    }
  };

  const handleDelete = (scanId) => {
    if (!canDeleteReports) {
      pushToast(denyMessage, "error");
      return;
    }
    const scan = scans.find(s => s.id === scanId);
    if (!scan) return;
    
    setModal({
      config: {
        icon: "🗑️",
        iconClass: "danger",
        title: `Permanently Delete Report for Scan No. ${scanNo(scan)}?`,
        subtitle: "This action cannot be undone. The scan record and its report will be completely removed.",
        warning: "Once deleted, you cannot recover this report or its associated data. This is irreversible.",
        confirmLabel: "Delete Permanently",
        confirmClass: "danger",
      },
      scanId: scanId,
    });
  };

  const handleConfirmDelete = async () => {
    if (!canDeleteReports) {
      setModal(null);
      pushToast(denyMessage, "error");
      return;
    }
    if (!modal?.scanId) return;
    
    const scanId = modal.scanId;
    try {
      await deleteReport(scanId);
      setScans(prev => prev.filter(s => s.id !== scanId));
      setModal(null);
    } catch (err) {
      console.error("Delete failed:", err);
      setModal(null);
      pushToast("Failed to delete report.", "error");
    }
  };

  const filtered = scans.filter(s => {
    const searchText = search.toLowerCase();
    const matchesSearch = s.target.toLowerCase().includes(searchText) ||
                          String(s.scan_no ?? s.display_id ?? "").includes(searchText);
    const matchesType = filterType === "all" || s.pipeline_mode === filterType || (filterType === "credentialed" && s.scan_type === "credentialed");
    return matchesSearch && matchesType;
  });

  return (
    <AppLayout pageTitle="Security Reports">
      <div className="page-inner">
        
        {/* Header Section */}
        <div className="reports-header-box">
          <div className="rh-left">
            <h2 className="page-title">Digital Report Cabinet</h2>
            <p className="page-subtitle">
              Securely store and retrieve historical audit archives for compliance and sharing.
            </p>
          </div>
          <div className="rh-stats">
            <div className="rh-stat-item">
              <span className="rh-stat-val">{scans.length}</span>
              <span className="rh-stat-lab">Total Reports</span>
            </div>
            <div className="rh-stat-item">
              <span className="rh-stat-val">
                {scans.filter(s => dateTimeMs(s.created_at) > Date.now() - 8.64e7).length}
              </span>
              <span className="rh-stat-lab">New Today</span>
            </div>
          </div>
        </div>

        {/* Search & Filter Bar */}
        <div className="reports-filter-bar">
          <div className="search-input-wrap">
            <span className="search-icon">🔍</span>
            <input 
              type="text" 
              placeholder="Search by target IP or Scan No..." 
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="search-input"
            />
          </div>
          <div className="filter-select-wrap">
            <select 
              value={filterType} 
              onChange={e => setFilterType(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Report Types</option>
              <option value="basic">Host Discovery</option>
              <option value="asset">Asset Discovery</option>
              <option value="advanced">Advanced Audits</option>
              <option value="credentialed">Credentialed Audits</option>
            </select>
          </div>
          <button className="btn btn--ghost" onClick={load} disabled={loading}>
            {loading ? "Syncing..." : "Refresh Cabinet"}
          </button>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        {loading ? (
          <div className="reports-loading-state">
            <div className="spinner" />
            <p>Accessing secure storage...</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state-icon">📁</span>
            <p className="empty-state-title">No reports found in this section.</p>
            <p className="empty-state-subtitle">Complete a scan to automatically generate and store a report here.</p>
          </div>
        ) : (
          <div className="reports-grid">
            {filtered.map(scan => (
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

      </div>

      

      {/* Confirmation modal for permanent deletion */}
      {modal && (
        <ConfirmDialog
          config={modal.config}
          onConfirm={handleConfirmDelete}
          onCancel={() => setModal(null)}
        />
      )}
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}

function ReportCard({ scan, onDownload, onDelete, canReadReports, canDeleteReports }) {
  const typeLabel = REPORT_TYPE_LABELS[scan.pipeline_mode] || 
                   (scan.scan_type === "credentialed" ? REPORT_TYPE_LABELS.credentialed : "Security Audit");

  return (
    <div className="report-card">
      <div className="rc-top">
        <span className="rc-type-tag">{typeLabel}</span>
        <span className="rc-id">Scan No. {scanNo(scan)}</span>
      </div>

      <div className="rc-body">
        <div className="rc-target">{scan.target}</div>
        <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 2 }}>
          {formatDateTime(scan.created_at, { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" })}
        </div>
      </div>

      <div className="rc-meta">
        <div className="rc-meta-item">
          <span>⏱️</span> {fmtDur(scan.scan_duration)}
        </div>
        <div className="rc-meta-item">
          <span>🎯</span> {scan.summary?.active_hosts || 0} Hosts
        </div>
        {scan.summary?.cve_count !== undefined && (
          <div className="rc-meta-item">
            <span>🛡️</span> {scan.summary.cve_count} Findings
          </div>
        )}
      </div>

      <div className="rc-actions">
        <button 
          className="download-btn download-btn--json" 
          onClick={() => onDownload(scan.id, 'JSON')}
          disabled={!canReadReports}
          title="Download Professional PDF Report with formatted tables"
        >
          <span>📄</span> Official Report
        </button>
        <button 
          className="download-btn download-btn--xml" 
          onClick={() => onDownload(scan.id, 'XML')}
          disabled={!canReadReports}
          title="Download Technical PDF containing raw audit data"
        >
          <span>📝</span> Technical Data
        </button>
        {canDeleteReports && (
          <button
            className="download-btn download-btn--delete"
            onClick={() => onDelete(scan.id)}
            title="Delete report artifacts"
          >
            <span>🗑️</span>
          </button>
        )}
      </div>
      
      {/* Visual indicate for "Stored in Cabinet" */}
      <div style={{ 
        position: 'absolute', right: -15, bottom: -15, 
        fontSize: '40px', opacity: 0.03, pointerEvents: 'none' 
      }}>
        🛡️
      </div>
    </div>
  );
}
