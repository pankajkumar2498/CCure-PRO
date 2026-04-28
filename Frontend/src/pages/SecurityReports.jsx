/**
 * src/pages/SecurityReports.jsx
 *
 * The "Cabinet": A production-grade repository for all generated security audit reports.
 * Allows users to search, filter, and download historical reports (PDF/XML) for compliance.
 */
import { useEffect, useState, useCallback, useRef } from "react";
import AppLayout from "../components/layout/AppLayout";
import { getScans, purgeScan } from "../api/scans";
import { useAuth } from "../context/AuthContext";
import api from "../api/axiosInstance";
import { dateTimeMs, formatDateTime } from "../utils/date";

/* ── Constants & Helpers ─────────────────────────────────────────────────── */

const REPORT_TYPE_LABELS = {
  basic:    "Host Discovery",
  asset:    "Asset Discovery",
  advanced: "Advanced Vulnerability Audit",
  credentialed: "SSH Credentialed Audit"
};

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
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [modal, setModal] = useState(null);

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
      alert("Failed to download report. The session may have expired.");
    }
  };

  const handleDelete = (scanId) => {
    const scan = scans.find(s => s.id === scanId);
    if (!scan) return;
    
    setModal({
      config: {
        icon: "🗑️",
        iconClass: "danger",
        title: `Permanently Delete Report #${scanId}?`,
        subtitle: "This action cannot be undone. The scan record and its report will be completely removed.",
        warning: "Once deleted, you cannot recover this report or its associated data. This is irreversible.",
        confirmLabel: "Delete Permanently",
        confirmClass: "danger",
      },
      scanId: scanId,
    });
  };

  const handleConfirmDelete = async () => {
    if (!modal?.scanId) return;
    
    const scanId = modal.scanId;
    try {
      await purgeScan(scanId);
      setScans(prev => prev.filter(s => s.id !== scanId));
      setModal(null);
    } catch (err) {
      console.error("Delete failed:", err);
      setModal(null);
      alert("Failed to delete report.");
    }
  };

  const filtered = scans.filter(s => {
    const matchesSearch = s.target.toLowerCase().includes(search.toLowerCase()) || 
                          s.id.toString().includes(search);
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
              placeholder="Search by target IP or Scan ID..." 
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
              />
            ))}
          </div>
        )}

      </div>

      <style dangerouslySetInnerHTML={{ __html: `
        .reports-header-box {
          background: #1e293b;
          border-radius: 12px;
          padding: 24px 32px;
          color: white;
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
          box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
        }
        .rh-stats {
          display: flex;
          gap: 32px;
        }
        .rh-stat-item {
          display: flex;
          flex-direction: column;
          align-items: flex-end;
        }
        .rh-stat-val {
          font-size: 1.5rem;
          font-weight: 700;
          color: #38bdf8;
        }
        .rh-stat-lab {
          font-size: 0.75rem;
          color: #94a3b8;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        
        .reports-filter-bar {
          display: flex;
          gap: 16px;
          margin-bottom: 24px;
          align-items: center;
        }
        .search-input-wrap {
          flex: 1;
          position: relative;
        }
        .search-icon {
          position: absolute;
          left: 12px;
          top: 50%;
          transform: translateY(-50%);
          color: #64748b;
        }
        .search-input {
          width: 100%;
          padding: 10px 12px 10px 40px;
          border-radius: 8px;
          border: 1px solid #e2e8f0;
          background: white;
          font-size: 0.9rem;
          outline: none;
          transition: border-color 0.2s;
        }
        .search-input:focus {
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59,130,246,0.1);
        }
        
        .filter-select {
          padding: 10px 16px;
          border-radius: 8px;
          border: 1px solid #e2e8f0;
          background: white;
          font-size: 0.9rem;
          outline: none;
          min-width: 180px;
        }

        .reports-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
          gap: 20px;
        }

        .report-card {
          background: white;
          border-radius: 12px;
          border: 1px solid #e2e8f0;
          padding: 20px;
          transition: transform 0.2s, box-shadow 0.2s;
          display: flex;
          flex-direction: column;
          gap: 16px;
          position: relative;
          overflow: hidden;
        }
        .report-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);
        }
        
        .rc-top {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
        }
        .rc-type-tag {
          font-size: 10px;
          font-weight: 700;
          text-transform: uppercase;
          padding: 2px 8px;
          border-radius: 4px;
          background: #f1f5f9;
          color: #475569;
        }
        .rc-id {
          font-family: var(--mono);
          font-size: 11px;
          color: #94a3b8;
        }
        
        .rc-target {
          font-size: 1.1rem;
          font-weight: 700;
          color: #1e293b;
          margin-top: 4px;
          word-break: break-all;
        }
        
        .rc-meta {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          font-size: 0.8rem;
          color: #64748b;
          border-top: 1px solid #f1f5f9;
          border-bottom: 1px solid #f1f5f9;
          padding: 12px 0;
        }
        .rc-meta-item {
          display: flex;
          align-items: center;
          gap: 4px;
        }

        .rc-actions {
          display: flex;
          gap: 10px;
        }
        .download-btn {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          padding: 8px 0;
          border-radius: 6px;
          font-size: 0.85rem;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
          border: 1px solid #e2e8f0;
        }
        .download-btn--json {
          background: #f8fafc;
          color: #1e293b;
        }
        .download-btn--json:hover {
          background: #f1f5f9;
        }
        .download-btn--xml {
          background: #f0f9ff;
          color: #0369a1;
          border-color: #bae6fd;
        }
        .download-btn--xml:hover {
          background: #e0f2fe;
        }
        .download-btn--delete {
          max-width: 44px;
          color: #94a3b8;
        }
        .download-btn--delete:hover {
          background: #fef2f2;
          color: #ef4444;
          border-color: #fecaca;
        }
        
        .reports-loading-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 60px;
          gap: 16px;
          color: #64748b;
        }

        .btn--rerun-sm {
          padding: 4px 10px;
          font-size: 11px;
        }
      `}} />

      {/* Confirmation modal for permanent deletion */}
      {modal && (
        <ConfirmDialog
          config={modal.config}
          onConfirm={handleConfirmDelete}
          onCancel={() => setModal(null)}
        />
      )}
    </AppLayout>
  );
}

function ReportCard({ scan, onDownload }) {
  const typeLabel = REPORT_TYPE_LABELS[scan.pipeline_mode] || 
                   (scan.scan_type === "credentialed" ? REPORT_TYPE_LABELS.credentialed : "Security Audit");

  return (
    <div className="report-card">
      <div className="rc-top">
        <span className="rc-type-tag">{typeLabel}</span>
        <span className="rc-id">#{scan.id}</span>
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
          title="Download Professional PDF Report with formatted tables"
        >
          <span>📄</span> Official Report
        </button>
        <button 
          className="download-btn download-btn--xml" 
          onClick={() => onDownload(scan.id, 'XML')}
          title="Download Technical PDF containing raw audit data"
        >
          <span>📝</span> Technical Data
        </button>
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
