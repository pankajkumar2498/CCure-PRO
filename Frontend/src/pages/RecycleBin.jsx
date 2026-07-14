import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { getScans, purgeScan, restoreScan } from "../api/scans";
import { formatDateTime } from "../utils/date";
import { useToasts, ToastContainer } from "../components/common/Toast";
import { can, denyMessage } from "../auth/permissions";
import { SCAN_PIPELINES } from "../config/scanConfig";

const STATUS_STYLE = {
  complete: {
    color: "#22c55e",
    bg: "rgba(34,197,94,.1)",
    border: "rgba(34,197,94,.25)",
  },
  running: {
    color: "#f59e0b",
    bg: "rgba(245,158,11,.1)",
    border: "rgba(245,158,11,.25)",
  },
  failed: {
    color: "#ef4444",
    bg: "rgba(239,68,68,.1)",
    border: "rgba(239,68,68,.25)",
  },
  cancelled: {
    color: "#ef4444",
    bg: "rgba(239,68,68,.1)",
    border: "rgba(239,68,68,.25)",
  },
  canceled: {
    color: "#ef4444",
    bg: "rgba(239,68,68,.1)",
    border: "rgba(239,68,68,.25)",
  },
};

const PHASE_LABELS = { 1: "Discovery", 2: "Port Scan", 3: "Vulnerability" };

const isCred = (scan) => scan.scan_type === "credentialed";
const scanNo = (scan) => scan.scan_no ?? scan.display_id ?? "-";

const phaseLabel = (scan) =>
  isCred(scan)
    ? "Credentialed Audit"
    : `P${scan.phase} - ${PHASE_LABELS[scan.phase] || "-"}`;

const scanTypeLabel = (scan) => {
  if (!scan) return "Unknown";
  if (isCred(scan)) return "Credentialed Scan";
  const mode = scan.pipeline_mode || "basic";
  const pipeline = SCAN_PIPELINES[mode];
  return (
    pipeline?.label ||
    String(scan.pipeline_mode || scan.scan_type || "Unknown").replace(/_/g, " ")
  );
};

const fmtDate = (iso) =>
  formatDateTime(iso, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

const fmtDur = (sec) =>
  !sec
    ? "-"
    : sec < 60
      ? `${sec.toFixed(1)}s`
      : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;

function StatusBadge({ status }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.running;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 9px",
        borderRadius: 4,
        background: s.bg,
        border: `1px solid ${s.border}`,
        color: s.color,
        fontSize: 11,
        fontFamily: "var(--mono)",
        letterSpacing: ".05em",
      }}
    >
      {status}
    </span>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   CONFIRMATION DIALOG
   ══════════════════════════════════════════════════════════════════════════ */
function ConfirmDialog({ config, onConfirm, onCancel }) {
  const {
    title,
    subtitle,
    warning,
    confirmLabel,
    confirmClass,
    icon,
    iconClass,
  } = config;
  const [busy, setBusy] = useState(false);
  const btnRef = useRef(null);

  // Focus confirm button on mount
  useEffect(() => {
    btnRef.current?.focus();
  }, []);

  // ESC to cancel
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const handleConfirm = async () => {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="confirm-overlay"
      onClick={(e) => e.target === e.currentTarget && onCancel()}
    >
      <div
        className="confirm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="cdlg-title"
      >
        {/* Header */}
        <div className="confirm-dialog-header">
          <div
            className={`confirm-dialog-icon confirm-dialog-icon--${iconClass}`}
          >
            {icon}
          </div>
          <div className="confirm-dialog-titles">
            <div className="confirm-dialog-title" id="cdlg-title">
              {title}
            </div>
            <div className="confirm-dialog-subtitle">{subtitle}</div>
          </div>
        </div>

        {/* Warning banner */}
        {warning && (
          <div
            className={`confirm-dialog-warning confirm-dialog-warning--danger`}
          >
            <span style={{ flexShrink: 0 }}>⚠️</span>
            <span>{warning}</span>
          </div>
        )}

        {/* Footer */}
        <div className="confirm-dialog-footer">
          <button
            className="confirm-btn confirm-btn--cancel"
            onClick={onCancel}
            disabled={busy}
          >
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

export default function RecycleBin() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canRestoreScans = can(user, "scans", "restore");
  const canPurgeScans = can(user, "scans", "purge");

  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [purgingId, setPurgingId] = useState(null);
  const [restoringId, setRestoringId] = useState(null);
  const [modal, setModal] = useState(null);
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await getScans(0, 200, "deleted");
      setScans(data.scans);
      setTotal(data.total);
    } catch {
      setError("Failed to load recycle bin.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleRestore = async (id) => {
    if (!canRestoreScans) {
      pushToast(denyMessage, "error");
      return;
    }
    setRestoringId(id);
    try {
      await restoreScan(id);
      setScans((prev) => prev.filter((scan) => scan.id !== id));
      setTotal((prev) => Math.max(prev - 1, 0));
      pushToast("Scan restored successfully.", "success");
    } catch (err) {
      pushToast(
        err.response?.data?.detail || "Failed to restore scan.",
        "error",
      );
    } finally {
      setRestoringId(null);
    }
  };

  const handlePermanentDelete = (id) => {
    if (!canPurgeScans) {
      pushToast(denyMessage, "error");
      return;
    }
    const scan = scans.find((s) => s.id === id);
    if (!scan) return;

    setModal({
      config: {
        icon: "🗑️",
        iconClass: "danger",
        title: `Permanently Delete Scan No. ${scanNo(scan)}?`,
        subtitle:
          "This action cannot be undone. The scan record will be completely removed from the system.",
        warning:
          "Once deleted, you cannot recover this scan or its associated data. This is irreversible.",
        confirmLabel: "Delete Permanently",
        confirmClass: "danger",
      },
      scanId: id,
    });
  };

  const handleConfirmDelete = async () => {
    if (!canPurgeScans) {
      setModal(null);
      pushToast(denyMessage, "error");
      return;
    }
    if (!modal?.scanId) return;

    const id = modal.scanId;
    setPurgingId(id);
    try {
      await purgeScan(id);
      setScans((prev) => prev.filter((scan) => scan.id !== id));
      setTotal((prev) => Math.max(prev - 1, 0));
      setModal(null);
      pushToast("Scan permanently deleted.", "success");
    } catch (err) {
      setModal(null);
      pushToast(
        err.response?.data?.detail || "Failed to delete scan permanently.",
        "error",
      );
    } finally {
      setPurgingId(null);
    }
  };

  return (
    <AppLayout pageTitle="Recycle Bin">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Recycle Bin</h2>
            <p className="page-subtitle" style={{ fontFamily: "var(--mono)" }}>
              {total} scan{total !== 1 ? "s" : ""} ready for permanent deletion
              - {user?.username}
            </p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="btn btn--ghost"
              onClick={() => navigate("/history")}
            >
              My Scan Jobs
            </button>
            <button
              className="btn btn--ghost"
              onClick={load}
              disabled={loading}
            >
              {loading ? (
                <span className="btn-spinner btn-spinner--dark" />
              ) : (
                "Refresh"
              )}
            </button>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        {loading && (
          <div
            style={{ display: "flex", justifyContent: "center", padding: 60 }}
          >
            <div className="spinner" />
          </div>
        )}

        {!loading && !error && scans.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon">-</span>
            <p className="empty-state-title">Recycle Bin is empty.</p>
            <button
              className="btn btn--primary"
              style={{ marginTop: 16 }}
              onClick={() => navigate("/history")}
            >
              Back to Scan Jobs
            </button>
          </div>
        )}

        {!loading && scans.length > 0 && (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scan No.</th>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Deleted</th>
                  <th>Created</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <code className="ip-code" style={{ fontSize: 12 }}>
                        {scanNo(scan)}
                      </code>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: "var(--mono)",
                          fontSize: 13,
                          fontWeight: 600,
                        }}
                      >
                        {scan.target}
                      </span>
                    </td>
                    <td>
                      <span className="method-chip">{scanTypeLabel(scan)}</span>
                    </td>
                    <td>
                      <StatusBadge status={scan.status} />
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
                        {fmtDur(scan.scan_duration)}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: "var(--mono)",
                          fontSize: 12,
                          color: "var(--text-muted)",
                        }}
                      >
                        {fmtDate(scan.deleted_at)}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: "var(--mono)",
                          fontSize: 12,
                          color: "var(--text-muted)",
                        }}
                      >
                        {fmtDate(scan.created_at)}
                      </span>
                    </td>
                    <td>
                      <div className="action-btns">
                        {canRestoreScans || canPurgeScans ? (
                          <>
                            {canRestoreScans && (
                              <button
                                className="action-btn"
                                onClick={() => handleRestore(scan.id)}
                                disabled={restoringId === scan.id}
                              >
                                {restoringId === scan.id ? "..." : "Restore"}
                              </button>
                            )}
                            {canPurgeScans && (
                              <button
                                className="action-btn action-btn--danger"
                                onClick={() => handlePermanentDelete(scan.id)}
                                disabled={purgingId === scan.id}
                              >
                                {purgingId === scan.id
                                  ? "..."
                                  : "Delete Permanently"}
                              </button>
                            )}
                          </>
                        ) : (
                          <span className="muted">Read only</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
