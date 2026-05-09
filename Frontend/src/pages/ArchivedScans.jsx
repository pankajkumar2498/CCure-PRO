import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "../context/AuthContext";
import { getScans, restoreScan, deleteScan } from "../api/scans";
import { formatDateTime } from "../utils/date";
import { useToasts, ToastContainer } from "../components/common/Toast";
import { can, denyMessage } from "../auth/permissions";

const STATUS_STYLE = {
  complete: { color: "#22c55e", bg: "rgba(34,197,94,.1)", border: "rgba(34,197,94,.25)" },
  running:  { color: "#f59e0b", bg: "rgba(245,158,11,.1)", border: "rgba(245,158,11,.25)" },
  failed:   { color: "#ef4444", bg: "rgba(239,68,68,.1)", border: "rgba(239,68,68,.25)" },
};

const PHASE_LABELS = { 1: "Discovery", 2: "Port Scan", 3: "Vulnerability" };

const isCred = (scan) => scan.scan_type === "credentialed";
const scanNo = (scan) => scan.scan_no ?? scan.display_id ?? "-";

const phaseLabel = (scan) =>
  isCred(scan) ? "Credentialed Audit" : `P${scan.phase} - ${PHASE_LABELS[scan.phase] || "-"}`;

const fmtDate = (iso) =>
  formatDateTime(iso, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

const fmtDur = (sec) =>
  !sec ? "-" : sec < 60 ? `${sec.toFixed(1)}s` : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;

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

export default function ArchivedScans() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canDeleteScans = can(user, "scans", "delete");

  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [restoringId, setRestoringId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await getScans(0, 200, "archived");
      setScans(data.scans);
      setTotal(data.total);
    } catch {
      setError("Failed to load archived scans.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleRestore = async (id) => {
    if (!canDeleteScans) {
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
      pushToast(err.response?.data?.detail || "Failed to restore scan.", "error");
    } finally {
      setRestoringId(null);
    }
  };

  const handleDelete = async (id) => {
    if (!canDeleteScans) {
      pushToast(denyMessage, "error");
      return;
    }
    setDeletingId(id);
    try {
      await deleteScan(id);
      setScans((prev) => prev.filter((scan) => scan.id !== id));
      setTotal((prev) => Math.max(prev - 1, 0));
      pushToast("Scan moved to Recycle Bin.", "success");
    } catch (err) {
      pushToast(err.response?.data?.detail || "Failed to move scan to Recycle Bin.", "error");
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <AppLayout pageTitle="Archived Scans">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Archived Scans</h2>
            <p className="page-subtitle" style={{ fontFamily: "var(--mono)" }}>
              {total} archived scan{total !== 1 ? "s" : ""} - {user?.username}
            </p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn--ghost" onClick={() => navigate("/history")}>
              My Scan Jobs
            </button>
            <button className="btn btn--ghost" onClick={load} disabled={loading}>
              {loading ? <span className="btn-spinner btn-spinner--dark" /> : "Refresh"}
            </button>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        {loading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
            <div className="spinner" />
          </div>
        )}

        {!loading && !error && scans.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon">-</span>
            <p className="empty-state-title">No archived scans yet.</p>
            <button className="btn btn--primary" style={{ marginTop: 16 }} onClick={() => navigate("/history")}>
              Back to My Scan Jobs
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
                  <th>Phase</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Archived</th>
                  <th>Created</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <code className="ip-code" style={{ fontSize: 12 }}>{scanNo(scan)}</code>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600 }}>
                        {scan.target}
                      </span>
                    </td>
                    <td><span className="method-chip">{scan.scan_type}</span></td>
                    <td>
                      <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{phaseLabel(scan)}</span>
                    </td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 13 }}>{fmtDur(scan.scan_duration)}</span>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-muted)" }}>
                        {fmtDate(scan.archived_at)}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-muted)" }}>
                        {fmtDate(scan.created_at)}
                      </span>
                    </td>
                    <td>
                      <div className="action-btns">
                        {canDeleteScans ? (
                          <>
                            <button
                              className="action-btn"
                              onClick={() => handleRestore(scan.id)}
                              disabled={restoringId === scan.id}
                            >
                              {restoringId === scan.id ? "..." : "Restore"}
                            </button>
                            <button
                              className="action-btn action-btn--danger"
                              onClick={() => handleDelete(scan.id)}
                              disabled={deletingId === scan.id}
                            >
                              {deletingId === scan.id ? "..." : "Delete"}
                            </button>
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
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
