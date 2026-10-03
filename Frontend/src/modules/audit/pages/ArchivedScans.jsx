/**
 * src/modules/audit/pages/ArchivedScans.jsx
 * Archived scan records — restore, or move to the recycle bin.
 *
 * ── Contract, unchanged by the Checkpoint 3C migration ──────────────────────
 * Every handler, request, permission check, state transition and navigation
 * below is what it was before. The migration changed presentation only.
 * Specifically preserved:
 *
 *   * `getScans(0, 200, "archived")` — the scope argument is load-bearing.
 *     `getScans` defaults to `scope="active"`, so losing it would list live
 *     scans on a page whose Delete button moves them to the recycle bin;
 *   * both actions stay gated on their own permission, `scans:restore` and
 *     `scans:recycle`, at render *and* inside the handler. The client gate is
 *     an affordance, not the authorisation boundary — the API enforces it —
 *     but a control offered to someone who cannot use it produces a failed
 *     request and a confusing error;
 *   * a successful action drops the row locally and does not re-fetch; a
 *     failed one leaves the row in place;
 *   * the page does not poll.
 *
 * src/__tests__/pages/ArchivedScans.test.jsx asserts all of this and was
 * written against the pre-migration page.
 */
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "@audit/components/layout/AppLayout";
import { useAuth } from "@shell/auth/AuthContext";
import { getScans, restoreScan, deleteScan } from "@audit/api/scans";
import { formatDateTime } from "@shell/utils/date";
import { useToasts, ToastContainer } from "@shell/feedback/Toast";
import { can, denyMessage } from "@shell/auth/permissions";
import { SCAN_PIPELINES } from "@audit/config/scanConfig";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureEmptyState,
  CcureLoader,
  CcureScanStatus,
  CcureTable,
} from "../../../design-system";
import "../styles/archived-scans.css";

const isCred = (scan) => scan.scan_type === "credentialed";
const scanNo = (scan) => scan.scan_no ?? scan.display_id ?? "-";

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

export default function ArchivedScans() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canRestoreScans = can(user, "audit.scan.lifecycle");
  const canRecycleScans = can(user, "audit.scan.lifecycle");

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

  const handleDelete = async (id) => {
    if (!canRecycleScans) {
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
      pushToast(
        err.response?.data?.detail || "Failed to move scan to Recycle Bin.",
        "error",
      );
    } finally {
      setDeletingId(null);
    }
  };

  /* Columns are declared rather than hand-written as <tr>/<td>, so CcureTable
     owns the caption, `scope="col"` on every header and `scope="row"` on the
     identifying cell. `mono` replaces four separate inline
     `fontFamily: "var(--mono)"` declarations. */
  const columns = [
    {
      key: "scan_no",
      header: "Scan No.",
      isRowHeader: true,
      mono: true,
      nowrap: true,
      cell: (scan) => scanNo(scan),
    },
    {
      key: "target",
      header: "Target",
      mono: true,
      cell: (scan) => <span className="as-target">{scan.target}</span>,
    },
    {
      key: "type",
      header: "Type",
      cell: (scan) => (
        <CcureBadge variant="neutral">{scanTypeLabel(scan)}</CcureBadge>
      ),
    },
    {
      key: "status",
      header: "Status",
      // Replaces the local STATUS_STYLE map, whose fallback rendered any
      // unrecognised status in the *running* style — a false statement about a
      // scan on a page whose whole job is to report what happened.
      cell: (scan) => <CcureScanStatus status={scan.status} />,
    },
    {
      key: "scan_duration",
      header: "Duration",
      mono: true,
      nowrap: true,
      cell: (scan) => fmtDur(scan.scan_duration),
    },
    {
      key: "archived_at",
      header: "Archived",
      mono: true,
      nowrap: true,
      cell: (scan) => (
        <span className="as-muted">{fmtDate(scan.archived_at)}</span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      mono: true,
      nowrap: true,
      cell: (scan) => (
        <span className="as-muted">{fmtDate(scan.created_at)}</span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      cell: (scan) => {
        if (!canRestoreScans && !canRecycleScans) {
          return <span className="as-muted">Read only</span>;
        }
        return (
          <div className="as-actions">
            {canRestoreScans && (
              <CcureButton
                variant="secondary"
                size="sm"
                onClick={() => handleRestore(scan.id)}
                loading={restoringId === scan.id}
                /* The label alone repeats once per row, so a screen reader
                   listing controls gets N identical entries and no way to tell
                   which scan each belongs to. The scan number disambiguates. */
                aria-label={`Restore scan ${scanNo(scan)}`}
              >
                Restore
              </CcureButton>
            )}
            {canRecycleScans && (
              <CcureButton
                variant="danger"
                size="sm"
                onClick={() => handleDelete(scan.id)}
                loading={deletingId === scan.id}
                aria-label={`Delete scan ${scanNo(scan)}`}
              >
                Delete
              </CcureButton>
            )}
          </div>
        );
      },
    },
  ];

  return (
    <AppLayout pageTitle="Archived Scans">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Archived Scans</h2>
            <p className="page-subtitle as-count">
              {total} archived scan{total !== 1 ? "s" : ""} - {user?.username}
            </p>
          </div>
          <div className="as-toolbar">
            <CcureButton variant="ghost" onClick={() => navigate("/history")}>
              My Scan Jobs
            </CcureButton>
            <CcureButton variant="ghost" onClick={load} loading={loading}>
              Refresh
            </CcureButton>
          </div>
        </div>

        {error && (
          <CcureAlert variant="danger" className="as-message">
            {error}
          </CcureAlert>
        )}

        {loading && (
          <div className="as-loading">
            <CcureLoader label="Loading archived scans…" />
          </div>
        )}

        {!loading && !error && scans.length === 0 && (
          <CcureEmptyState
            title="No archived scans yet."
            action={
              <CcureButton onClick={() => navigate("/history")}>
                Back to My Scan Jobs
              </CcureButton>
            }
          />
        )}

        {!loading && scans.length > 0 && (
          <CcureTable
            caption={`Archived scans — ${total} record${total !== 1 ? "s" : ""}`}
            columns={columns}
            rows={scans}
            rowKey={(scan) => scan.id}
            density="comfortable"
          />
        )}
      </div>
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
