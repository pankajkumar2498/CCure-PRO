/**
 * src/pages/RecycleBin.jsx
 * Deleted scan records — restore, or destroy permanently.
 *
 * ── Contract, unchanged by the Checkpoint 3C migration ──────────────────────
 * Every handler, request, permission check, state transition and navigation
 * below is what it was before. The migration changed presentation only.
 * Specifically preserved:
 *
 *   * `getScans(0, 200, "deleted")` — the scope argument is load-bearing.
 *     `getScans` defaults to `scope="active"`, so losing it would list LIVE
 *     scans on a page whose second button purges them;
 *   * restore is gated on `scans:restore` and purge on `scans:purge`, at
 *     render *and* inside the handler, and they stay separate permissions —
 *     a user who may undo a deletion is not thereby a user who may make one
 *     permanent. The client gate is an affordance, not the authorisation
 *     boundary; the API enforces it;
 *   * purge requires an explicit confirmation naming the scan, and restore
 *     deliberately does not — it is the reversible direction;
 *   * a successful action drops the row locally and does not re-fetch; a
 *     failed one leaves the row in place;
 *   * the page does not poll.
 *
 * src/__tests__/pages/RecycleBin.test.jsx asserts all of this and was written
 * against the pre-migration page.
 *
 * ── What the migration changed ──────────────────────────────────────────────
 * The local `ConfirmDialog` defined in this file — a byte-identical twin of
 * the one in SecurityReports.jsx — is gone, replaced by `CcureConfirmDialog`.
 * It placed focus but never trapped it, never restored it, and described the
 * dialog to a screen reader by its title alone, omitting the "this is
 * irreversible" warning that is the whole content of a purge confirmation.
 *
 * The local `STATUS_STYLE`/`StatusBadge` are gone too. Their fallback,
 * `STATUS_STYLE[status] || STATUS_STYLE.running`, painted any status the map
 * did not carry — `queued` and `pending` among them — in the *running* style:
 * a false statement about a scan, on a page that reports what happened to it.
 */
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import { useAuth } from "@shell/auth/AuthContext";
import { getScans, purgeScan, restoreScan } from "../api/scans";
import { formatDateTime } from "../utils/date";
import { useToasts, ToastContainer } from "../components/common/Toast";
import { can, denyMessage } from "@shell/auth/permissions";
import { SCAN_PIPELINES } from "../config/scanConfig";
import {
  CcureAlert,
  CcureBadge,
  CcureButton,
  CcureConfirmDialog,
  CcureEmptyState,
  CcureLoader,
  CcureScanStatus,
  CcureTable,
} from "../design-system";
import "../styles/recycle-bin.css";

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
    setModal({ scanId: id, scanNo: scanNo(scan) });
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

  /* Columns are declared rather than hand-written as <tr>/<td>, so CcureTable
     owns the caption, `scope="col"` on every header and `scope="row"` on the
     identifying cell. `mono` replaces five separate inline
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
      cell: (scan) => <span className="rb-target">{scan.target}</span>,
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
      key: "deleted_at",
      header: "Deleted",
      mono: true,
      nowrap: true,
      cell: (scan) => (
        <span className="rb-muted">{fmtDate(scan.deleted_at)}</span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      mono: true,
      nowrap: true,
      cell: (scan) => (
        <span className="rb-muted">{fmtDate(scan.created_at)}</span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      cell: (scan) => {
        if (!canRestoreScans && !canPurgeScans) {
          return <span className="rb-muted">Read only</span>;
        }
        return (
          <div className="rb-actions">
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
            {canPurgeScans && (
              <CcureButton
                variant="danger"
                size="sm"
                onClick={() => handlePermanentDelete(scan.id)}
                loading={purgingId === scan.id}
                aria-label={`Delete scan ${scanNo(scan)} permanently`}
              >
                Delete Permanently
              </CcureButton>
            )}
          </div>
        );
      },
    },
  ];

  return (
    <AppLayout pageTitle="Recycle Bin">
      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Recycle Bin</h2>
            <p className="page-subtitle rb-count">
              {total} scan{total !== 1 ? "s" : ""} ready for permanent deletion
              - {user?.username}
            </p>
          </div>
          <div className="rb-toolbar">
            <CcureButton variant="ghost" onClick={() => navigate("/history")}>
              My Scan Jobs
            </CcureButton>
            <CcureButton variant="ghost" onClick={load} loading={loading}>
              Refresh
            </CcureButton>
          </div>
        </div>

        {error && (
          <CcureAlert variant="danger" className="rb-message">
            {error}
          </CcureAlert>
        )}

        {loading && (
          <div className="rb-loading">
            <CcureLoader label="Loading recycle bin…" />
          </div>
        )}

        {!loading && !error && scans.length === 0 && (
          <CcureEmptyState
            title="Recycle Bin is empty."
            action={
              <CcureButton onClick={() => navigate("/history")}>
                Back to Scan Jobs
              </CcureButton>
            }
          />
        )}

        {!loading && scans.length > 0 && (
          <CcureTable
            caption={`Recycle bin — ${total} scan${total !== 1 ? "s" : ""} awaiting permanent deletion`}
            columns={columns}
            rows={scans}
            rowKey={(scan) => scan.id}
            density="comfortable"
          />
        )}
      </div>

      <CcureConfirmDialog
        open={Boolean(modal)}
        title={`Permanently Delete Scan No. ${modal?.scanNo ?? ""}?`}
        subtitle="This action cannot be undone. The scan record will be completely removed from the system."
        warning="Once deleted, you cannot recover this scan or its associated data. This is irreversible."
        confirmLabel="Delete Permanently"
        tone="danger"
        busy={purgingId !== null}
        onConfirm={handleConfirmDelete}
        onCancel={() => setModal(null)}
      />
      <ToastContainer toasts={toasts} dismiss={dismissToast} />
    </AppLayout>
  );
}
