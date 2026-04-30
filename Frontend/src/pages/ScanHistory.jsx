/**
 * src/pages/ScanHistory.jsx
 * Production-grade scan history with:
 *   • Custom confirm dialogs (Re-run / Archive / Delete) — no browser confirm/alert
 *   • Toast notifications for success / error feedback
 *   • Re-run shows scan details + live-network warning before executing
 *   • Archive confirms with scan context + restore hint
 *   • Delete shows danger dialog + recycle-bin explanation
 * APIs: GET /scans, GET /scans/{id}, DELETE /scans/{id}, POST /scan/host-discovery (re-run)
 */
import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import RiskBadge from "../components/scan/RiskBadge";
import { useAuth } from "../context/AuthContext";
import { useScan } from "../context/ScanContext";
import { getScans, getScan, deleteScan, archiveScan, streamScanEvents } from "../api/scans";
import { buildPhasePayload } from "../config/scanConfig";
import api from "../api/axiosInstance";
import { dateTimeMs, formatDateTime } from "../utils/date";

/* ── constants ── */
const STATUS_STYLE = {
  complete: { color: "#22c55e", bg: "rgba(34,197,94,.1)", border: "rgba(34,197,94,.25)" },
  completed: { color: "#22c55e", bg: "rgba(34,197,94,.1)", border: "rgba(34,197,94,.25)" },
  running: { color: "#f59e0b", bg: "rgba(245,158,11,.1)", border: "rgba(245,158,11,.25)" },
  failed: { color: "#ef4444", bg: "rgba(239,68,68,.1)", border: "rgba(239,68,68,.25)" },
  cancelled: { color: "#64748b", bg: "rgba(100,116,139,.1)", border: "rgba(100,116,139,.25)" },
  canceled: { color: "#64748b", bg: "rgba(100,116,139,.1)", border: "rgba(100,116,139,.25)" },
};
const STATUS_LABELS = {
  complete: "Completed",
  completed: "Completed",
  running: "Running",
  failed: "Failed",
  cancelled: "Cancelled",
  canceled: "Cancelled",
};
const TERMINAL_PHASES = { basic: 1, asset: 2, advanced: 3 };
const PHASE_LABELS = { 1: "Discovery", 2: "Port Scan", 3: "Vulnerability" };
const DATE_MS = { "1h": 3.6e6, "24h": 8.64e7, "7d": 6.048e8, "30d": 2.592e9 };
const LIVE_LABELS = {
  connecting: "Live sync connecting",
  connected: "Live sync active",
  reconnecting: "Live sync reconnecting",
  polling: "Live sync polling",
};

const normalizeStatus = status => {
  const raw = String(status || "running").toLowerCase();
  if (raw === "completed") return "complete";
  if (raw === "canceled") return "cancelled";
  return raw;
};

const isCred = scan => scan.scan_type === "credentialed";
const scanLabel = scan => `Scan No. ${scan?.scan_no ?? scan?.display_id ?? "-"}`;
const phaseLabel = scan =>
  isCred(scan) ? "Credentialed Audit" : `P${scan.phase} — ${PHASE_LABELS[scan.phase] || "-"}`;

const fmtDate = iso =>
  formatDateTime(iso, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

const getScanDisplayDate = scan =>
  ["complete", "failed", "cancelled"].includes(normalizeStatus(scan.status)) ? scan.updated_at || scan.created_at : scan.created_at;

const fmtDur = sec =>
  !sec ? "—" : sec < 60 ? `${sec.toFixed(1)}s` : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;

const normCve = cve => {
  const cvss = Number(cve.cvss_score ?? cve.cvss ?? 0) || 0;
  return {
    cve_id: cve.cve_id || cve.cve || "Unknown",
    severity: cve.severity || (cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : cvss > 0 ? "Low" : "Info"),
    description: cve.description || cve.desc || "",
  };
};

const getStoredTargets = scan => {
  if (Array.isArray(scan.targets) && scan.targets.length > 0) return scan.targets;
  return String(scan.target || "").split(",").map(x => x.trim()).filter(Boolean);
};

const getScanProgress = scan => {
  const fromApi = Number(scan.progress_percentage);
  if (Number.isFinite(fromApi)) return Math.max(0, Math.min(100, fromApi));

  const status = normalizeStatus(scan.status);
  if (status === "complete") return 100;

  const terminal = TERMINAL_PHASES[scan.pipeline_mode || "basic"] || 1;
  const phase = Math.max(0, Math.min(Number(scan.phase || 0), terminal));
  const percent = Math.round((phase / terminal) * 100);
  return status === "running" ? Math.max(8, Math.min(96, percent)) : Math.max(8, percent);
};

const isSameScan = (a, b) =>
  a &&
  b &&
  a.id === b.id &&
  a.scan_no === b.scan_no &&
  a.status === b.status &&
  a.phase === b.phase &&
  a.updated_at === b.updated_at &&
  a.scan_duration === b.scan_duration &&
  a.progress_percentage === b.progress_percentage &&
  JSON.stringify(a.summary || {}) === JSON.stringify(b.summary || {});

const mergeScanSnapshot = (current, incoming) => {
  const byId = new Map(current.map(scan => [scan.id, scan]));
  return incoming.map(scan => {
    const previous = byId.get(scan.id);
    return isSameScan(previous, scan) ? previous : { ...previous, ...scan };
  });
};

/* ══════════════════════════════════════════════════════════════════════════
   TOAST SYSTEM
   ══════════════════════════════════════════════════════════════════════════ */
let _toastId = 0;
function useToasts() {
  const [toasts, setToasts] = useState([]);

  const push = useCallback((msg, type = "info", duration = 4000) => {
    const id = ++_toastId;
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => {
      setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 220);
    }, duration);
  }, []);

  const dismiss = useCallback(id => {
    setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 220);
  }, []);

  return { toasts, push, dismiss };
}

const TOAST_ICONS = { success: "✓", error: "✕", info: "ℹ" };

function ToastContainer({ toasts, dismiss }) {
  if (!toasts.length) return null;
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`toast toast--${t.type}${t.exiting ? " toast--exit" : ""}`}
          onClick={() => dismiss(t.id)}
          style={{ cursor: "pointer" }}
        >
          <span className="toast-icon">{TOAST_ICONS[t.type]}</span>
          <span className="toast-msg">{t.msg}</span>
        </div>
      ))}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   CONFIRM DIALOG COMPONENT
   ══════════════════════════════════════════════════════════════════════════ */
function ConfirmDialog({ config, onConfirm, onCancel }) {
  const { type, title, subtitle, meta, warning, confirmLabel, confirmClass, icon, iconClass } = config;
  const [busy, setBusy] = useState(false);
  const btnRef = useRef(null);

  // Focus confirm button on mount
  useEffect(() => { btnRef.current?.focus(); }, []);

  // ESC to cancel
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
        {/* Header */}
        <div className="confirm-dialog-header">
          <div className={`confirm-dialog-icon confirm-dialog-icon--${iconClass}`}>
            {icon}
          </div>
          <div className="confirm-dialog-titles">
            <div className="confirm-dialog-title" id="cdlg-title">{title}</div>
            <div className="confirm-dialog-subtitle">{subtitle}</div>
          </div>
        </div>

        {/* Scan meta */}
        {meta && meta.length > 0 && (
          <div className="confirm-dialog-meta">
            {meta.map(([label, value]) => (
              <div className="confirm-meta-row" key={label}>
                <span className="confirm-meta-label">{label}</span>
                <span className="confirm-meta-value">{value}</span>
              </div>
            ))}
          </div>
        )}

        {/* Warning banner */}
        {warning && (
          <div className={`confirm-dialog-warning${type === "delete" ? " confirm-dialog-warning--danger" : ""}`}>
            <span style={{ flexShrink: 0 }}>{type === "delete" ? "⚠️" : "ℹ️"}</span>
            <span>{warning}</span>
          </div>
        )}

        {/* Footer */}
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

/* ══════════════════════════════════════════════════════════════════════════
   DETAIL MODAL (View button)
   ══════════════════════════════════════════════════════════════════════════ */
function DetailModal({ scanId, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getScan(scanId)
      .then(({ data }) => setDetail(data))
      .catch(() => setError("Failed to load scan details."))
      .finally(() => setLoading(false));
  }, [scanId]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">{detail ? scanLabel(detail) : "Scan Details"}</h2>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        {loading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
            <div className="spinner" />
          </div>
        )}
        {error && <div className="alert alert--error" style={{ margin: 20 }}>{error}</div>}

        {detail && (
          <div className="modal-body">
            {/* Meta grid */}
            <div className="detail-meta">
              <div className="dm-item">
                <span className="dm-label">Target</span>
                <code className="ip-code">{detail.target}</code>
              </div>
              <div className="dm-item">
                <span className="dm-label">Scan Type</span>
                <span>{detail.scan_type}</span>
              </div>
              <div className="dm-item">
                <span className="dm-label">Phase</span>
                <span>{isCred(detail) ? "Credentialed" : (PHASE_LABELS[detail.phase] || detail.phase)}</span>
              </div>
              <div className="dm-item">
                <span className="dm-label">Status</span>
                <StatusBadge status={detail.status} />
              </div>
              <div className="dm-item">
                <span className="dm-label">Duration</span>
                <span style={{ fontFamily: "var(--mono)" }}>{fmtDur(detail.scan_duration)}</span>
              </div>
              <div className="dm-item">
                <span className="dm-label">Completed</span>
                <span>{fmtDate(getScanDisplayDate(detail))}</span>
              </div>
            </div>

            {/* Summary */}
            {detail.summary && Object.keys(detail.summary).length > 0 && (
              <div className="detail-section">
                <h4 className="section-title" style={{ marginBottom: 8 }}>Summary</h4>
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {Object.entries(detail.summary).map(([k, v]) => (
                    <div key={k} style={{ display: "flex", gap: 12, padding: "5px 0", borderBottom: "1px solid #f1f5f9" }}>
                      <span style={{ fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", minWidth: 160 }}>
                        {k.replace(/_/g, " ")}
                      </span>
                      <span style={{ fontFamily: "var(--mono)", fontSize: "0.8rem" }}>{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Phase results */}
            {detail.results && Object.entries(detail.results).map(([pk, pd]) => {
              const hosts = (pd?.data || []).filter(h => h.is_active);
              if (!hosts.length) return null;
              return (
                <div key={pk} className="detail-section">
                  <h4 className="section-title" style={{ marginBottom: 8 }}>
                    {PHASE_LABELS[pk.replace("phase", "")] || pk} Results
                    <span className="muted" style={{ marginLeft: 8, fontSize: 11 }}>
                      ({hosts.length} host{hosts.length !== 1 ? "s" : ""})
                    </span>
                  </h4>
                  {hosts.map(h => (
                    <div key={h.ip_address} className="detail-host">
                      <div className="detail-host-header">
                        <code className="ip-code">{h.ip_address}</code>
                        {h.hostname && h.hostname !== "Unknown" && (
                          <span className="muted small"> {h.hostname}</span>
                        )}
                        {h.host_risk_level && <RiskBadge level={h.host_risk_level} score={h.host_risk_score} />}
                        {h.open_ports?.length > 0 && (
                          <span style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 7px", borderRadius: 3 }}>
                            {h.open_ports.length} ports
                          </span>
                        )}
                        {h.cves?.length > 0 && (
                          <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "#f97316" }}>
                            {h.cves.length} CVEs
                          </span>
                        )}
                      </div>
                      {h.open_ports?.length > 0 && (
                        <div className="port-pills" style={{ marginTop: 8 }}>
                          {h.open_ports.map((p, i) => (
                            <span key={i} className="port-pill">
                              <code>{p.port}</code> {p.service}
                            </span>
                          ))}
                        </div>
                      )}
                      {h.cves?.length > 0 && (
                        <div className="cve-list" style={{ marginTop: 10 }}>
                          {h.cves.slice(0, 5).map((rawCve, i) => {
                            const cve = normCve(rawCve);
                            return (
                              <div key={i} className="cve-row">
                                <span className="cve-id">{cve.cve_id}</span>
                                <span className="cve-sev">{cve.severity}</span>
                                <span className="cve-desc">{cve.description}</span>
                              </div>
                            );
                          })}
                          {h.cves.length > 5 && (
                            <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                              +{h.cves.length - 5} more
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

/* ── sub-components ── */
function StatusBadge({ status }) {
  const normalized = normalizeStatus(status);
  const s = STATUS_STYLE[normalized] || STATUS_STYLE.running;
  return (
    <span style={{
      display: "inline-block", padding: "2px 9px", borderRadius: 4,
      background: s.bg, border: `1px solid ${s.border}`, color: s.color,
      fontSize: 11, fontFamily: "var(--mono)", letterSpacing: ".05em",
    }}>
      {STATUS_LABELS[normalized] || status}
    </span>
  );
}

function ScanProgress({ scan }) {
  const progress = getScanProgress(scan);
  const status = normalizeStatus(scan.status);

  return (
    <div className="history-progress" aria-label={`Scan progress ${Math.round(progress)}%`}>
      <div className="history-progress-track">
        <div
          className={`history-progress-fill history-progress-fill--${status}`}
          style={{ width: `${progress}%` }}
        />
      </div>
      <span className="history-progress-text">{Math.round(progress)}%</span>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   MAIN PAGE
   ══════════════════════════════════════════════════════════════════════════ */
export default function ScanHistory() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { setTarget, setScanType, setPipelineMode, setPhase1Hosts, setPhase1Summary, setScanId, setScanNo, resetScan } = useScan();
  const { toasts, push: pushToast, dismiss: dismissToast } = useToasts();

  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [liveState, setLiveState] = useState("connecting");
  const [lastLiveAt, setLastLiveAt] = useState(null);
  const [error, setError] = useState("");
  const [viewId, setViewId] = useState(null);
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterDate, setFilterDate] = useState("all");

  // Confirm dialog state
  const [dialog, setDialog] = useState(null); // { type, scan, config }

  const applySnapshot = useCallback((data) => {
    if (!Array.isArray(data?.scans)) return;
    setScans(prev => mergeScanSnapshot(prev, data.scans));
    setTotal(Number.isFinite(Number(data.total)) ? Number(data.total) : data.scans.length);
    setLastLiveAt(new Date());
    setError("");
  }, []);

  const load = useCallback(async ({ initial = false, quiet = false } = {}) => {
    if (initial) setLoading(true);
    if (!quiet) {
      setRefreshing(!initial);
      setError("");
    }
    try {
      const { data } = await getScans(0, 200, "active");
      applySnapshot(data);
    } catch {
      if (!quiet) setError("Failed to load scan history.");
    } finally {
      if (initial) setLoading(false);
      if (!quiet) setRefreshing(false);
    }
  }, [applySnapshot]);

  useEffect(() => { load({ initial: true }); }, [load]);

  useEffect(() => {
    let stopped = false;
    const controller = new AbortController();
    const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

    const runPollingFallback = async () => {
      setLiveState("polling");
      while (!stopped) {
        await load({ quiet: true });
        await wait(5000);
      }
    };

    const connect = async () => {
      let failures = 0;
      while (!stopped) {
        try {
          setLiveState(failures ? "reconnecting" : "connecting");
          await streamScanEvents({
            scope: "active",
            limit: 200,
            interval: 2,
            signal: controller.signal,
            onEvent: ({ event, data }) => {
              if (stopped) return;
              if (event === "connected") setLiveState("connected");
              if (event === "heartbeat") setLastLiveAt(new Date());
              if (event === "scans") {
                applySnapshot(data);
                setLiveState("connected");
              }
            },
          });

          if (!stopped) throw new Error("Scan history stream closed.");
        } catch {
          if (stopped || controller.signal.aborted) return;
          failures += 1;
          setLiveState("reconnecting");
          if (failures >= 2) {
            await runPollingFallback();
            return;
          }
          await wait(2500);
        }
      }
    };

    connect();
    return () => {
      stopped = true;
      controller.abort();
    };
  }, [applySnapshot, load]);

  const handleView = scan => {
    if (isCred(scan)) {
      navigate(`/scan/credentialed/results?scan_id=${scan.id}`);
      return;
    }
    setViewId(scan.id);
  };

  /* ── Dialog openers ── */
  const openRerunDialog = scan => {
    setDialog({
      type: "rerun",
      scan,
      config: {
        type: "rerun",
        icon: "🔁",
        iconClass: "info",
        title: `Re-run ${scanLabel(scan)}?`,
        subtitle: "This will start a fresh scan against the same target using the same configuration.",
        meta: [
          ["Target", scan.target],
          ["Type", scan.scan_type],
          ["Phase", phaseLabel(scan)],
          ["Last run", fmtDate(getScanDisplayDate(scan))],
        ],
        warning: "This action will send live network packets to the target. Only proceed if you have authorisation to scan this host.",
        confirmLabel: "Re-run Scan",
        confirmClass: "rerun",
      },
    });
  };



  /* ── Dialog confirm handlers ── */
  const handleConfirmRerun = async () => {
    const scan = dialog.scan;
    try {
      // Handle credentialed scans separately
      if (isCred(scan)) {
        resetScan();
        setDialog(null);
        navigate("/scan/credentialed", { state: { prefill: { ip: scan.target } } });
        return;
      }

      // Extract scan parameters
      const target = scan.target;
      const scanType = scan.scan_type || "adaptive";
      const pipelineMode = scan.pipeline_mode || "basic";
      const targets = getStoredTargets(scan);

      // Reset context FIRST
      resetScan();

      // Set up context for the new scan session with the ORIGINAL configuration
      setTarget(target);
      setScanType(scanType);
      setPipelineMode(pipelineMode);

      // Build payload with correct phases based on pipeline mode
      const payload = buildPhasePayload(pipelineMode, {
        targets,
        scan_type: scanType,
      });

      // Execute the scan with the same pipeline as the original
      const { data } = await api.post("/scan/host-discovery", payload);
      if (!data.success) throw new Error(data.error || "Re-run failed");

      // Store results
      setPhase1Hosts(data.data);
      setPhase1Summary(data.summary);
      setScanId(data.scan_id ?? null);
      setScanNo(data.scan_no ?? data.display_id ?? null);

      setDialog(null);

      // Navigate based on pipeline mode (same as when initially creating the scan)
      if (pipelineMode === "advanced") {
        navigate("/scan/advanced-scan");
      } else {
        navigate("/scan/host-discovery");
      }

      pushToast(`Re-running scan with ${pipelineMode} mode (${payload.phases.length} phase${payload.phases.length !== 1 ? "s" : ""})`, "success");
    } catch (err) {
      setDialog(null);
      pushToast("Re-run failed: " + (err.response?.data?.detail || err.message), "error");
    }
  };

  const handleConfirmArchive = async (dialogObj) => {
    const scan = dialogObj?.scan || dialog?.scan;
    if (!scan) return;
    try {
      await archiveScan(scan.id);
      setScans(prev => prev.filter(s => s.id !== scan.id));
      setTotal(prev => Math.max(prev - 1, 0));
      setDialog(null);
      pushToast(`${scanLabel(scan)} archived. You can restore it from Archived Scans.`, "success");
    } catch {
      setDialog(null);
      pushToast("Failed to archive scan. Please try again.", "error");
    }
  };

  const handleConfirmDelete = async (dialogObj) => {
    const scan = dialogObj?.scan || dialog?.scan;
    if (!scan) return;
    try {
      await deleteScan(scan.id);
      setScans(prev => prev.filter(s => s.id !== scan.id));
      setTotal(prev => Math.max(prev - 1, 0));
      setDialog(null);
      pushToast(`${scanLabel(scan)} moved to Recycle Bin.`, "info");
    } catch {
      setDialog(null);
      pushToast("Failed to delete scan. Please try again.", "error");
    }
  };

  const handleDialogConfirm = () => {
    if (!dialog) return;
    if (dialog.type === "rerun") return handleConfirmRerun();
  };

  /* ── Filtering ── */
  const now = Date.now();
  const visible = scans.filter(scan => {
    if (filterStatus !== "all" && normalizeStatus(scan.status) !== filterStatus) return false;
    if (filterDate !== "all" && now - dateTimeMs(getScanDisplayDate(scan)) > DATE_MS[filterDate]) return false;
    return true;
  });

  return (
    <AppLayout pageTitle="Scan History">
      <div className="page-inner">

        {/* Page header */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Scan History</h2>
            <p className="page-subtitle" style={{ fontFamily: "var(--mono)" }}>
              {total} scan{total !== 1 ? "s" : ""} · {user?.username}
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", justifyContent: "flex-end" }}>
            <div className={`history-live history-live--${liveState}`} title={lastLiveAt ? `Last update ${lastLiveAt.toLocaleTimeString()}` : ""}>
              <span className="history-live-dot" />
              <span>{LIVE_LABELS[liveState]}</span>
            </div>
            <button className="btn btn--ghost" onClick={() => load()} disabled={refreshing}>
              {refreshing ? <span className="btn-spinner btn-spinner--dark" /> : "Sync now"}
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="filter-bar">
          <div className="filter-group">
            <label>Status</label>
            <div className="filter-tabs">
              {["all", "complete", "running", "failed", "cancelled"].map(s => (
                <button
                  key={s}
                  className={`filter-tab ${filterStatus === s ? "filter-tab--active" : ""}`}
                  onClick={() => setFilterStatus(s)}
                >
                  {s === "all" ? "All" : STATUS_LABELS[s]}
                </button>
              ))}
            </div>
          </div>
          <div className="filter-group">
            <label>Time range</label>
            <div className="filter-tabs">
              {[["all", "All time"], ["1h", "1 hr"], ["24h", "24 hrs"], ["7d", "7 days"], ["30d", "30 days"]].map(([v, l]) => (
                <button
                  key={v}
                  className={`filter-tab ${filterDate === v ? "filter-tab--active" : ""}`}
                  onClick={() => setFilterDate(v)}
                >
                  {l}
                </button>
              ))}
            </div>
          </div>
        </div>

        {error && <div className="alert alert--error">{error}</div>}

        {loading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
            <div className="spinner" />
          </div>
        )}

        {!loading && !error && visible.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon">📋</span>
            <p className="empty-state-title">
              {filterStatus !== "all" || filterDate !== "all" ? "No scans match your filters." : "No scans yet."}
            </p>
            <button className="btn btn--primary" style={{ marginTop: 16 }} onClick={() => navigate("/scan")}>
              Start your first scan →
            </button>
          </div>
        )}

        {!loading && visible.length > 0 && (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scan No.</th>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Phase</th>
                  <th>Status</th>
                  <th>Active Hosts</th>
                  <th>Duration</th>
                  <th>Date</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.map(scan => {
                  const summary = scan.summary || {};
                  const isRunning = normalizeStatus(scan.status) === "running";

                  return (
                    <tr key={scan.id}>
                      <td>
                        <code className="ip-code" style={{ fontSize: 12 }}>{scan.scan_no ?? scan.display_id ?? "-"}</code>
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
                      <td>
                        <div className="history-status-cell">
                          <StatusBadge status={scan.status} />
                          <ScanProgress scan={scan} />
                        </div>
                      </td>
                      <td>
                        {summary.active_hosts !== undefined
                          ? <span style={{ color: "var(--ok)", fontFamily: "var(--mono)", fontWeight: 700 }}>{summary.active_hosts}</span>
                          : <span className="muted">—</span>}
                      </td>
                      <td>
                        <span style={{ fontFamily: "var(--mono)", fontSize: 13 }}>{fmtDur(scan.scan_duration)}</span>
                      </td>
                      <td>
                        <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-muted)" }}>
                          {fmtDate(getScanDisplayDate(scan))}
                        </span>
                      </td>
                      <td>
                        <div className="action-btns">
                          {/* View */}
                          <button
                            className="action-btn"
                            onClick={() => handleView(scan)}
                            title="View scan details"
                          >
                            View
                          </button>

                          {/* Re-run — disabled for running scans */}
                          <button
                            className="action-btn action-btn--rerun"
                            onClick={() => openRerunDialog(scan)}
                            disabled={isRunning}
                            title={isRunning ? "Scan is already running" : "Re-run this scan against the same target"}
                          >
                            Re-run
                          </button>

                          {/* Archive — disabled for running scans */}
                          <button
                            className="action-btn"
                            onClick={() => handleConfirmArchive({ scan })}
                            disabled={isRunning}
                            title={isRunning ? "Cannot archive a running scan" : "Move to archived scans"}
                          >
                            Archive
                          </button>

                          {/* Delete */}
                          <button
                            className="action-btn action-btn--danger"
                            onClick={() => handleConfirmDelete({ scan })}
                            title="Move to Recycle Bin"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {visible.length > 0 && visible.length < total && (
          <p className="muted" style={{ textAlign: "center", marginTop: 16, fontSize: 13, fontFamily: "var(--mono)" }}>
            Showing {visible.length} of {total} scans
          </p>
        )}

      </div>

      {/* Detail modal */}
      {viewId && <DetailModal scanId={viewId} onClose={() => setViewId(null)} />}

      {/* Confirm dialog */}
      {dialog && (
        <ConfirmDialog
          config={dialog.config}
          onConfirm={handleDialogConfirm}
          onCancel={() => setDialog(null)}
        />
      )}

      {/* Toast notifications */}
      <ToastContainer toasts={toasts} dismiss={dismissToast} />

    </AppLayout>
  );
}
