/**
 * src/pages/ScanHistory.jsx
 * Lists all user scans with:
 *   • Status + date filters
 *   • View detail modal (phases / credentialed)
 *   • Re-run scan (loops back into wizard)
 *   • Delete scan
 * APIs: GET /scans, GET /scans/{id}, DELETE /scans/{id}, POST /scan/phase1 (re-run)
 */
import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout  from "../components/layout/AppLayout";
import RiskBadge  from "../components/scan/RiskBadge";
import { useAuth } from "../context/AuthContext";
import { useScan } from "../context/ScanContext";
import { getScans, getScan, deleteScan, archiveScan } from "../api/scans";
import api from "../api/axiosInstance";

/* ── constants ── */
const STATUS_STYLE = {
  complete: { color: "#22c55e", bg: "rgba(34,197,94,.1)",   border: "rgba(34,197,94,.25)"   },
  running:  { color: "#f59e0b", bg: "rgba(245,158,11,.1)",  border: "rgba(245,158,11,.25)"  },
  failed:   { color: "#ef4444", bg: "rgba(239,68,68,.1)",   border: "rgba(239,68,68,.25)"   },
};
const PHASE_LABELS = { 1: "Discovery", 2: "Port Scan", 3: "Vulnerability" };
const DATE_MS      = { "1h": 3.6e6, "24h": 8.64e7, "7d": 6.048e8, "30d": 2.592e9 };

const isCred    = scan => scan.scan_type === "credentialed";
const phaseLabel = scan =>
  isCred(scan) ? "Credentialed Audit" : `P${scan.phase} — ${PHASE_LABELS[scan.phase] || "-"}`;

const fmtDate = iso =>
  iso ? new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";

const getScanDisplayDate = scan =>
  scan.status === "complete" || scan.status === "failed" ? scan.updated_at || scan.created_at : scan.created_at;

const fmtDur = sec =>
  !sec ? "—" : sec < 60 ? `${sec.toFixed(1)}s` : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;

const normCve = cve => {
  const cvss = Number(cve.cvss_score ?? cve.cvss ?? 0) || 0;
  return {
    cve_id:      cve.cve_id || cve.cve || "Unknown",
    severity:    cve.severity || (cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : cvss > 0 ? "Low" : "Info"),
    description: cve.description || cve.desc || "",
  };
};

const getStoredTargets = scan => {
  if (Array.isArray(scan.targets) && scan.targets.length > 0) {
    return scan.targets;
  }

  return String(scan.target || "")
    .split(",")
    .map(x => x.trim())
    .filter(Boolean);
};

/* ── sub-components ── */
function StatusBadge({ status }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.running;
  return (
    <span style={{
      display: "inline-block", padding: "2px 9px", borderRadius: 4,
      background: s.bg, border: `1px solid ${s.border}`, color: s.color,
      fontSize: 11, fontFamily: "var(--mono)", letterSpacing: ".05em",
    }}>
      {status}
    </span>
  );
}

function DetailModal({ scanId, onClose }) {
  const [detail,  setDetail]  = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState("");

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
          <h2 className="modal-title">Scan #{scanId}</h2>
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

/* ── Main page ── */
export default function ScanHistory() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { setTarget, setScanType, setPhase1Hosts, setPhase1Summary, setScanId, resetScan } = useScan();

  const [scans,       setScans]       = useState([]);
  const [total,       setTotal]       = useState(0);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState("");
  const [viewId,      setViewId]      = useState(null);
  const [archivingId, setArchivingId] = useState(null);
  const [deletingId,  setDeletingId]  = useState(null);
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterDate,   setFilterDate]   = useState("all");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const { data } = await getScans(0, 200, "active");
      setScans(data.scans);
      setTotal(data.total);
    } catch {
      setError("Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleView = scan => {
    if (isCred(scan)) {
      navigate(`/scan/credentialed/results?scan_id=${scan.id}`);
      return;
    }
    setViewId(scan.id);
  };

  const handleDelete = async id => {
    if (!confirm(`Move Scan #${id} to Recycle Bin? You can permanently delete it later from Recycle Bin.`)) return;
    setDeletingId(id);
    try {
      await deleteScan(id);
      setScans(prev => prev.filter(s => s.id !== id));
      setTotal(prev => Math.max(prev - 1, 0));
    } catch {
      alert("Failed to move scan to Recycle Bin.");
    } finally {
      setDeletingId(null);
    }
  };

  const handleArchive = async id => {
    if (!confirm(`Archive Scan #${id}? You can restore it later from Archived Scans.`)) return;
    setArchivingId(id);
    try {
      await archiveScan(id);
      setScans(prev => prev.filter(s => s.id !== id));
      setTotal(prev => Math.max(prev - 1, 0));
    } catch {
      alert("Failed to archive scan.");
    } finally {
      setArchivingId(null);
    }
  };

  const handleRerun = async scan => {
    try {
      if (isCred(scan)) {
        resetScan();
        navigate("/scan/credentialed", { state: { prefill: { ip: scan.target } } });
        return;
      }

      const t  = scan.target;
      const st = scan.scan_type || "adaptive";
      const targets = getStoredTargets(scan);

      const { data } = await api.post("/scan/phase1", {
        targets,
        scan_type: st,
      });
      if (!data.success) throw new Error(data.error || "Re-run failed");

      resetScan();
      setTarget(t);
      setScanType(st);
      setPhase1Hosts(data.data);
      setPhase1Summary(data.summary);
      setScanId(data.scan_id ?? null);
      navigate("/scan/phase1");
    } catch (err) {
      alert("Re-run failed: " + (err.response?.data?.detail || err.message));
    }
  };

  const now     = Date.now();
  const visible = scans.filter(scan => {
    if (filterStatus !== "all" && scan.status !== filterStatus) return false;
    if (filterDate   !== "all" && now - new Date(getScanDisplayDate(scan)).getTime() > DATE_MS[filterDate]) return false;
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
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn--ghost" onClick={load} disabled={loading}>
              {loading ? <span className="btn-spinner btn-spinner--dark" /> : "Refresh"}
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="filter-bar">
          <div className="filter-group">
            <label>Status</label>
            <div className="filter-tabs">
              {["all", "complete", "running", "failed"].map(s => (
                <button
                  key={s}
                  className={`filter-tab ${filterStatus === s ? "filter-tab--active" : ""}`}
                  onClick={() => setFilterStatus(s)}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="filter-group">
            <label>Time range</label>
            <div className="filter-tabs">
              {[["all","All time"],["1h","1 hr"],["24h","24 hrs"],["7d","7 days"],["30d","30 days"]].map(([v,l]) => (
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
                  <th>#</th>
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

                  return (
                    <tr key={scan.id}>
                      <td>
                        <code className="ip-code" style={{ fontSize: 12 }}>#{scan.id}</code>
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
                          <button className="action-btn" onClick={() => handleView(scan)}>View</button>
                          <button className="action-btn action-btn--rerun" onClick={() => handleRerun(scan)}>
                            Re-run
                          </button>
                          <button
                            className="action-btn"
                            onClick={() => handleArchive(scan.id)}
                            disabled={archivingId === scan.id}
                          >
                            {archivingId === scan.id ? "..." : "Archive"}
                          </button>
                          <button
                            className="action-btn action-btn--danger"
                            onClick={() => handleDelete(scan.id)}
                            disabled={deletingId === scan.id}
                          >
                            {deletingId === scan.id ? "…" : "Delete"}
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

      {viewId && <DetailModal scanId={viewId} onClose={() => setViewId(null)} />}
    </AppLayout>
  );
}
