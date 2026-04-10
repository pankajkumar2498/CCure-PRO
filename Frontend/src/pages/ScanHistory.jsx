/**
 * src/pages/ScanHistory.jsx - Page 5
 *
 * All past scans with:
 *   - Filter by status / date
 *   - View detail modal (network scan phases)
 *   - Delete scan
 *   - Re-run scan
 */

import { useEffect, useState, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import AppShell from "../components/layout/AppShell";
import RiskBadge from "../components/scan/RiskBadge";
import { useAuth } from "../context/AuthContext";
import { useScan } from "../context/ScanContext";
import { getScans, getScan, deleteScan } from "../api/scans";
import api from "../api/axiosInstance";

const STATUS_COLORS = {
  complete: { color: "#22c55e", bg: "rgba(34,197,94,.1)", border: "rgba(34,197,94,.25)" },
  running:  { color: "#f59e0b", bg: "rgba(245,158,11,.1)", border: "rgba(245,158,11,.25)" },
  failed:   { color: "#ef4444", bg: "rgba(239,68,68,.1)", border: "rgba(239,68,68,.25)" },
};

const PHASE_LABELS = { 1: "Discovery", 2: "Port Scan", 3: "Vulnerability" };

const isCredentialedScan = (scan) => scan.scan_type === "credentialed";

const getHistoryPhaseLabel = (scan) =>
  isCredentialedScan(scan)
    ? "Credentialed Audit"
    : `P${scan.phase} - ${PHASE_LABELS[scan.phase] || "-"}`;

function StatusBadge({ status }) {
  const s = STATUS_COLORS[status] || STATUS_COLORS.running;
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

const fmtDate = (iso) =>
  iso
    ? new Date(iso).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "-";

const fmtDuration = (sec) => {
  if (!sec) return "-";
  return sec < 60 ? `${sec.toFixed(1)}s` : `${Math.floor(sec / 60)}m ${(sec % 60).toFixed(0)}s`;
};

const normalizeCve = (cve) => {
  const cvss = Number(cve.cvss_score ?? cve.cvss ?? 0) || 0;
  const severity = cve.severity || (
    cvss >= 9 ? "Critical" :
    cvss >= 7 ? "High" :
    cvss >= 4 ? "Medium" :
    cvss > 0 ? "Low" : "Info"
  );

  return {
    cve_id: cve.cve_id || cve.cve || "Unknown",
    severity,
    description: cve.description || cve.desc || "",
  };
};

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
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">Scan #{scanId}</h2>
          <button className="modal-close" onClick={onClose}>x</button>
        </div>

        {loading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 40 }}>
            <div className="spinner" />
          </div>
        )}
        {error && <div className="scan-error" style={{ margin: 20 }}>Warning: {error}</div>}

        {detail && (
          <div className="modal-body">
            <div className="detail-meta">
              <div className="dm-item"><span className="dm-label">Target</span><code className="ip">{detail.target}</code></div>
              <div className="dm-item"><span className="dm-label">Scan Type</span>{detail.scan_type}</div>
              <div className="dm-item"><span className="dm-label">Phase</span>{isCredentialedScan(detail) ? "Credentialed Audit" : (PHASE_LABELS[detail.phase] || detail.phase)}</div>
              <div className="dm-item"><span className="dm-label">Status</span><StatusBadge status={detail.status} /></div>
              <div className="dm-item"><span className="dm-label">Duration</span>{fmtDuration(detail.scan_duration)}</div>
              <div className="dm-item"><span className="dm-label">Created</span>{fmtDate(detail.created_at)}</div>
            </div>

            {detail.summary && Object.keys(detail.summary).length > 0 && (
              <div className="detail-section">
                <h4 className="section-title">Summary</h4>
                <div className="kv-grid">
                  {Object.entries(detail.summary).map(([k, v]) => (
                    <div key={k} className="kv-row">
                      <span className="kv-key">{k.replace(/_/g, " ")}</span>
                      <span className="kv-val">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {detail.results && Object.entries(detail.results).map(([pk, pd]) => {
              const hosts = (pd?.data || []).filter((h) => h.is_active);
              if (!hosts.length) return null;

              return (
                <div key={pk} className="detail-section">
                  <h4 className="section-title">
                    {PHASE_LABELS[pk.replace("phase", "")] || pk} Results
                    <span className="muted" style={{ marginLeft: 8, fontSize: 11 }}>
                      ({hosts.length} host{hosts.length !== 1 ? "s" : ""})
                    </span>
                  </h4>

                  {hosts.map((h) => (
                    <div key={h.ip_address} className="detail-host">
                      <div className="detail-host-header">
                        <code className="ip">{h.ip_address}</code>
                        {h.hostname && h.hostname !== "Unknown" && <span className="muted small"> {h.hostname}</span>}
                        {h.host_risk_level && <RiskBadge level={h.host_risk_level} score={h.host_risk_score} />}
                        {h.open_ports?.length > 0 && <span className="port-count">{h.open_ports.length} ports</span>}
                        {h.cves?.length > 0 && <span className="cve-count">{h.cves.length} CVEs</span>}
                      </div>

                      {h.open_ports?.length > 0 && (
                        <div className="mini-ports" style={{ marginTop: 8 }}>
                          {h.open_ports.map((p, i) => (
                            <span key={i} className="port-pill"><code>{p.port}</code> {p.service}</span>
                          ))}
                        </div>
                      )}

                      {h.cves?.length > 0 && (
                        <div className="cve-list" style={{ marginTop: 10 }}>
                          {h.cves.slice(0, 5).map((rawCve, i) => {
                            const cve = normalizeCve(rawCve);
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

export default function ScanHistory() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const {
    setTarget,
    setScanType,
    setPhase1Hosts,
    setPhase1Summary,
    setScanId,
    setSaveStatus,
    resetScan,
  } = useScan();

  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [viewId, setViewId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [rerunningId, setRerunningId] = useState(null);
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterDate, setFilterDate] = useState("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await getScans(0, 200);
      setScans(data.scans);
      setTotal(data.total);
    } catch {
      setError("Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleView = (scan) => {
    if (isCredentialedScan(scan)) {
      navigate(`/scan/credentialed/results?scan_id=${scan.id}`);
      return;
    }
    setViewId(scan.id);
  };

  const handleDelete = async (id) => {
    if (!confirm(`Delete Scan #${id}? This cannot be undone.`)) return;

    setDeletingId(id);
    try {
      await deleteScan(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
      setTotal((prev) => prev - 1);
    } catch {
      alert("Failed to delete scan.");
    } finally {
      setDeletingId(null);
    }
  };

  const handleRerun = async (scan) => {
    setRerunningId(scan.id);

    try {
      if (isCredentialedScan(scan)) {
        setSaveStatus("");
        navigate("/scan/credentialed", { state: { prefill: { ip: scan.target } } });
        return;
      }

      resetScan();
      const target = scan.target;
      const scanType = scan.scan_type || "adaptive";

      setTarget(target);
      setScanType(scanType);
      setSaveStatus("saving");

      const { data } = await api.post("/scan/phase1", {
        targets: target.split(",").map((t) => t.trim()).filter(Boolean),
        scan_type: scanType,
      });

      if (!data.success) {
        throw new Error(data.error || "Re-run failed");
      }

      setPhase1Hosts(data.data);
      setPhase1Summary(data.summary);
      setScanId(data.scan_id ?? null);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);
      navigate("/scan/phase1");
    } catch (err) {
      alert("Re-run failed: " + (err.response?.data?.detail || err.message));
      setSaveStatus("error");
    } finally {
      setRerunningId(null);
    }
  };

  const DATE_MS = { "1h": 3.6e6, "24h": 8.64e7, "7d": 6.048e8, "30d": 2.592e9 };
  const now = Date.now();
  const visible = scans.filter((scan) => {
    if (filterStatus !== "all" && scan.status !== filterStatus) return false;
    if (filterDate !== "all" && now - new Date(scan.created_at).getTime() > DATE_MS[filterDate]) return false;
    return true;
  });

  return (
    <AppShell>
      <div className="page-content">
        <div className="history-topbar">
          <div>
            <h2 className="history-title">Scan History</h2>
            <p className="muted" style={{ fontSize: 13, marginTop: 4, fontFamily: "var(--mono)" }}>
              {total} scan{total !== 1 ? "s" : ""} - {user?.username}
            </p>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <Link to="/scan" className="phase-btn" style={{ textDecoration: "none", display: "inline-flex" }}>
              New Scan
            </Link>
            <button className="phase-btn phase-btn--ghost" onClick={load} disabled={loading} style={{ height: 40 }}>
              {loading ? <span className="btn-spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> : "Refresh"}
            </button>
          </div>
        </div>

        <div className="history-filters">
          <div className="filter-group">
            <label>Status</label>
            <div className="filter-tabs">
              {["all", "complete", "running", "failed"].map((status) => (
                <button
                  key={status}
                  className={`filter-tab ${filterStatus === status ? "filter-tab--active" : ""}`}
                  onClick={() => setFilterStatus(status)}
                >
                  {status}
                </button>
              ))}
            </div>
          </div>

          <div className="filter-group">
            <label>Time range</label>
            <div className="filter-tabs">
              {[["all", "All time"], ["1h", "1 hr"], ["24h", "24 hrs"], ["7d", "7 days"], ["30d", "30 days"]].map(([value, label]) => (
                <button
                  key={value}
                  className={`filter-tab ${filterDate === value ? "filter-tab--active" : ""}`}
                  onClick={() => setFilterDate(value)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {error && <div className="scan-error">{error}</div>}

        {loading && (
          <div style={{ display: "flex", justifyContent: "center", padding: 60 }}>
            <div className="spinner" />
          </div>
        )}

        {!loading && !error && visible.length === 0 && (
          <div className="history-empty">
            <span className="empty-icon">*</span>
            <p>{filterStatus !== "all" || filterDate !== "all" ? "No scans match your filters." : "No scans yet."}</p>
            <Link to="/scan" className="phase-btn" style={{ display: "inline-flex", marginTop: 16, textDecoration: "none" }}>
              Start your first scan {"->"}
            </Link>
          </div>
        )}

        {!loading && visible.length > 0 && (
          <div className="table-wrap">
            <table className="scan-table history-table">
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
                {visible.map((scan) => {
                  const summary = scan.summary || {};
                  const isRerunning = rerunningId === scan.id;

                  return (
                    <tr key={scan.id} className="tr-host">
                      <td><code className="ip" style={{ fontSize: 12 }}>#{scan.id}</code></td>
                      <td><span className="history-target">{scan.target}</span></td>
                      <td><span className="method-chip">{scan.scan_type}</span></td>
                      <td><span className="phase-chip">{getHistoryPhaseLabel(scan)}</span></td>
                      <td><StatusBadge status={scan.status} /></td>
                      <td>
                        {summary.active_hosts !== undefined
                          ? <span style={{ color: "var(--ok)", fontFamily: "var(--mono)" }}>{summary.active_hosts}</span>
                          : <span className="muted">-</span>}
                      </td>
                      <td><span style={{ fontFamily: "var(--mono)", fontSize: 13 }}>{fmtDuration(scan.scan_duration)}</span></td>
                      <td><span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-muted)" }}>{fmtDate(scan.created_at)}</span></td>
                      <td>
                        <div className="action-btns">
                          <button className="action-btn" onClick={() => handleView(scan)}>View</button>
                          <button
                            className="action-btn action-btn--rerun"
                            onClick={() => handleRerun(scan)}
                            disabled={isRerunning || !!rerunningId}
                            title="Re-run this scan"
                          >
                            {isRerunning
                              ? <span className="btn-spinner" style={{ width: 11, height: 11, borderWidth: 2 }} />
                              : "Re-run"}
                          </button>
                          <button
                            className="action-btn action-btn--danger"
                            onClick={() => handleDelete(scan.id)}
                            disabled={deletingId === scan.id}
                            title="Delete scan"
                          >
                            {deletingId === scan.id ? "..." : "Delete"}
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
    </AppShell>
  );
}
