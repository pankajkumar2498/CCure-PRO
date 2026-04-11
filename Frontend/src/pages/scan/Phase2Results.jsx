/**
 * src/pages/scan/Phase2Results.jsx  [FIXED]
 *
 * ROOT-CAUSE FIXES:
 *  1. Render-time navigate() removed → replaced with useEffect guard.
 *  2. catch block now clears saveStatus after a delay (was permanently
 *     stuck on "error" — no setTimeout present in original code).
 */
import { useState, useEffect } from "react";
import { useNavigate }         from "react-router-dom";
import AppLayout               from "../../components/layout/AppLayout";
import ScanStepper             from "../../components/layout/ScanStepper";
import { useScan }             from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";
import api                     from "../../api/axiosInstance";

const INTENSITIES = ["light", "normal", "deep"];

const RISK_COLOR = {
  Critical: "#ff4d4d",
  High:     "#f97316",
  Medium:   "#f59e0b",
  Low:      "#22c55e",
  Info:     "#60a5fa",
};

export default function Phase2Results() {
  const navigate = useNavigate();
  const {
    phase2Hosts: hosts, scanId, target,
    setPhase2Hosts: setHosts,
    setPhase2Summary,
    setPhase3Results: setP3,
    pipelineMode,
    saveStatus, setSaveStatus,
  } = useScan();

  const [intensity,  setIntensity]  = useState("normal");
  const [loading,    setLoading]    = useState(false);
  const [results,    setResults]    = useState([]);
  const [summary,    setSummary]    = useState(null);
  const [selected,   setSelected]   = useState(new Set());
  const [expanded,   setExpanded]   = useState(new Set());
  const [error,      setError]      = useState("");
  const [hasScanned, setHasScanned] = useState(false);

  // ── FIX 1: redirect in useEffect, never during render ──────────────────
  useEffect(() => {
    if (!hosts.length) {
      navigate("/scan/host-discovery", { replace: true });
    }
  }, [hosts.length, navigate]);

  // Pure render guard
  if (!hosts.length) return null;

  // ── Pipeline logic ──────────────────────────────────────────────────────
  const canProceedToPhase3 = isPhaseEnabled(pipelineMode, 3);
  const nextPhase          = getNextPhase(pipelineMode, 2);

  const runScan = async () => {
    setLoading(true);
    setError(""); setResults([]); setSummary(null);
    setSelected(new Set()); setExpanded(new Set());
    setHasScanned(false);
    setSaveStatus("saving");
    try {
      const { data } = await api.post("/scan/asset-discovery", {
        hosts,
        intensity,
        scan_id:       scanId,
        pipeline_mode: pipelineMode,
      });
      if (!data.success) throw new Error(data.error || "Phase 2 failed");
      setResults(data.data);
      setSummary(data.summary);
      setPhase2Summary(data.summary);
      setHasScanned(true);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Phase 2 failed");
      setSaveStatus("error");
      // ── FIX 2: clear error save-status after delay (was missing) ──────
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setLoading(false);
    }
  };

  const toggle       = ip => { const n = new Set(selected); n.has(ip) ? n.delete(ip) : n.add(ip); setSelected(n); };
  const toggleExpand = ip => { const n = new Set(expanded); n.has(ip) ? n.delete(ip) : n.add(ip); setExpanded(n); };

  const proceedToNextPhase = () => {
    if (!canProceedToPhase3 || !nextPhase) return;
    setP3(results.filter(h => selected.has(h.ip_address)));
    navigate(nextPhase.route);
  };

  const activeResults = results.filter(h => h.is_active);

  return (
    <AppLayout pageTitle="Port Scan" saveStatus={saveStatus}>
      <ScanStepper current={2} />

      <div className="page-inner">

        <div className="page-title-row">
          <div>
            <h2 className="page-title">Port Scan</h2>
            <p className="page-subtitle">
              Scanning <b>{hosts.length}</b> host{hosts.length !== 1 ? "s" : ""} from{" "}
              <code className="ip-code">{target}</code>
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)" }}>Intensity</span>
              <div className="filter-tabs">
                {INTENSITIES.map(i => (
                  <button
                    key={i}
                    className={`filter-tab ${intensity === i ? "filter-tab--active" : ""}`}
                    onClick={() => setIntensity(i)}
                    disabled={loading}
                  >
                    {i}
                  </button>
                ))}
              </div>
            </div>
            <button className="btn btn--ghost" onClick={() => navigate("/scan/host-discovery")}>← Back</button>
            <button className="btn btn--primary" onClick={runScan} disabled={loading}>
              {loading ? <><span className="btn-spinner" /> Scanning…</> : "▶ Run Port Scan"}
            </button>
          </div>
        </div>

        <div className="host-chip-row">
          {hosts.map(h => (
            <span key={h.ip_address} className="host-chip">
              <span className="status-dot dot-active" style={{ width: 6, height: 6 }} />
              {h.ip_address}
            </span>
          ))}
        </div>

        {loading && (
          <div className="progress-wrap">
            <div className="progress-bar"><div className="progress-fill" /></div>
            <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>
              Probing TCP services — takes 5–30 seconds depending on intensity…
            </p>
          </div>
        )}

        {error && <div className="alert alert--error">⚠ {error}</div>}

        {summary && (
          <div className="summary-bar">
            <span className="summary-item"><b>{summary.total_hosts}</b> Hosts</span>
            <span className="summary-item summary-item--active"><b>{summary.hosts_with_ports}</b> Have open ports</span>
            <span className="summary-item"><b>{summary.scan_duration?.toFixed(1)}s</b> Duration</span>
            {selected.size > 0 && <span className="summary-item summary-item--sel"><b>{selected.size}</b> Selected</span>}
          </div>
        )}

        {hasScanned && !canProceedToPhase3 && (
          <div className="alert alert--info" style={{ marginBottom: 16 }}>
            ℹ Asset Discovery complete. Port Scanning is the final phase for this scan type.
          </div>
        )}

        {hasScanned && activeResults.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon">🔍</span>
            <p className="empty-state-title">No active hosts returned open ports</p>
          </div>
        )}

        {activeResults.map(h => {
          const portCount  = h.open_ports?.length || 0;
          const critPorts  = h.open_ports?.filter(p => p.risk === "Critical").length || 0;
          const isExpanded = expanded.has(h.ip_address);
          const isSelected = selected.has(h.ip_address);

          return (
            <div
              key={h.ip_address}
              className={`host-card ${isSelected ? "host-card--selected" : ""}`}
            >
              <div className="host-card-header" onClick={() => toggle(h.ip_address)}>
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => toggle(h.ip_address)}
                  onClick={e => e.stopPropagation()}
                />

                <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <code className="ip-code" style={{ fontSize: "0.9rem", fontWeight: 700 }}>{h.ip_address}</code>
                  {h.hostname && h.hostname !== "Unknown" && (
                    <span className="muted small">{h.hostname}</span>
                  )}
                </div>

                <div className="host-card-meta">
                  {portCount > 0
                    ? <span style={{ fontFamily: "var(--mono)", fontSize: 12, background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 8px", borderRadius: 4 }}>
                        {portCount} port{portCount !== 1 ? "s" : ""}
                      </span>
                    : <span className="muted small">No open ports</span>}

                  {critPorts > 0 && (
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "#ff4d4d", background: "rgba(255,77,77,.1)", border: "1px solid rgba(255,77,77,.25)", borderRadius: 3, padding: "2px 7px" }}>
                      {critPorts} Critical
                    </span>
                  )}

                  {h.os_guess && h.os_guess !== "Unknown" && (
                    <span style={{ fontSize: 11, color: "var(--text-muted)", background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 8px", borderRadius: 4 }}>
                      {h.os_guess}
                    </span>
                  )}
                </div>

                <button
                  className="expand-btn"
                  onClick={e => { e.stopPropagation(); toggleExpand(h.ip_address); }}
                >
                  {isExpanded ? "▲" : "▼"}
                </button>
              </div>

              {isExpanded && (
                <div className="host-card-body">
                  {h.open_ports?.length > 0 ? (
                    <table className="ports-table">
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>Service</th>
                          <th>Banner / Version</th>
                          <th>Risk</th>
                          <th>CVEs</th>
                        </tr>
                      </thead>
                      <tbody>
                        {h.open_ports.map((p, i) => (
                          <tr key={i}>
                            <td><code className="ip-code">{p.port}/tcp</code></td>
                            <td>
                              <span style={{ background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 7px", borderRadius: 3, fontSize: 12, fontWeight: 600 }}>
                                {p.service}
                              </span>
                            </td>
                            <td style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>
                              {p.banner || p.version || <span className="muted">—</span>}
                            </td>
                            <td>
                              <span style={{ color: RISK_COLOR[p.risk] || "#60a5fa", fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700 }}>
                                {p.risk || "Info"}
                              </span>
                            </td>
                            <td>
                              {p.cves?.length > 0
                                ? <span style={{ color: "#f97316", fontFamily: "var(--mono)", fontSize: 11 }}>
                                    {p.cves.length} CVE{p.cves.length > 1 ? "s" : ""}
                                  </span>
                                : <span className="muted">—</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="muted" style={{ fontSize: 13, padding: "12px 0" }}>No open ports detected on this host.</p>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {hasScanned && canProceedToPhase3 && (
          <div className="phase-footer">
            <p className="muted" style={{ fontSize: 13 }}>
              {selected.size === 0
                ? "Select hosts above to run a deep vulnerability audit."
                : `${selected.size} host${selected.size > 1 ? "s" : ""} selected for deep audit.`}
            </p>
            <button className="btn btn--danger" onClick={proceedToNextPhase} disabled={selected.size === 0}>
              {nextPhase?.label ?? "Vulnerability Audit"} →
            </button>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
