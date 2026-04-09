/**
 * src/pages/scan/Phase2Results.jsx  —  Page 3
 *
 * Runs port scan on selected hosts, shows results with risk indicators.
 * User selects hosts for deep audit → "Deep Audit" → /scan/phase3.
 */

import { useState } from "react";
import { useNavigate }   from "react-router-dom";
import AppShell          from "../../components/layout/AppShell";
import ScanStepper       from "../../components/layout/ScanStepper";

import { useScan }       from "../../context/ScanContext";
import api               from "../../api/axiosInstance";

const INTENSITIES = ["light", "normal", "deep"];
const RISK_COLOR  = {
  Critical:"#ff4d4d", High:"#f97316", Medium:"#f59e0b", Low:"#22c55e", Info:"#60a5fa",
};

export default function Phase2Results() {
  const navigate = useNavigate();
  const {
    phase2Hosts: hosts, scanId,
    setPhase2Hosts: setHosts,
    phase2Summary, setPhase2Summary,
    setPhase3Results: setP3,
    saveStatus, setSaveStatus,
    target,
  } = useScan();

  const [intensity,  setIntensity]  = useState("normal");
  const [loading,    setLoading]    = useState(false);
  const [results,    setResults]    = useState([]);
  const [summary,    setSummary]    = useState(null);
  const [selected,   setSelected]   = useState(new Set());
  const [expanded,   setExpanded]   = useState(new Set());
  const [error,      setError]      = useState("");
  const [hasScanned, setHasScanned] = useState(false);

  if (!hosts.length) { navigate("/scan/phase1", { replace: true }); return null; }

  const runScan = async () => {
    setLoading(true); setError(""); setResults([]); setSummary(null);
    setSelected(new Set()); setExpanded(new Set()); setHasScanned(false);
    setSaveStatus("saving");
    try {
      const { data } = await api.post("/scan/phase2", {
        hosts, intensity, scan_id: scanId,
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
    } finally {
      setLoading(false);
    }
  };

  const toggle      = ip => { const n = new Set(selected); n.has(ip) ? n.delete(ip) : n.add(ip); setSelected(n); };
  const toggleExpand= ip => { const n = new Set(expanded); n.has(ip) ? n.delete(ip) : n.add(ip); setExpanded(n); };

  const proceed = () => {
    setP3(results.filter(h => selected.has(h.ip_address)));
    navigate("/scan/phase3");
  };

  const activeResults = results.filter(h => h.is_active);

  return (
    <AppShell saveStatus={saveStatus}>
      <ScanStepper current={2} />

      <div className="page-content">
        <div className="page-header">
          <div>
            <h2 className="page-title">Port Scan</h2>
            <p className="page-sub">
              Scanning <b>{hosts.length}</b> host{hosts.length !== 1 ? "s" : ""} from{" "}
              <code className="ip">{target}</code>
            </p>
          </div>
          <div className="page-header-actions">
            {/* Intensity */}
            <div className="field" style={{ marginBottom:0 }}>
              <label>Intensity</label>
              <div className="filter-tabs">
                {INTENSITIES.map(i => (
                  <button key={i}
                    className={`filter-tab ${intensity === i ? "filter-tab--active" : ""}`}
                    onClick={() => setIntensity(i)} disabled={loading}>
                    {i}
                  </button>
                ))}
              </div>
            </div>
            <button className="phase-btn phase-btn--ghost"
              onClick={() => navigate("/scan/phase1")}>← Back</button>
            <button className="phase-btn" onClick={runScan} disabled={loading}>
              {loading ? <><span className="btn-spinner" /> Scanning…</> : "▶ Run Port Scan"}
            </button>
          </div>
        </div>

        {/* Target chips */}
        <div className="host-chip-row">
          {hosts.map(h => (
            <span key={h.ip_address} className="host-chip">
              <span className="user-dot" style={{width:6,height:6}} />
              {h.ip_address}
            </span>
          ))}
        </div>

        {loading && (
          <div className="scan-progress">
            <div className="progress-bar"><div className="progress-fill" /></div>
            <p className="muted" style={{marginTop:8,fontSize:13}}>
              Probing TCP services — this takes 5–30 seconds depending on intensity…
            </p>
          </div>
        )}

        {error && <div className="scan-error">⚠ {error}</div>}

        {summary && (
          <div className="summary-bar">
            <span className="sb-item"><b>{summary.total_hosts}</b> Hosts</span>
            <span className="sb-item sb-active"><b>{summary.hosts_with_ports}</b> Have open ports</span>
            <span className="sb-item"><b>{summary.scan_duration?.toFixed(1)}s</b> Duration</span>
            {selected.size > 0 && <span className="sb-item sb-sel"><b>{selected.size}</b> Selected</span>}
          </div>
        )}

        {/* ── Host cards ── */}
        {hasScanned && activeResults.length === 0 && (
          <div className="empty-card">No active hosts returned open ports.</div>
        )}

        {activeResults.map(h => {
          const portCount   = h.open_ports?.length || 0;
          const critPorts   = h.open_ports?.filter(p => p.risk === "Critical").length || 0;
          const isExpanded  = expanded.has(h.ip_address);
          const isSelected  = selected.has(h.ip_address);

          return (
            <div key={h.ip_address}
              className={`host-card ${isSelected ? "host-card--selected" : ""}`}>

              {/* Card header */}
              <div className="hc-header" onClick={() => toggle(h.ip_address)}>
                <input type="checkbox" checked={isSelected}
                  onChange={() => toggle(h.ip_address)}
                  onClick={e => e.stopPropagation()} />

                <div className="hc-title" style={{flex:1}}>
                  <code className="ip">{h.ip_address}</code>
                  {h.hostname !== "Unknown" && <span className="muted small"> {h.hostname}</span>}
                </div>

                {/* Risk summary chips */}
                <div className="hc-meta">
                  {portCount > 0
                    ? <span className="port-count">{portCount} port{portCount !== 1 ? "s" : ""}</span>
                    : <span className="muted small">No open ports</span>}
                  {critPorts > 0 && (
                    <span style={{fontFamily:"var(--mono)",fontSize:11,color:"#ff4d4d",
                      background:"rgba(255,77,77,.1)",border:"1px solid rgba(255,77,77,.25)",
                      borderRadius:3,padding:"2px 7px"}}>
                      {critPorts} Critical
                    </span>
                  )}
                  {h.os_guess && h.os_guess !== "Unknown" && (
                    <span className="os-chip">{h.os_guess}</span>
                  )}
                </div>

                <button className="expand-btn"
                  onClick={e => { e.stopPropagation(); toggleExpand(h.ip_address); }}>
                  {isExpanded ? "▲" : "▼"}
                </button>
              </div>

              {/* Port table */}
              {isExpanded && (
                <div className="ports-wrap">
                  {h.open_ports?.length > 0 ? (
                    <table className="ports-table">
                      <thead>
                        <tr><th>Port</th><th>Service</th><th>Banner / Version</th><th>Risk</th><th>CVEs</th></tr>
                      </thead>
                      <tbody>
                        {h.open_ports.map((p, i) => (
                          <tr key={i}>
                            <td><code className="ip">{p.port}/tcp</code></td>
                            <td><span className="svc-chip">{p.service}</span></td>
                            <td className="banner">{p.banner || p.version || <span className="muted">—</span>}</td>
                            <td>
                              <span style={{color:RISK_COLOR[p.risk]||"#60a5fa",
                                fontFamily:"var(--mono)",fontSize:11,fontWeight:600}}>
                                {p.risk || "Info"}
                              </span>
                            </td>
                            <td>
                              {p.cves?.length > 0
                                ? <span style={{color:"#f97316",fontFamily:"var(--mono)",fontSize:11}}>
                                    {p.cves.length} CVE{p.cves.length > 1 ? "s" : ""}
                                  </span>
                                : <span className="muted">—</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="empty-ports">No open ports detected on this host.</div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {/* Footer */}
        {hasScanned && (
          <div className="phase-footer">
            <p className="muted" style={{fontSize:13}}>
              {selected.size === 0
                ? "Select hosts above to run a deep vulnerability audit."
                : `${selected.size} host${selected.size > 1 ? "s" : ""} selected for deep audit.`}
            </p>
            <button className="phase-btn phase-btn--next"
              onClick={proceed} disabled={selected.size === 0}>
              Deep Vulnerability Audit →
            </button>
          </div>
        )}
      </div>
    </AppShell>
  );
}
