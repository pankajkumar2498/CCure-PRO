/**
 * src/components/scan/PhaseTwo.jsx
 * Receives hosts + scanId → POST /scan/phase2 → port cards.
 */
import { useState } from "react";
import api from "../../api/axiosInstance";

const RISK_COLOR = {
  Critical: "#ff4d4d", High: "#f97316",
  Medium: "#f59e0b", Low: "#22c55e", Info: "#60a5fa",
};
const INTENSITIES = ["light", "normal", "deep"];

export default function PhaseTwo({ hosts, scanId, onBack, onComplete, onSaving }) {
  const [intensity, setIntensity] = useState("normal");
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState("");
  const [results, setResults]     = useState([]);
  const [summary, setSummary]     = useState(null);
  const [selected, setSelected]   = useState(new Set());
  const [expanded, setExpanded]   = useState(new Set());

  const runScan = async () => {
    setLoading(true); setError(""); setResults([]); setSummary(null);
    setSelected(new Set()); setExpanded(new Set());
    onSaving?.();
    try {
      const { data } = await api.post("/scan/phase2", {
        hosts,
        intensity,
        scan_id: scanId,      // ← send scan_id so backend updates DB
      });
      if (!data.success) throw new Error(data.error || "Phase 2 failed");
      setResults(data.data);
      setSummary(data.summary);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Phase 2 failed");
    } finally {
      setLoading(false);
    }
  };

  const toggle = ip => {
    const next = new Set(selected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setSelected(next);
  };

  const toggleExpand = ip => {
    const next = new Set(expanded);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setExpanded(next);
  };

  const proceed = () => onComplete(results.filter(h => selected.has(h.ip_address)));

  return (
    <div className="phase-panel">
      <div className="phase-controls">
        <div className="info-pill">
          <span className="muted">Scanning</span>
          <b>{hosts.length}</b>
          <span className="muted">host{hosts.length !== 1 ? "s" : ""}</span>
          {hosts.map(h => (
            <code key={h.ip_address} className="ip ip--small">{h.ip_address}</code>
          ))}
        </div>
        <div className="field" style={{ width: 160 }}>
          <label>Intensity</label>
          <select value={intensity} onChange={e => setIntensity(e.target.value)}>
            {INTENSITIES.map(i => <option key={i} value={i}>{i}</option>)}
          </select>
        </div>
        <button className="phase-btn phase-btn--ghost" onClick={onBack}>← Back</button>
        <button className="phase-btn" onClick={runScan} disabled={loading}>
          {loading ? <span className="btn-spinner" /> : "▶ Port Scan"}
        </button>
      </div>

      {error && <div className="scan-error">⚠ {error}</div>}

      {summary && (
        <div className="summary-bar">
          <span className="sb-item"><b>{summary.total_hosts}</b> Hosts</span>
          <span className="sb-item sb-active"><b>{summary.hosts_with_ports}</b> Have open ports</span>
          <span className="sb-item"><b>{summary.scan_duration?.toFixed(1)}s</b> Duration</span>
          {scanId && <span className="sb-item" style={{color:"var(--accent)"}}>
            <b>Scan #{scanId}</b> updated
          </span>}
          {selected.size > 0 && (
            <span className="sb-item sb-sel"><b>{selected.size}</b> Selected</span>
          )}
        </div>
      )}

      {/* ── Results ── */}
      {results.length > 0 && (
        <>
          <div className="host-cards">
            {results.filter(h => h.is_active).map(h => (
              <div key={h.ip_address}
                className={`host-card ${selected.has(h.ip_address) ? "host-card--selected" : ""}`}>

                {/* Card header */}
                <div className="hc-header" onClick={() => toggle(h.ip_address)}>
                  <input type="checkbox" checked={selected.has(h.ip_address)}
                    onChange={() => toggle(h.ip_address)}
                    onClick={e => e.stopPropagation()} />
                  <div className="hc-title">
                    <code className="ip">{h.ip_address}</code>
                    {h.hostname !== "Unknown" && <span className="muted small"> {h.hostname}</span>}
                  </div>
                  <div className="hc-meta">
                    <span className="port-count">
                      {h.open_ports?.length || 0} port{h.open_ports?.length !== 1 ? "s" : ""} open
                    </span>
                    {h.os_guess && h.os_guess !== "Unknown" && (
                      <span className="os-chip">{h.os_guess}</span>
                    )}
                  </div>
                  <button className="expand-btn"
                    onClick={e => { e.stopPropagation(); toggleExpand(h.ip_address); }}>
                    {expanded.has(h.ip_address) ? "▲" : "▼"}
                  </button>
                </div>

                {/* Ports table */}
                {expanded.has(h.ip_address) && h.open_ports?.length > 0 && (
                  <div className="ports-wrap">
                    <table className="ports-table">
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>Service</th>
                          <th>Banner / Version</th>
                          <th>Risk</th>
                        </tr>
                      </thead>
                      <tbody>
                        {h.open_ports.map((p, i) => (
                          <tr key={i}>
                            <td><code className="ip">{p.port}/tcp</code></td>
                            <td><span className="svc-chip">{p.service}</span></td>
                            <td className="banner">{p.banner || p.version || <span className="muted">—</span>}</td>
                            <td>
                              <span style={{
                                color: RISK_COLOR[p.risk] || "#60a5fa",
                                fontFamily: "var(--mono)", fontSize: 11,
                              }}>
                                {p.risk || "Info"}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {expanded.has(h.ip_address) && !h.open_ports?.length && (
                  <div className="empty-ports">No open ports found</div>
                )}
              </div>
            ))}
          </div>

          {selected.size > 0 && (
            <div className="phase-footer">
              <span className="muted">{selected.size} host{selected.size > 1 ? "s" : ""} selected for deep audit</span>
              <button className="phase-btn phase-btn--next" onClick={proceed}>
                Deep Vulnerability Audit →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
