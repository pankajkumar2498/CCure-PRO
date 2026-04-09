/**
 * src/components/scan/PhaseOne.jsx
 * Target input → POST /scan/phase1 → host table with checkboxes.
 * Returns scanId (from DB) via onComplete(selectedHosts, scanId).
 */
import { useState } from "react";
import api from "../../api/axiosInstance";

const SCAN_TYPES = ["adaptive", "ping", "arp", "tcp", "full", "stealth"];

export default function PhaseOne({ onComplete, onSaving }) {
  const [target, setTarget]     = useState("");
  const [scanType, setScanType] = useState("adaptive");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");
  const [hosts, setHosts]       = useState([]);
  const [summary, setSummary]   = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [scanId, setScanId]     = useState(null);

  const runScan = async () => {
    if (!target.trim()) return;
    setLoading(true); setError(""); setHosts([]); setSummary(null);
    setSelected(new Set()); setScanId(null);
    onSaving?.();
    try {
      const { data } = await api.post("/scan/phase1", {
        targets: target.split(",").map(t => t.trim()).filter(Boolean),
        scan_type: scanType,
      });
      if (!data.success) throw new Error(data.error || "Scan failed");
      setHosts(data.data);
      setSummary(data.summary);
      setScanId(data.scan_id ?? null);   // ← DB id returned by backend
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  const activeHosts = hosts.filter(h => h.is_active);

  const toggleAll = () =>
    selected.size === activeHosts.length
      ? setSelected(new Set())
      : setSelected(new Set(activeHosts.map(h => h.ip_address)));

  const toggle = (ip) => {
    const next = new Set(selected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setSelected(next);
  };

  const proceed = () => {
    const picked = hosts.filter(h => selected.has(h.ip_address));
    onComplete(picked, scanId);   // ← pass scanId up to Dashboard
  };

  return (
    <div className="phase-panel">
      <div className="phase-controls">
        <div className="field" style={{ flex: 1 }}>
          <label>Target (IP, range, or CIDR)</label>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="192.168.1.0/24  or  10.0.0.1-50  or  192.168.1.10"
            onKeyDown={e => e.key === "Enter" && runScan()}
          />
        </div>
        <div className="field" style={{ width: 160 }}>
          <label>Scan Type</label>
          <select value={scanType} onChange={e => setScanType(e.target.value)}>
            {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <button className="phase-btn" onClick={runScan} disabled={loading || !target.trim()}>
          {loading ? <span className="btn-spinner" /> : "▶ Discover"}
        </button>
      </div>

      {error && <div className="scan-error">⚠ {error}</div>}

      {summary && (
        <div className="summary-bar">
          <span className="sb-item"><b>{summary.total_hosts}</b> Total</span>
          <span className="sb-item sb-active"><b>{summary.active_hosts}</b> Active</span>
          <span className="sb-item sb-inactive"><b>{summary.inactive_hosts}</b> Inactive</span>
          <span className="sb-item"><b>{summary.scan_duration?.toFixed(1)}s</b> Duration</span>
          {scanId && <span className="sb-item" style={{color:"var(--accent)"}}>
            <b>Scan #{scanId}</b> saved
          </span>}
          {selected.size > 0 && (
            <span className="sb-item sb-sel"><b>{selected.size}</b> Selected</span>
          )}
        </div>
      )}

      {hosts.length > 0 && (
        <>
          <div className="table-wrap">
            <table className="scan-table">
              <thead>
                <tr>
                  <th style={{ width: 36 }}>
                    <input type="checkbox"
                      checked={selected.size === activeHosts.length && activeHosts.length > 0}
                      onChange={toggleAll} title="Select all active" />
                  </th>
                  <th>IP Address</th>
                  <th>Hostname</th>
                  <th>MAC / Vendor</th>
                  <th>Status</th>
                  <th>Method</th>
                  <th>OS Guess</th>
                  <th>Confidence</th>
                  <th>RTT</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map(h => (
                  <tr key={h.ip_address}
                    className={`tr-host ${!h.is_active ? "tr-inactive" : ""} ${selected.has(h.ip_address) ? "tr-selected" : ""}`}
                    onClick={() => h.is_active && toggle(h.ip_address)}>
                    <td onClick={e => e.stopPropagation()}>
                      {h.is_active && (
                        <input type="checkbox"
                          checked={selected.has(h.ip_address)}
                          onChange={() => toggle(h.ip_address)} />
                      )}
                    </td>
                    <td><code className="ip">{h.ip_address}</code></td>
                    <td>{h.hostname !== "Unknown" ? h.hostname : <span className="muted">—</span>}</td>
                    <td>
                      <div>{h.mac_address !== "N/A" ? h.mac_address : <span className="muted">—</span>}</div>
                      {h.vendor && h.vendor !== "N/A" && <div className="muted small">{h.vendor}</div>}
                    </td>
                    <td>
                      <span className={`status-dot ${h.is_active ? "dot-active" : "dot-inactive"}`} />
                      {h.status}
                    </td>
                    <td><span className="method-chip">{h.scan_method}</span></td>
                    <td>{h.os_guess !== "Unknown" ? h.os_guess : <span className="muted">—</span>}</td>
                    <td>{h.confidence !== "N/A" ? h.confidence : <span className="muted">—</span>}</td>
                    <td>{h.response_time_ms ? `${h.response_time_ms.toFixed(1)} ms` : <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {selected.size > 0 && (
            <div className="phase-footer">
              <span className="muted">{selected.size} host{selected.size > 1 ? "s" : ""} selected for Phase 2</span>
              <button className="phase-btn phase-btn--next" onClick={proceed}>
                Port Scan Selected →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
