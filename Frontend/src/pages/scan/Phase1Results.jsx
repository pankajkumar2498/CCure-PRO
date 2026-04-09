/**
 * src/pages/scan/Phase1Results.jsx  —  Page 2
 *
 * Shows all discovered hosts. User checks active hosts → "Scan Ports".
 * Navigates to /scan/phase2 on proceed.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AppShell    from "../../components/layout/AppShell";
import ScanStepper from "../../components/layout/ScanStepper";
import { useScan } from "../../context/ScanContext";

export default function Phase1Results() {
  const navigate = useNavigate();
  const {
    target, scanId, phase1Hosts, phase1Summary,
    setPhase2Hosts, saveStatus,
  } = useScan();

  const [selected, setSelected] = useState(new Set());
  const [filter,   setFilter]   = useState("active"); // "all" | "active"

  const activeHosts  = phase1Hosts.filter(h => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : phase1Hosts;

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
    const picked = phase1Hosts.filter(h => selected.has(h.ip_address));
    setPhase2Hosts(picked);
    navigate("/scan/phase2");
  };

  if (!phase1Hosts.length) {
    navigate("/scan", { replace: true });
    return null;
  }

  return (
    <AppShell saveStatus={saveStatus}>
      <ScanStepper current={1} />

      <div className="page-content">
        {/* ── Page header ── */}
        <div className="page-header">
          <div>
            <h2 className="page-title">Discovery Results</h2>
            <p className="page-sub">
              Target: <code className="ip">{target}</code>
              {scanId && <span className="muted"> · Scan #{scanId}</span>}
            </p>
          </div>
          <div className="page-header-actions">
            <button className="phase-btn phase-btn--ghost"
              onClick={() => navigate("/scan")}>
              ← New Scan
            </button>
          </div>
        </div>

        {/* ── Summary strip ── */}
        {phase1Summary && (
          <div className="summary-bar">
            <span className="sb-item"><b>{phase1Summary.total_hosts}</b> Total</span>
            <span className="sb-item sb-active"><b>{phase1Summary.active_hosts}</b> Active</span>
            <span className="sb-item sb-inactive"><b>{phase1Summary.inactive_hosts}</b> Inactive</span>
            <span className="sb-item"><b>{phase1Summary.scan_duration?.toFixed(1)}s</b> Duration</span>
            {selected.size > 0 && (
              <span className="sb-item sb-sel"><b>{selected.size}</b> selected</span>
            )}
          </div>
        )}

        {/* ── Filter toggle ── */}
        <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:4 }}>
          <div className="filter-tabs">
            {["active","all"].map(f => (
              <button key={f}
                className={`filter-tab ${filter === f ? "filter-tab--active" : ""}`}
                onClick={() => setFilter(f)}>
                {f === "active" ? `Active (${activeHosts.length})` : `All (${phase1Hosts.length})`}
              </button>
            ))}
          </div>
          {activeHosts.length > 0 && (
            <button className="filter-tab" onClick={toggleAll}
              style={{ marginLeft:"auto" }}>
              {selected.size === activeHosts.length ? "Deselect all" : "Select all active"}
            </button>
          )}
        </div>

        {/* ── Host table ── */}
        <div className="table-wrap">
          <table className="scan-table">
            <thead>
              <tr>
                <th style={{ width:36 }}>
                  <input type="checkbox"
                    checked={selected.size === activeHosts.length && activeHosts.length > 0}
                    onChange={toggleAll} />
                </th>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC Address</th>
                <th>Vendor</th>
                <th>Status</th>
                <th>Method</th>
                <th>OS Guess</th>
                <th>Confidence</th>
                <th>RTT</th>
              </tr>
            </thead>
            <tbody>
              {displayHosts.map(h => (
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
                  <td><span style={{fontFamily:"var(--mono)",fontSize:12}}>{h.mac_address !== "N/A" ? h.mac_address : <span className="muted">—</span>}</span></td>
                  <td>{h.vendor && h.vendor !== "N/A" ? <span className="muted small">{h.vendor}</span> : <span className="muted">—</span>}</td>
                  <td>
                    <span className={`status-dot ${h.is_active ? "dot-active" : "dot-inactive"}`} />
                    {h.status}
                  </td>
                  <td><span className="method-chip">{h.scan_method}</span></td>
                  <td>{h.os_guess && h.os_guess !== "Unknown" ? h.os_guess : <span className="muted">—</span>}</td>
                  <td>{h.confidence !== "N/A" ? h.confidence : <span className="muted">—</span>}</td>
                  <td>{h.response_time_ms ? `${h.response_time_ms.toFixed(1)} ms` : <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ── Footer action ── */}
        <div className="phase-footer">
          <p className="muted" style={{fontSize:13}}>
            {selected.size === 0
              ? "Check hosts above to select them for port scanning."
              : `${selected.size} host${selected.size > 1 ? "s" : ""} selected — ready for port scan.`}
          </p>
          <button className="phase-btn phase-btn--next"
            onClick={proceed}
            disabled={selected.size === 0}>
            Scan Ports on Selected →
          </button>
        </div>
      </div>
    </AppShell>
  );
}
