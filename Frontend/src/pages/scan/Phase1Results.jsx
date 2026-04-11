/**
 * src/pages/scan/Phase1Results.jsx
 * Shows all discovered hosts from POST /scan/phase1.
 * User checks active hosts → "Scan Ports" → navigates to /scan/phase2.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout    from "../../components/layout/AppLayout";
import ScanStepper  from "../../components/layout/ScanStepper";
import { useScan }  from "../../context/ScanContext";

export default function Phase1Results() {
  const navigate = useNavigate();
  const {
    target, scanId,
    phase1Hosts, phase1Summary,
    setPhase2Hosts,
    saveStatus,
  } = useScan();

  const [selected, setSelected] = useState(new Set());
  const [filter,   setFilter]   = useState("active"); // "active" | "all"

  const activeHosts  = phase1Hosts.filter(h => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : phase1Hosts;

  // Redirect if no data
  if (!phase1Hosts.length) {
    navigate("/scan", { replace: true });
    return null;
  }

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

  return (
    <AppLayout pageTitle="Discovery Results" saveStatus={saveStatus}>
      <ScanStepper current={1} />

      <div className="page-inner">

        {/* Page header */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Discovery Results</h2>
            <p className="page-subtitle">
              Target: <code className="ip-code">{target}</code>
              {scanId && <span className="muted"> · Scan #{scanId}</span>}
            </p>
          </div>
          <button className="btn btn--ghost" onClick={() => navigate("/scan")}>
            ← New Scan
          </button>
        </div>

        {/* Summary bar */}
        {phase1Summary && (
          <div className="summary-bar">
            <span className="summary-item"><b>{phase1Summary.total_hosts}</b> Total</span>
            <span className="summary-item summary-item--active"><b>{phase1Summary.active_hosts}</b> Active</span>
            <span className="summary-item"><b>{phase1Summary.inactive_hosts}</b> Inactive</span>
            <span className="summary-item"><b>{phase1Summary.scan_duration?.toFixed(1)}s</b> Duration</span>
            {selected.size > 0 && (
              <span className="summary-item summary-item--sel"><b>{selected.size}</b> selected</span>
            )}
          </div>
        )}

        {/* Filter + select-all row */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <div className="filter-tabs">
            {[
              ["active", `Active (${activeHosts.length})`],
              ["all",    `All (${phase1Hosts.length})`],
            ].map(([val, lbl]) => (
              <button
                key={val}
                className={`filter-tab ${filter === val ? "filter-tab--active" : ""}`}
                onClick={() => setFilter(val)}
              >
                {lbl}
              </button>
            ))}
          </div>

          {activeHosts.length > 0 && (
            <button
              className="filter-tab"
              onClick={toggleAll}
              style={{ marginLeft: "auto" }}
            >
              {selected.size === activeHosts.length ? "Deselect all" : "Select all active"}
            </button>
          )}
        </div>

        {/* Host table */}
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 36 }}>
                  <input
                    type="checkbox"
                    checked={selected.size === activeHosts.length && activeHosts.length > 0}
                    onChange={toggleAll}
                  />
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
                <tr
                  key={h.ip_address}
                  className={`tr-host ${!h.is_active ? "tr-inactive" : ""} ${selected.has(h.ip_address) ? "tr-selected" : ""}`}
                  onClick={() => h.is_active && toggle(h.ip_address)}
                >
                  <td onClick={e => e.stopPropagation()}>
                    {h.is_active && (
                      <input
                        type="checkbox"
                        checked={selected.has(h.ip_address)}
                        onChange={() => toggle(h.ip_address)}
                      />
                    )}
                  </td>
                  <td><code className="ip-code">{h.ip_address}</code></td>
                  <td>{h.hostname && h.hostname !== "Unknown" ? h.hostname : <span className="muted">—</span>}</td>
                  <td>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
                      {h.mac_address && h.mac_address !== "N/A" ? h.mac_address : <span className="muted">—</span>}
                    </span>
                  </td>
                  <td>
                    {h.vendor && h.vendor !== "N/A"
                      ? <span className="muted small">{h.vendor}</span>
                      : <span className="muted">—</span>}
                  </td>
                  <td>
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span className={`status-dot ${h.is_active ? "dot-active" : "dot-inactive"}`} />
                      <span style={{ fontSize: 13 }}>{h.status}</span>
                    </span>
                  </td>
                  <td><span className="method-chip">{h.scan_method}</span></td>
                  <td>
                    {h.os_guess && h.os_guess !== "Unknown"
                      ? <span style={{ fontSize: 13 }}>{h.os_guess}</span>
                      : <span className="muted">—</span>}
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
                      {h.confidence !== "N/A" ? h.confidence : <span className="muted">—</span>}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
                      {h.response_time_ms ? `${h.response_time_ms.toFixed(1)} ms` : <span className="muted">—</span>}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer action */}
        <div className="phase-footer">
          <p className="muted" style={{ fontSize: 13 }}>
            {selected.size === 0
              ? "Select active hosts above to run port scanning."
              : `${selected.size} host${selected.size > 1 ? "s" : ""} selected — ready for port scan.`}
          </p>
          <button
            className="btn btn--primary"
            onClick={proceed}
            disabled={selected.size === 0}
          >
            Scan Ports on Selected →
          </button>
        </div>

      </div>
    </AppLayout>
  );
}
