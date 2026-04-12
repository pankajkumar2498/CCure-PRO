/**
 * src/pages/scan/Phase1Results.jsx  [FIXED]
 *
 * ROOT-CAUSE FIXES:
 *  1. Render-time navigate() removed → replaced with useEffect guard.
 *     Calling navigate() during render triggers React's
 *     "Cannot update a component while rendering a different component"
 *     error, causing layout instability and potential infinite re-renders.
 *  2. Guard `if (!phase1Hosts.length) return null` is kept as a pure
 *     render guard only — no side-effects inside the conditional.
 */
import { useState, useEffect } from "react";
import { useNavigate }         from "react-router-dom";
import AppLayout               from "../../components/layout/AppLayout";
import ScanStepper             from "../../components/layout/ScanStepper";
import ExportPanel             from "../../components/scan/ExportPanel";
import { useScan }             from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";

export default function Phase1Results() {
  const navigate = useNavigate();
  const {
    target, scanId,
    phase1Hosts, phase1Summary,
    pipelineMode,
    saveStatus,
  } = useScan();

  const [filter, setFilter] = useState("active");

  // ── FIX 1: redirect in useEffect, never during render ──────────────────
  useEffect(() => {
    if (!phase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [phase1Hosts.length, navigate]);

  // Pure render guard — no navigate() call here
  if (!phase1Hosts.length) return null;

  const activeHosts  = phase1Hosts.filter(h => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : phase1Hosts;

  // ── Pipeline logic ──────────────────────────────────────────────────────
  const canProceedToPhase2 = isPhaseEnabled(pipelineMode, 2);
  const nextPhase          = getNextPhase(pipelineMode, 1);

  const proceedToNextPhase = () => {
    if (!canProceedToPhase2) return;
    navigate(nextPhase.route);
  };

  return (
    <AppLayout pageTitle="Discovery Results" saveStatus={saveStatus}>
      <ScanStepper current={1} />

      <div className="page-inner">

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

        {phase1Summary && (
          <div className="summary-bar">
            <span className="summary-item"><b>{phase1Summary.total_hosts}</b> Total</span>
            <span className="summary-item summary-item--active"><b>{phase1Summary.active_hosts}</b> Active</span>
            <span className="summary-item"><b>{phase1Summary.inactive_hosts}</b> Inactive</span>
            <span className="summary-item"><b>{phase1Summary.scan_duration?.toFixed(1)}s</b> Duration</span>
          </div>
        )}

        {!canProceedToPhase2 && (
          <div className="alert alert--info" style={{ marginBottom: 16 }}>
            ℹ Basic Network Scan complete. Host Discovery is the final phase for this scan type.
          </div>
        )}

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
        </div>

        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Status</th>
                <th>Method</th>
                <th>Response</th>
                <th>MAC</th>
                <th>Vendor</th>
              </tr>
            </thead>
            <tbody>
              {displayHosts.map(h => (
                <tr
                  key={h.ip_address}
                  className={h.is_active ? "row--active" : "row--inactive"}
                >
                  <td><code className="ip-code">{h.ip_address}</code></td>
                  <td>{h.hostname || <span className="muted">—</span>}</td>
                  <td>
                    <span className={`status-dot ${h.is_active ? "status-dot--up" : "status-dot--down"}`} />
                    {h.is_active ? "Active" : "Inactive"}
                  </td>
                  <td>{h.discovery_method || <span className="muted">—</span>}</td>
                  <td>{h.response_time_ms != null ? `${h.response_time_ms.toFixed(1)} ms` : <span className="muted">—</span>}</td>
                  <td>{h.mac_address || <span className="muted">—</span>}</td>
                  <td>{h.vendor || <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {phase1Summary && (
          <>
            {!canProceedToPhase2 && (
              <div className="alert alert--success" style={{ marginBottom: 16 }}>
                ✓ Scan completed. Export report available below.
              </div>
            )}
            <ExportPanel
              results={phase1Hosts}
              summary={phase1Summary}
              scanId={scanId}
              target={target}
              pipelineMode={pipelineMode}
            />
          </>
        )}

        {canProceedToPhase2 && (
          <div className="phase-action-bar">
            <p className="muted" style={{ fontSize: "0.85rem" }}>
              Continue to Port Scan to choose hosts and intensity on the same page.
            </p>
            <button
              className="btn btn--primary"
              onClick={proceedToNextPhase}
            >
              Continue to Port Scan
            </button>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
