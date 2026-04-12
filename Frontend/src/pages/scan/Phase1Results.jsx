/**
 * src/pages/scan/Phase1Results.jsx
 *
 * Asset Discovery mode is now handled inline on the Phase 1 page.
 * Basic Network Scan export remains unchanged and still appears after Phase 1.
 */
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import ScanStepper from "../../components/layout/ScanStepper";
import ExportPanel from "../../components/scan/ExportPanel";
import { useScan } from "../../context/ScanContext";
import api from "../../api/axiosInstance";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";

const INTENSITIES = ["light", "normal", "deep"];

export default function Phase1Results() {
  const navigate = useNavigate();
  const {
    target, scanId,
    phase1Hosts, phase1Summary,
    pipelineMode,
    saveStatus,
    setPhase2Hosts,
    setPhase2Summary,
    setPhase2Results,
  } = useScan();

  const [filter, setFilter] = useState("active");
  const [assetFilter, setAssetFilter] = useState("active");
  const [assetIntensity, setAssetIntensity] = useState("normal");
  const [assetSelected, setAssetSelected] = useState(new Set());
  const [assetLoading, setAssetLoading] = useState(false);
  const [assetResults, setAssetResults] = useState([]);
  const [assetSummary, setAssetSummary] = useState(null);
  const [assetExpanded, setAssetExpanded] = useState(new Set());
  const [assetError, setAssetError] = useState("");
  const [assetHasScanned, setAssetHasScanned] = useState(false);

  useEffect(() => {
    if (!phase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [phase1Hosts.length, navigate]);

  if (!phase1Hosts.length) return null;

  const isAssetPipeline = pipelineMode === "asset";
  const activeHosts = phase1Hosts.filter(h => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : phase1Hosts;
  const assetHosts = assetFilter === "active" ? activeHosts : phase1Hosts;
  const selectedHosts = phase1Hosts.filter(h => assetSelected.has(h.ip_address) && h.is_active);
  const selectedCount = selectedHosts.length;

  const canProceedToPhase2 = isPhaseEnabled(pipelineMode, 2);
  const nextPhase = getNextPhase(pipelineMode, 1);

  useEffect(() => {
    if (isAssetPipeline) {
      setAssetSelected(new Set(activeHosts.map(h => h.ip_address)));
    }
  }, [isAssetPipeline, activeHosts.length]);

  const toggleAssetHost = (ip) => {
    const next = new Set(assetSelected);
    if (next.has(ip)) {
      next.delete(ip);
    } else {
      next.add(ip);
    }
    setAssetSelected(next);
  };

  const toggleAssetAll = () => {
    const next = selectedCount === activeHosts.length
      ? new Set()
      : new Set(activeHosts.map(h => h.ip_address));
    setAssetSelected(next);
  };

  const runAssetDiscovery = async () => {
    if (!selectedCount) return;

    const payloadHosts = phase1Hosts.filter(h => assetSelected.has(h.ip_address));
    setPhase2Hosts(payloadHosts);

    setAssetLoading(true);
    setAssetError("");
    setAssetResults([]);
    setAssetSummary(null);
    setAssetExpanded(new Set());
    setAssetHasScanned(false);

    try {
      const { data: result } = await api.post("/scan/asset-discovery", {
        hosts: payloadHosts,
        intensity: assetIntensity,
        scan_id: scanId,
        pipeline_mode: pipelineMode,
        phases: [1, 2],
      });

      if (!result.success) {
        throw new Error(result.error || "Phase 2 failed");
      }

      setAssetResults(result.data);
      setAssetSummary(result.summary);
      setPhase2Summary(result.summary);
      setPhase2Results(result.data);
      setAssetHasScanned(true);
    } catch (err) {
      setAssetError(err.response?.data?.detail || err.message || "Phase 2 failed");
    } finally {
      setAssetLoading(false);
    }
  };

  const toggleAssetExpand = (ip) => {
    const next = new Set(assetExpanded);
    if (next.has(ip)) {
      next.delete(ip);
    } else {
      next.add(ip);
    }
    setAssetExpanded(next);
  };

  const canShowAssetExport = assetHasScanned && assetSummary && assetResults.length > 0;

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
          <button className="btn btn--ghost" onClick={() => navigate("/dashboard")}>
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

        {isAssetPipeline ? (
          <div className="phase-action-bar" style={{ flexWrap: "wrap", gap: 12, marginBottom: 16 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 240 }}>
              <span className="muted" style={{ fontSize: 13 }}>Select active hosts to include in Port Scan.</span>
              <div className="filter-tabs">
                {[["active", `Active (${activeHosts.length})`], ["all", `All (${phase1Hosts.length})`]].map(([val, lbl]) => (
                  <button
                    key={val}
                    className={`filter-tab ${assetFilter === val ? "filter-tab--active" : ""}`}
                    onClick={() => setAssetFilter(val)}
                    disabled={assetLoading}
                  >
                    {lbl}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 240 }}>
              <span className="muted" style={{ fontSize: 13 }}>Scan intensity</span>
              <div className="filter-tabs">
                {INTENSITIES.map(level => (
                  <button
                    key={level}
                    className={`filter-tab ${assetIntensity === level ? "filter-tab--active" : ""}`}
                    onClick={() => setAssetIntensity(level)}
                    disabled={assetLoading}
                  >
                    {level}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-end" }}>
              <button
                className="btn btn--ghost btn--sm"
                onClick={toggleAssetAll}
                disabled={assetLoading || !activeHosts.length}
              >
                {selectedCount === activeHosts.length ? "Deselect all" : "Select all active"}
              </button>
              <button
                className="btn btn--primary"
                onClick={runAssetDiscovery}
                disabled={assetLoading || selectedCount === 0}
                style={{ minWidth: 170 }}
              >
                {assetLoading ? <><span className="btn-spinner" /> Scanning…</> : "▶ Run Port Scan"}
              </button>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
            <div className="filter-tabs">
              {[["active", `Active (${activeHosts.length})`], ["all", `All (${phase1Hosts.length})`]].map(([val, lbl]) => (
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
        )}

        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                {isAssetPipeline && <th style={{ width: 36 }} />}
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
              {(isAssetPipeline ? assetHosts : displayHosts).map(h => (
                <tr
                  key={h.ip_address}
                  className={h.is_active ? "row--active" : "row--inactive"}
                  style={{ cursor: isAssetPipeline && h.is_active ? "pointer" : "default" }}
                >
                  {isAssetPipeline && (
                    <td>
                      {h.is_active && (
                        <input
                          type="checkbox"
                          checked={assetSelected.has(h.ip_address)}
                          onChange={() => toggleAssetHost(h.ip_address)}
                          onClick={e => e.stopPropagation()}
                        />
                      )}
                    </td>
                  )}
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

        {/* Basic Network Scan: completion message + export AFTER host table */}
        {phase1Summary && !canProceedToPhase2 && (
          <>
            <div className="alert alert--success" style={{ marginTop: 20, marginBottom: 8 }}>
              ✓ Scan completed. Export report available below.
            </div>
            <ExportPanel
              results={phase1Hosts}
              summary={phase1Summary}
              scanId={scanId}
              target={target}
              pipelineMode={pipelineMode}
            />
          </>
        )}

        {assetError && <div className="alert alert--error">⚠ {assetError}</div>}

        {assetHasScanned && assetSummary && (
          <div className="summary-bar" style={{ marginTop: 16 }}>
            <span className="summary-item"><b>{assetSummary.total_hosts}</b> Hosts scanned</span>
            <span className="summary-item summary-item--active"><b>{assetSummary.hosts_with_ports}</b> Have open ports</span>
            <span className="summary-item"><b>{assetSummary.scan_duration?.toFixed(1)}s</b> Duration</span>
            <span className="summary-item summary-item--sel"><b>{selectedCount}</b> selected</span>
          </div>
        )}

        {assetLoading && (
          <div className="progress-wrap">
            <div className="progress-bar"><div className="progress-fill" /></div>
            <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>
              Probing TCP services — takes 5–30 seconds depending on intensity…
            </p>
          </div>
        )}

        {assetHasScanned && assetResults.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon">🔍</span>
            <p className="empty-state-title">No active hosts returned open ports</p>
          </div>
        )}

        {assetHasScanned && assetResults.map(host => {
          const portCount = host.open_ports?.length || 0;
          const critPorts = host.open_ports?.filter(p => p.risk === "Critical").length || 0;
          const isSelected = assetSelected.has(host.ip_address);
          const isExpanded = assetExpanded.has(host.ip_address);
          return (
            <div key={host.ip_address} className={`host-card ${isSelected ? "host-card--selected" : ""}`}>
              <div className="host-card-header" onClick={() => toggleAssetHost(host.ip_address)}>
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => toggleAssetHost(host.ip_address)}
                  onClick={e => e.stopPropagation()}
                />

                <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <code className="ip-code" style={{ fontSize: "0.9rem", fontWeight: 700 }}>{host.ip_address}</code>
                  {host.hostname && host.hostname !== "Unknown" && (
                    <span className="muted small">{host.hostname}</span>
                  )}
                </div>

                <div className="host-card-meta">
                  {portCount > 0 ? (
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12, background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 8px", borderRadius: 4 }}>
                      {portCount} port{portCount !== 1 ? "s" : ""}
                    </span>
                  ) : (
                    <span className="muted small">No open ports</span>
                  )}

                  {critPorts > 0 && (
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "#ff4d4d", background: "rgba(255,77,77,.1)", border: "1px solid rgba(255,77,77,.25)", borderRadius: 3, padding: "2px 7px" }}>
                      {critPorts} Critical
                    </span>
                  )}

                  {host.os_guess && host.os_guess !== "Unknown" && (
                    <span style={{ fontSize: 11, color: "var(--text-muted)", background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 8px", borderRadius: 4 }}>
                      {host.os_guess}
                    </span>
                  )}
                </div>

                <button
                  className="expand-btn"
                  onClick={e => { e.stopPropagation(); toggleAssetExpand(host.ip_address); }}
                >
                  {isExpanded ? "▲" : "▼"}
                </button>
              </div>

              {isExpanded && (
                <div className="host-card-body">
                  {host.open_ports?.length > 0 ? (
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
                        {host.open_ports.map((port, index) => (
                          <tr key={index}>
                            <td><code className="ip-code">{port.port}/tcp</code></td>
                            <td>
                              <span style={{ background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 7px", borderRadius: 3, fontSize: 12, fontWeight: 600 }}>
                                {port.service}
                              </span>
                            </td>
                            <td style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>
                              {port.banner || port.version || <span className="muted">—</span>}
                            </td>
                            <td>
                              <span style={{ color: port.risk === "Critical" ? "#ff4d4d" : port.risk === "High" ? "#f97316" : port.risk === "Medium" ? "#f59e0b" : port.risk === "Low" ? "#22c55e" : "#60a5fa", fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700 }}>
                                {port.risk || "Info"}
                              </span>
                            </td>
                            <td>
                              {port.cves?.length > 0 ? (
                                <span style={{ color: "#f97316", fontFamily: "var(--mono)", fontSize: 11 }}>
                                  {port.cves.length} CVE{port.cves.length > 1 ? "s" : ""}
                                </span>
                              ) : (
                                <span className="muted">—</span>
                              )}
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

        {canShowAssetExport && (
          <ExportPanel
            results={assetResults}
            summary={assetSummary}
            scanId={scanId}
            target={target}
          />
        )}

        {canProceedToPhase2 && !isAssetPipeline && (
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
