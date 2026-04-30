/**
 * src/pages/scan/Phase1Results.jsx
 *
 * Asset Discovery mode is now handled inline on the Phase 1 page.
 * Basic Network Scan export remains unchanged and still appears after Phase 1.
 *
 * STATE MACHINE (Asset Discovery only):
 *   DISCOVERY_DONE  → user configures & clicks "Run Port Scan"
 *   PORTSCAN_RUNNING → loading shimmer, animated progress bar
 *   PORTSCAN_DONE   → "Run Port Scan" button REMOVED, results + export shown
 *
 * Stepper is driven by pipelineState for live step indicators.
 */
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import ScanStepper from "../../components/layout/ScanStepper";
import ExportPanel from "../../components/scan/ExportPanel";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import api from "../../api/axiosInstance";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";

const INTENSITIES = ["light", "normal", "deep"];

const textValue = (value, fallback = "—") => {
  if (value == null || value === "" || value === "Unknown" || value === "N/A") return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(v => textValue(v, "")).filter(Boolean).join(", ") || fallback;
  if (typeof value === "object") return value.name || value.vendor || value.address || value.value || fallback;
  return fallback;
};

const fmtNumber = (value, digits = 1, fallback = "—") => {
  const num = Number(value);
  return Number.isFinite(num) ? num.toFixed(digits) : fallback;
};

export default function Phase1Results() {
  const navigate = useNavigate();
  const {
    target, scanId, scanNo,
    phase1Hosts, phase1Summary,
    pipelineMode,
    saveStatus, setSaveStatus,
    setPipelineState,
    setPhase2Hosts,
    setPhase2Summary,
    setPhase2Results,
  } = useScan();

  const [filter, setFilter]             = useState("active");
  const [assetFilter, setAssetFilter]   = useState("active");
  const [assetIntensity, setAssetIntensity] = useState("normal");
  const [assetSelected, setAssetSelected]  = useState(new Set());
  const [assetLoading, setAssetLoading]    = useState(false);
  const [assetResults, setAssetResults]    = useState([]);
  const [assetSummary, setAssetSummary]    = useState(null);
  const [assetError, setAssetError]        = useState("");
  const [assetHasScanned, setAssetHasScanned] = useState(false);
  const [assetExpanded, setAssetExpanded]  = useState(new Set());

  useEffect(() => {
    if (!phase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [phase1Hosts.length, navigate]);

  const isBasicScan      = pipelineMode === "basic";
  const isAssetPipeline  = pipelineMode === "asset";
  const activeHosts      = phase1Hosts.filter(h => h.is_active);
  const displayHosts     = filter === "active" ? activeHosts : phase1Hosts;
  const assetHosts       = assetFilter === "active" ? activeHosts : phase1Hosts;
  const selectedHosts    = phase1Hosts.filter(h => assetSelected.has(h.ip_address) && h.is_active);
  const selectedCount    = selectedHosts.length;

  const canProceedToPhase2 = isPhaseEnabled(pipelineMode, 2);
  const nextPhase          = getNextPhase(pipelineMode, 1);
  const canShowAssetExport = assetHasScanned && assetSummary && assetResults.length > 0;

  // Derived phase state flags
  const portScanRunning = assetLoading;
  const portScanDone    = assetHasScanned;

  useEffect(() => {
    if (isAssetPipeline) {
      setAssetSelected(new Set(activeHosts.map(h => h.ip_address)));
    }
  }, [isAssetPipeline, activeHosts.length]);

  // ── Sync pipeline state to stepper ──────────────────────────────────────────
  useEffect(() => {
    if (isAssetPipeline) {
      // Asset pipeline: reflect port scan phase in stepper
      if (portScanRunning) {
        setPipelineState(PIPELINE_STATES.PORT_SCAN);
      } else if (portScanDone) {
        // PORT_SCAN done → step 2 shows ✓ in stepper
        setPipelineState(PIPELINE_STATES.REPORT_READY);
      }
    } else {
      // Basic Network Scan: discovery is the only phase → mark it ✓ (green)
      // Any value > DISCOVERY (activeStep > 1) makes step 1 render as done
      if (phase1Hosts.length > 0) {
        setPipelineState(PIPELINE_STATES.PORT_SCAN);
      }
    }
  }, [portScanRunning, portScanDone, isAssetPipeline, phase1Hosts.length]);

  if (!phase1Hosts.length) return null;

  const toggleAssetHost = (ip) => {
    const next = new Set(assetSelected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
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

    setAssetHasScanned(false);
    setAssetExpanded(new Set());
    setSaveStatus("saving");

    try {
      const { data: result } = await api.post("/scan/asset-discovery", {
        hosts:         payloadHosts,
        intensity:     assetIntensity,
        scan_id:       scanId,
        pipeline_mode: pipelineMode,
        phases:        [1, 2],
      });

      if (!result.success) throw new Error(result.error || "Phase 2 failed");

      setAssetResults(result.data);
      setAssetSummary(result.summary);
      setPhase2Summary(result.summary);
      setPhase2Results(result.data);
      setAssetHasScanned(true);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);
    } catch (err) {
      setAssetError(err.response?.data?.detail || err.message || "Phase 2 failed");
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setAssetLoading(false);
    }
  };

  const toggleAssetExpand = (ip) => {
    const next = new Set(assetExpanded);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setAssetExpanded(next);
  };

  const proceedToNextPhase = () => {
    if (!canProceedToPhase2) return;
    navigate(nextPhase.route);
  };

  // ── Stepper current: drives which step is "active" via prop fallback ─────
  // pipelineState is set above, so ScanStepper reads it from context directly
  const stepperCurrent = portScanDone ? 3 : portScanRunning ? 2 : isAssetPipeline ? 1 : 1;

  return (
    <AppLayout pageTitle="Discovery Results" saveStatus={saveStatus}>
      <ScanStepper current={stepperCurrent} />

      <div className="page-inner">

        {/* ── Header ──────────────────────────────────────────────────────── */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Discovery Results</h2>
            <p className="page-subtitle">
              Target: <code className="ip-code">{target}</code>
              {scanId && <span className="muted"> · Scan No. {scanNo ?? "-"}</span>}
            </p>
          </div>
          <button className="btn btn--ghost" onClick={() => navigate("/dashboard")}>
            ← New Scan
          </button>
        </div>

        {/* ── Phase 1 summary bar ─────────────────────────────────────────── */}
        {phase1Summary && (
          <div className="summary-bar">
            <span className="summary-item"><b>{phase1Summary.total_hosts}</b> Total</span>
            <span className="summary-item summary-item--active"><b>{phase1Summary.active_hosts}</b> Active</span>
            <span className="summary-item"><b>{phase1Summary.inactive_hosts}</b> Inactive</span>
            <span className="summary-item"><b>{fmtNumber(phase1Summary.scan_duration)}s</b> Duration</span>
            {/* Asset Discovery: show discovery profile and intensity */}
            {isAssetPipeline && phase1Summary.discovery_profile && (
              <span className="summary-item" style={{ gap: 6 }}>
                <span style={{
                  fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 10,
                  background: phase1Summary.discovery_profile === "FAST" ? "rgba(34,211,238,0.12)"
                    : phase1Summary.discovery_profile === "BALANCED" ? "rgba(245,158,11,0.12)"
                    : "rgba(34,197,94,0.12)",
                  color: phase1Summary.discovery_profile === "FAST" ? "#22d3ee"
                    : phase1Summary.discovery_profile === "BALANCED" ? "#f59e0b"
                    : "#22c55e",
                  border: phase1Summary.discovery_profile === "FAST" ? "1px solid rgba(34,211,238,0.3)"
                    : phase1Summary.discovery_profile === "BALANCED" ? "1px solid rgba(245,158,11,0.3)"
                    : "1px solid rgba(34,197,94,0.3)",
                }}>
                  {phase1Summary.discovery_profile}
                </span>
              </span>
            )}
            {/* Normal intensity: show fallback stats */}
            {isAssetPipeline && phase1Summary.discovery_intensity === "normal"
              && phase1Summary.fallback_targets_count != null && (
              <span className="summary-item" style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Fallback: <b>{phase1Summary.fallback_active_hosts}</b>/{phase1Summary.fallback_targets_count} resolved
              </span>
            )}
          </div>
        )}

        {/* ── Asset pipeline progress bar (50% → 100%) ────────────────────── */}
        {isAssetPipeline && (
          <div className="asset-pipeline-progress">
            <div className="app-progress-track">
              <div
                className={`app-progress-fill ${portScanRunning ? "app-progress-fill--animated" : ""}`}
                style={{ width: portScanDone ? "100%" : portScanRunning ? "65%" : "50%" }}
              />
            </div>
            <div className="app-progress-labels">
              <span className={`app-progress-label ${!portScanDone ? "app-progress-label--active" : "app-progress-label--done"}`}>
                {portScanDone || portScanRunning ? "✓ Discovery" : "● Discovery"}
              </span>
              <span className={`app-progress-label ${portScanRunning ? "app-progress-label--active" : portScanDone ? "app-progress-label--done" : "app-progress-label--pending"}`}>
                {portScanDone ? "✓ Port Scan" : portScanRunning ? "● Port Scan" : "○ Port Scan"}
              </span>
            </div>
          </div>
        )}

        {/* ── Asset: Phase controls — HIDDEN once port scan completes ─────── */}
        {isAssetPipeline && !portScanDone ? (
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
              {/* "Run Port Scan" — shown only before scan, disappears on completion */}
              <button
                className="btn btn--primary"
                onClick={runAssetDiscovery}
                disabled={assetLoading || selectedCount === 0}
                style={{ minWidth: 170 }}
              >
                {assetLoading
                  ? <><span className="btn-spinner" /> Scanning…</>
                  : "▶ Run Port Scan"}
              </button>
            </div>
          </div>
        ) : !isAssetPipeline ? (
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
        ) : null}

        {/* ── Discovery hosts table ────────────────────────────────────────── */}
        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                {isAssetPipeline && !portScanDone && <th style={{ width: 36 }} />}
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>Vendor</th>
                <th>Method</th>
                {!isBasicScan && <th>Response</th>}
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {(isAssetPipeline ? assetHosts : displayHosts).map(h => {
                // Determine best hostname
                let displayHost = h.hostname;
                if (!displayHost || displayHost === "Unknown") {
                    if (h.mdns_name) displayHost = h.mdns_name;
                    else if (h.netbios_names && h.netbios_names.length) displayHost = h.netbios_names[0]?.name;
                }
                displayHost = textValue(displayHost, "");

                return (
                  <React.Fragment key={h.ip_address}>
                    <tr
                      className={h.is_active ? "row--active" : "row--inactive"}
                      style={{ cursor: isAssetPipeline && !portScanDone && h.is_active ? "pointer" : "default" }}
                      onClick={() => { if (isAssetPipeline && !portScanDone && h.is_active) toggleAssetHost(h.ip_address); }}
                    >
                      {isAssetPipeline && !portScanDone && (
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
                      <td>{displayHost || <span className="muted">—</span>}</td>
                      <td>{textValue(h.mac_address, <span className="muted">—</span>)}</td>
                      <td>{textValue(h.vendor, <span className="muted">—</span>)}</td>
                      <td>{textValue(h.discovery_method, <span className="muted">—</span>)}</td>
                      {!isBasicScan && (
                        <td>{h.response_time_ms != null ? `${fmtNumber(h.response_time_ms)} ms` : <span className="muted">—</span>}</td>
                      )}
                      <td>
                        <span style={{ 
                          display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 600, 
                          padding: h.is_active ? "2px 8px" : "2px 6px", 
                          background: h.is_active ? "rgba(34,197,94,0.1)" : "transparent", 
                          color: h.is_active ? "#15803d" : "inherit", 
                          borderRadius: 12 
                        }}>
                          <span className={`status-dot ${h.is_active ? "status-dot--up" : "status-dot--down"}`} style={{ margin: 0 }} />
                          {h.is_active ? "Active" : "Inactive"}
                        </span>
                      </td>
                    </tr>
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Basic Network Scan: completion + export below table */}
        {phase1Summary && !canProceedToPhase2 && (
          <>
            <div className="alert alert--success" style={{ marginTop: 20, marginBottom: 8 }}>
              ✓ Scan completed. Export report available below.
            </div>
            <ExportPanel
              results={phase1Hosts}
              summary={phase1Summary}
              scanId={scanId}
              scanNo={scanNo}
              target={target}
              pipelineMode={pipelineMode}
            />
          </>
        )}

        {/* ── Port Scan: error ─────────────────────────────────────────────── */}
        {assetError && (
          <div className="pipeline-error-card" style={{ marginTop: 16 }}>
            <div className="pipeline-error-header">
              <span className="pipeline-error-icon">⚠</span>
              <div>
                <strong>Port Scan failed</strong>
                <p className="pipeline-error-detail">{assetError}</p>
              </div>
            </div>
            <div className="pipeline-error-actions">
              <button className="btn btn--primary" onClick={runAssetDiscovery}>
                ↻ Retry Port Scan
              </button>
            </div>
          </div>
        )}

        {/* ── Port Scan: animated progress while loading ───────────────────── */}
        {assetLoading && (
          <div className="pipeline-progress-card" style={{ marginTop: 20 }}>
            <div className="pipeline-progress-header">
              <div className="pipeline-pulse" />
              <div>
                <h3 className="pipeline-progress-title">Running Port Scan…</h3>
                <p className="pipeline-progress-desc">
                  Probing TCP services on {selectedCount} host{selectedCount !== 1 ? "s" : ""} — intensity: <strong>{assetIntensity}</strong>
                </p>
              </div>
            </div>
            <div className="progress-bar progress-bar--pipeline">
              <div className="progress-fill progress-fill--animated" />
            </div>
            {/* Shimmer skeleton rows */}
            <div className="shimmer-table">
              {[1, 2, 3].map(i => (
                <div key={i} className="shimmer-row">
                  <div className="shimmer-cell shimmer-cell--short" />
                  <div className="shimmer-cell shimmer-cell--medium" />
                  <div className="shimmer-cell shimmer-cell--long" />
                  <div className="shimmer-cell shimmer-cell--short" />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Port Scan: results section (revealed with animation) ─────────── */}
        {portScanDone && (
          <>
            {/* Completion banner */}
            <div className="pipeline-complete-card" style={{ marginTop: 20, marginBottom: 16 }}>
              <div className="pipeline-complete-left">
                <span className="pipeline-complete-icon">✓</span>
                <div>
                  <h3 className="pipeline-complete-title">Port Scan Complete</h3>
                  <p className="pipeline-complete-desc">
                    {assetSummary?.hosts_with_ports ?? 0} host{(assetSummary?.hosts_with_ports ?? 0) !== 1 ? "s" : ""} with open ports found.
                  </p>
                </div>
              </div>
            </div>

            {/* Port scan summary bar */}
            {assetSummary && (
              <div className="summary-bar" style={{ marginBottom: 16 }}>
                <span className="summary-item"><b>{assetSummary.total_hosts}</b> Hosts scanned</span>
                <span className="summary-item summary-item--active"><b>{assetSummary.hosts_with_ports}</b> Have open ports</span>
                <span className="summary-item"><b>{fmtNumber(assetSummary.scan_duration)}s</b> Duration</span>
              </div>
            )}

            {/* Empty state */}
            {assetResults.length === 0 && (
              <div className="empty-state">
                <span className="empty-state-icon">🔍</span>
                <p className="empty-state-title">No active hosts returned open ports</p>
              </div>
            )}

            {/* Host result cards */}
            {assetResults.map(host => {
              const portCount  = host.open_ports?.length || 0;
              const critPorts  = host.open_ports?.filter(p => p.risk === "Critical").length || 0;
              const isExpanded = assetExpanded.has(host.ip_address);
              return (
                <div key={host.ip_address} className="host-card pipeline-section--reveal">
                  <div className="host-card-header" onClick={() => toggleAssetExpand(host.ip_address)}>
                    <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <code className="ip-code" style={{ fontSize: "0.9rem", fontWeight: 700 }}>{host.ip_address}</code>
                      {textValue(host.hostname, "") && (
                        <span className="muted small">{textValue(host.hostname, "")}</span>
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
                                    {textValue(port.service)}
                                  </span>
                                </td>
                                <td style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>
                                  {textValue(port.banner || port.version, <span className="muted">—</span>)}
                                </td>
                                <td>
                                  <span style={{
                                    color: port.risk === "Critical" ? "#ff4d4d" : port.risk === "High" ? "#f97316" : port.risk === "Medium" ? "#f59e0b" : port.risk === "Low" ? "#22c55e" : "#60a5fa",
                                    fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700,
                                  }}>
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

            {/* Export panel after results */}
            {canShowAssetExport && (
              <ExportPanel
                results={assetResults}
                summary={assetSummary}
                scanId={scanId}
                scanNo={scanNo}
                target={target}
              />
            )}
          </>
        )}

        {canProceedToPhase2 && !isAssetPipeline && (
          <div className="phase-action-bar">
            <p className="muted" style={{ fontSize: "0.85rem" }}>
              Continue to Port Scan to choose hosts and intensity on the same page.
            </p>
            <button className="btn btn--primary" onClick={proceedToNextPhase}>
              Continue to Port Scan
            </button>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
