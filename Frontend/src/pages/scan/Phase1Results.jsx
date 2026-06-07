/**
 * src/pages/scan/Phase1Results.jsx
 *
 * Pattern B — Pure Reporting Screen
 *
 * For the ASSET pipeline:
 *   Phase 1 (host discovery) results are shown here as a read-only table.
 *   Phase 2 (port scan) is auto-chained on the backend immediately after Phase 1.
 *   No mid-run controls here — all configuration happened on NewScan.jsx upfront.
 *   A status indicator links to the Phase 2 results page when ready.
 *
 * For the BASIC pipeline:
 *   Behaviour unchanged — shows host table + export panel.
 *
 * For the VULNERABILITY AUDIT pipeline:
 *   Shows host table + "Continue to Port Scan" button (navigates to Phase2Results).
 */
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import ScanStepper from "../../components/layout/ScanStepper";
import ExportPanel from "../../components/scan/ExportPanel";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";
import api from "../../api/axiosInstance";
import { useAuth } from "../../context/AuthContext";
import { can, denyMessage } from "../../auth/permissions";

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
  const { user } = useAuth();
  const canExecuteScans = can(user, "scans", "execute");
  const {
    target, scanId, scanNo,
    phase1Hosts, phase1Summary,
    phase2Results,
    pipelineMode,
    saveStatus, setSaveStatus,
    setPhase2Results,
    setPhase2Summary,
    setPipelineState,
    executionMode,
    portScanIntensity,
    osDetection,
  } = useScan();

  const [filter, setFilter] = useState("active");
  // For asset pipeline: poll once to know if Phase 2 is already done
  const [phase2Done, setPhase2Done]     = useState(phase2Results.length > 0);
  const [phase2Polling, setPhase2Polling] = useState(false);
  const [selected, setSelected] = useState(() => new Set(phase1Hosts.filter(h => h.is_active).map(h => h.ip_address)));
  const [assetLoading, setAssetLoading] = useState(false);
  const [error, setError] = useState("");

  const hasPhase2 = isPhaseEnabled(pipelineMode, 2);
  const showCheckboxes = executionMode === "interactive" && pipelineMode !== "basic";

  const toggleHost = (ip) => {
    const next = new Set(selected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setSelected(next);
  };

  const runPortScan = async () => {
    if (!canExecuteScans) {
      setError("You do not have permission to execute scans.");
      return;
    }
    const selectedHosts = phase1Hosts.filter(h => selected.has(h.ip_address) && h.is_active);
    if (!selectedHosts.length) {
      setError("Select at least one host to port scan.");
      return;
    }
    setAssetLoading(true);
    setError("");
    setSaveStatus("saving");
    try {
      const { data } = await api.post("/scan/asset-discovery", {
        hosts: selectedHosts,
        intensity: portScanIntensity || "normal",
        scan_id: scanId,
        pipeline_mode: pipelineMode,
        os_detection: osDetection,
        phases: [1, 2],
      });
      if (!data.success) throw new Error(data.error || "Port scan failed to start.");
      setPipelineState(PIPELINE_STATES.PORT_SCAN);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 4000);
      navigate("/scan/asset-discovery");
    } catch (err) {
      setError(err.message || "Failed to start Port Scan");
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setAssetLoading(false);
    }
  };

  useEffect(() => {
    if (!phase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [phase1Hosts.length, navigate]);

  const isBasicScan     = pipelineMode === "basic";
  const isAssetPipeline = pipelineMode === "asset";
  const activeHosts     = phase1Hosts.filter(h => h.is_active);
  const displayHosts    = filter === "active" ? activeHosts : phase1Hosts;

  const isUnreachable = phase1Summary && (
    phase1Summary.status === "unreachable" ||
    (Number(phase1Summary.active_hosts) === 0 && Number(phase1Summary.total_hosts) > 0)
  );

  const canProceedToPhase2 = isPhaseEnabled(pipelineMode, 2) && !isUnreachable;
  const nextPhase          = getNextPhase(pipelineMode, 1);

  // ── Stepper: configure active step state ──
  useEffect(() => {
    if (hasPhase2) {
      if (phase2Done) {
        setPipelineState(pipelineMode === "asset" ? PIPELINE_STATES.REPORT_READY : PIPELINE_STATES.PORT_SCAN);
      } else {
        setPipelineState(executionMode === "interactive" ? PIPELINE_STATES.IDLE : PIPELINE_STATES.PORT_SCAN);
      }
    } else if (phase1Hosts.length > 0) {
      setPipelineState(PIPELINE_STATES.PORT_SCAN);
    }
  }, [hasPhase2, phase2Done, phase1Hosts.length, executionMode, pipelineMode, setPipelineState]);

  // ── For pipelines with phase 2: poll the scan until Phase 2 is complete ──────────
  useEffect(() => {
    if (!hasPhase2 || phase2Done || !scanId || isUnreachable || executionMode === "interactive") return;

    let stopped = false;
    setPhase2Polling(true);

    const poll = async () => {
      while (!stopped) {
        await new Promise(r => setTimeout(r, 4000));
        if (stopped) break;
        try {
          const { data: scan } = await api.get(`/scans/${scanId}`);
          const p2 = scan?.results?.phase2?.data;
          const p2Summary = scan?.results?.phase2?.summary;
          if (Array.isArray(p2) && p2.length > 0) {
            // Save results into context so Phase2Results.jsx can read them
            setPhase2Results(p2);
            if (p2Summary) setPhase2Summary(p2Summary);
            setPhase2Done(true);
            setPhase2Polling(false);
            break;
          }
          // Also stop polling if scan has completed/failed
          if (scan?.status === "complete" || scan?.status === "failed") {
            if (Array.isArray(p2) && p2.length > 0) {
              setPhase2Results(p2);
              if (p2Summary) setPhase2Summary(p2Summary);
            }
            setPhase2Done(Array.isArray(p2) && p2.length > 0);
            setPhase2Polling(false);
            break;
          }
        } catch { /* ignore transient errors */ }
      }
    };

    poll();
    return () => { stopped = true; };
  }, [hasPhase2, phase2Done, scanId, isUnreachable, executionMode, setPhase2Results, setPhase2Summary]);

  if (!phase1Hosts.length) return null;

  const proceedToNextPhase = () => {
    if (!canExecuteScans) return;
    if (!canProceedToPhase2 || !nextPhase) return;
    navigate(nextPhase.route);
  };

  const stepperCurrent = hasPhase2
    ? (phase2Done
        ? (pipelineMode === "asset" ? 3 : 2)
        : (executionMode === "interactive" ? 1 : 2))
    : 1;

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
              {scanId && <span className="muted"> · Scan No. {scanNo ?? "—"}</span>}
            </p>
          </div>
          <button className="btn btn--ghost" onClick={() => navigate("/dashboard")}>
            ← New Scan
          </button>
        </div>

        {error && <div className="alert alert--error" style={{ margin: "16px 0" }}>⚠ {error}</div>}

        {/* ── Unreachable Banner ───────────────────────────────────────────── */}
        {isUnreachable && (
          <div style={{
            margin: "16px 0", padding: "16px 20px", borderRadius: 8,
            background: "rgba(245, 158, 11, 0.08)", border: "1px solid rgba(245, 158, 11, 0.3)",
            display: "flex", alignItems: "center", gap: 16, color: "#92400e"
          }}>
            <span style={{ fontSize: 24 }}>⚠️</span>
            <div>
              <strong style={{ display: "block", fontSize: 16 }}>Host is unavailable/down/unreachable</strong>
              <p style={{ margin: "4px 0 0", fontSize: 14, opacity: 0.9 }}>
                The discovery scan completed but the target did not respond.
                Verify the IP address and network connectivity before re-scanning.
              </p>
            </div>
          </div>
        )}

        {/* ── Phase 1 summary bar ──────────────────────────────────────────── */}
        {phase1Summary && (
          <div className="summary-bar">
            <span className="summary-item"><b>{phase1Summary.total_hosts}</b> Total</span>
            <span className="summary-item summary-item--active"><b>{phase1Summary.active_hosts}</b> Active</span>
            <span className="summary-item"><b>{phase1Summary.inactive_hosts}</b> Inactive</span>
            <span className="summary-item"><b>{fmtNumber(phase1Summary.scan_duration)}s</b> Duration</span>
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
            {isAssetPipeline && phase1Summary.discovery_intensity === "normal"
              && phase1Summary.fallback_targets_count != null && (
              <span className="summary-item" style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Fallback: <b>{phase1Summary.fallback_active_hosts}</b>/{phase1Summary.fallback_targets_count} resolved
              </span>
            )}
          </div>
        )}

        {/* ── Port Scan Phase Banners & Controls ── */}
        {hasPhase2 && !isUnreachable && (
          <div style={{ margin: "16px 0" }}>
            {phase2Done ? (
              <div style={{
                display: "flex", alignItems: "center", gap: 14,
                padding: "14px 20px", borderRadius: 8,
                background: "rgba(34,197,94,0.08)", border: "1px solid rgba(34,197,94,0.3)",
              }}>
                <span style={{ fontSize: 22 }}>✅</span>
                <div style={{ flex: 1 }}>
                  <strong style={{ display: "block", color: "#15803d" }}>Port Scan Complete</strong>
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                    Phase 2 finished successfully. View the full port scan results below.
                  </span>
                </div>
                <button className="btn btn--primary" onClick={() => navigate("/scan/asset-discovery")}>
                  View Port Scan Results →
                </button>
              </div>
            ) : executionMode === "interactive" ? (
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 14,
                padding: "14px 20px",
                borderRadius: 8,
                background: "var(--bg-card)",
                border: "1px solid var(--border)",
              }}>
                <div>
                  <strong style={{ display: "block", color: "var(--text)" }}>Run Port Scan</strong>
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                    Select hosts below to probe TCP/UDP services. <b>{selected.size}</b> host{selected.size !== 1 ? "s" : ""} selected.
                  </span>
                </div>
                <button
                  className="btn btn--primary"
                  onClick={runPortScan}
                  disabled={selected.size === 0 || assetLoading || !canExecuteScans}
                  style={{ display: "flex", alignItems: "center", gap: 8 }}
                >
                  {assetLoading ? (
                    <>
                      <span className="btn-spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
                      Starting Port Scan...
                    </>
                  ) : (
                    <>
                      Run Port Scan on Selected Hosts →
                    </>
                  )}
                </button>
              </div>
            ) : (
              <div style={{
                display: "flex", alignItems: "center", gap: 14,
                padding: "14px 20px", borderRadius: 8,
                background: "rgba(99,102,241,0.08)", border: "1px solid rgba(99,102,241,0.3)",
              }}>
                <span className="btn-spinner" style={{ width: 20, height: 20, borderWidth: 3, flexShrink: 0 }} />
                <div>
                  <strong style={{ display: "block", color: "#6366f1" }}>Port Scan Running…</strong>
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
                    Phase 2 is running automatically in the background. This page will update when it completes.
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Sub-progress bar (automatic mode only) ── */}
        {executionMode === "automatic" && hasPhase2 && (
          <div className="asset-pipeline-progress">
            <div className="app-progress-track">
              <div
                className={`app-progress-fill ${phase2Polling ? "app-progress-fill--animated" : ""}`}
                style={{ width: phase2Done ? "100%" : phase2Polling ? "65%" : "50%" }}
              />
            </div>
            <div className="app-progress-labels">
              <span className="app-progress-label app-progress-label--done">✓ Discovery</span>
              <span className={`app-progress-label ${phase2Polling ? "app-progress-label--active" : phase2Done ? "app-progress-label--done" : "app-progress-label--pending"}`}>
                {phase2Done ? "✓ Port Scan" : phase2Polling ? "● Port Scan" : "○ Port Scan"}
              </span>
            </div>
          </div>
        )}

        {/* ── Filter tabs (non-asset pipelines) ────────────────────────────── */}
        {!isAssetPipeline && (
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

        {/* ── Discovery hosts table ─────────────────────────────────────────── */}
        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                {showCheckboxes && (
                  <th style={{ width: 40, paddingRight: 0 }}>
                    <input
                      type="checkbox"
                      checked={activeHosts.length > 0 && activeHosts.every(h => selected.has(h.ip_address))}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelected(new Set(activeHosts.map(h => h.ip_address)));
                        } else {
                          setSelected(new Set());
                        }
                      }}
                      disabled={!canExecuteScans}
                      style={{ cursor: "pointer" }}
                    />
                  </th>
                )}
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
              {(isAssetPipeline ? activeHosts : displayHosts).map(h => {
                let displayHost = h.hostname;
                if (!displayHost || displayHost === "Unknown") {
                    if (h.mdns_name) displayHost = h.mdns_name;
                    else if (h.netbios_names && h.netbios_names.length) displayHost = h.netbios_names[0]?.name;
                }
                displayHost = textValue(displayHost, "");

                return (
                  <React.Fragment key={h.ip_address}>
                    <tr className={h.is_active ? "row--active" : "row--inactive"}>
                      {showCheckboxes && (
                        <td style={{ paddingRight: 0 }}>
                          <input
                            type="checkbox"
                            checked={selected.has(h.ip_address)}
                            onChange={() => toggleHost(h.ip_address)}
                            disabled={!h.is_active || !canExecuteScans}
                            style={{ cursor: "pointer" }}
                          />
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

        {/* ── Basic Scan: completion + export ──────────────────────────────── */}
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

        {/* ── Vulnerability Audit pipeline: proceed button ─────────────────── */}
        {canProceedToPhase2 && !isAssetPipeline && executionMode !== "interactive" && executionMode !== "automatic" && (
          <div className="phase-action-bar">
            <p className="muted" style={{ fontSize: "0.85rem" }}>
              Continue to Port Scan to choose hosts and intensity on the same page.
            </p>
            <button className="btn btn--primary" onClick={proceedToNextPhase} disabled={!canExecuteScans}>
              Continue to Port Scan
            </button>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
