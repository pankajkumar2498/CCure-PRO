/**
 * src/pages/scan/Phase3Results.jsx
 *
 * UNIFIED AUTO-PIPELINE PAGE
 * ─────────────────────────────────────────────────────────────────────────────
 * After the user clicks "Start Discovery Scan" and Phase 1 completes,
 * this page automatically runs the entire pipeline:
 *
 *   Phase 2 (Port Scan) → Phase 3 (Vulnerability Audit) → Report Ready
 *
 * NO manual buttons between phases. The pipeline runs seamlessly.
 *
 * Features:
 *   • Automatic sequential phase execution
 *   • Live progress with animated stepper
 *   • Progressive result reveal as each phase completes
 *   • Cancel / Retry support
 *   • Scan intensity selector (before pipeline starts)
 *   • Failure handling with phase-specific retry
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate }          from "react-router-dom";
import AppLayout                from "../../components/layout/AppLayout";
import ScanStepper              from "../../components/layout/ScanStepper";
import Modal                    from "../../components/layout/Modal";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import api                      from "../../api/axiosInstance";

/* ── Helpers ──────────────────────────────────────────────────────────────── */

const SEV_COLOR = {
  Critical: "#ff4d4d",
  High:     "#f97316",
  Medium:   "#f59e0b",
  Low:      "#22c55e",
  Info:     "#60a5fa",
};

// GAP-07: device category → { icon, color, label } for richly-rendered badge
const DEVICE_CAT_META = {
  router:            { icon: "🔀", color: "#60a5fa",  label: "Router"          },
  switch:            { icon: "🔗", color: "#818cf8",  label: "Switch"          },
  firewall:          { icon: "🛡",  color: "#f97316",  label: "Firewall"        },
  wireless_ap:       { icon: "📡", color: "#22d3ee",  label: "Wireless AP"     },
  printer:           { icon: "🖨", color: "#a78bfa",  label: "Printer"         },
  iot:               { icon: "⚙",  color: "#fb923c",  label: "IoT/ICS"         },
  server:            { icon: "🖥",  color: "#34d399",  label: "Server"          },
  endpoint:          { icon: "💻", color: "#94a3b8",  label: "Endpoint"        },
  voip:              { icon: "📞", color: "#f472b6",  label: "VoIP"            },
  storage:           { icon: "💾", color: "#fbbf24",  label: "Storage"         },
  network_appliance: { icon: "🔌", color: "#64748b",  label: "Net Appliance"   },
  unknown:           { icon: "❓", color: "var(--text-muted)", label: "Unknown" },
};

// GAP-06: count active exploit conditions on a host
const countActiveFindings = (host) => {
  let n = 0;
  if (host.heartbleed_info?.vulnerable)               n++;
  if (host.smb_ms17010_info?.ms17010_likely)          n++;
  if (host.ldap_info?.anonymous_bind?.allowed)        n++;
  if (host.dns_info?.zone_transfer?.vulnerable)        n++;
  if (host.default_creds_info?.ftp_anon?.allowed)     n++;
  if (host.default_creds_info?.redis_noauth?.vulnerable) n++;
  if (host.default_creds_info?.mongo_noauth?.vulnerable) n++;
  if (host.default_creds_info?.mqtt_noauth?.vulnerable)  n++;
  if (host.default_creds_info?.http_default_creds?.found) n++;
  return n;
};

const fmtSec = (v) => {
  if (typeof v === "number") return v.toFixed(1);
  const n = Number(v);
  return Number.isFinite(n) ? n.toFixed(1) : "—";
};

const safeArr = (v) => (Array.isArray(v) ? v : []);

/* ── Phase progress messages ──────────────────────────────────────────────── */
const PHASE_MESSAGES = {
  [PIPELINE_STATES.DISCOVERY]:  { title: "Running Discovery…",           desc: "Probing the network for live hosts." },
  [PIPELINE_STATES.PORT_SCAN]:  { title: "Running Port Scan…",           desc: "Mapping open TCP services and grabbing banners." },
  [PIPELINE_STATES.VULN_SCAN]:  { title: "Running Vulnerability Audit…", desc: "Analyzing services for CVEs and security risks." },
};

/* ── Main Component ───────────────────────────────────────────────────────── */

export default function Phase3Results() {
  const navigate = useNavigate();
  const {
    phase1Hosts, phase1Summary,
    phase2Results, phase2Summary,
    phase3AuditResults, phase3Summary,
    scanId, target, intensity,
    setPhase2Results, setPhase2Summary,
    setPhase3Summary, setPhase3AuditResults,
    pipelineMode,
    pipelineState, setPipelineState,
    pipelineError, setPipelineError,
    pipelinePhaseTimings, setPipelinePhaseTimings,
    saveStatus, setSaveStatus,
    abortRef,
    resetScan,
  } = useScan();

  // Track whether the auto-pipeline has been triggered
  const pipelineStarted = useRef(false);
  const [localPortHosts, setLocalPortHosts]     = useState(() => safeArr(phase2Results));
  const [localVulnResults, setLocalVulnResults] = useState(() => safeArr(phase3AuditResults));
  const [expanded, setExpanded] = useState(new Set());
  
  // Filter states for each result section (active/all)
  const [filter1, setFilter1] = useState("active"); // Discovery Results
  const [filter2, setFilter2] = useState("active"); // Port Scan Results
  const [filter3, setFilter3] = useState("active"); // Vulnerability Results

  // Modal state for Risk Report
  const [showReportModal, setShowReportModal] = useState(false);

  const safePhase1Hosts     = safeArr(phase1Hosts);
  const activeDiscoveryHosts = safePhase1Hosts.filter(h => h.is_active);

  // Redirect if no hosts exist
  useEffect(() => {
    if (!safePhase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [safePhase1Hosts.length, navigate]);

  // Sync from context when results change externally
  useEffect(() => { setLocalPortHosts(safeArr(phase2Results)); }, [phase2Results]);
  useEffect(() => { setLocalVulnResults(safeArr(phase3AuditResults)); }, [phase3AuditResults]);

  /* ── Auto-start pipeline on mount ───────────────────────────────────────── */
  useEffect(() => {
    if (
      pipelineStarted.current ||
      !safePhase1Hosts.length ||
      !activeDiscoveryHosts.length
    ) return;

    // Don't auto-start if pipeline already completed or is mid-run
    if ([
      PIPELINE_STATES.PORT_SCAN,
      PIPELINE_STATES.VULN_SCAN,
      PIPELINE_STATES.REPORT_READY,
      PIPELINE_STATES.COMPLETE,
    ].includes(pipelineState)) return;

    // Don't auto-start if we already have results (page refresh scenario)
    if (safeArr(phase2Results).length > 0 || safeArr(phase3AuditResults).length > 0) return;

    pipelineStarted.current = true;
    runFullPipeline();
  }, [safePhase1Hosts.length, activeDiscoveryHosts.length]);

  /* ── The automated pipeline executor ────────────────────────────────────── */
  const runFullPipeline = useCallback(async (retryFromPhase = null) => {
    const controller = new AbortController();
    abortRef.current = controller;

    const signal = controller.signal;
    const timings = { ...pipelinePhaseTimings };

    // Determine starting phase
    const startPhase = retryFromPhase || "PORT_SCAN";
    let portHosts = retryFromPhase === "PORT_SCAN" ? [] : safeArr(phase2Results);

    /* ── Phase 2: Port Scan ───────────────────────────────────────────────── */
    if (startPhase === "PORT_SCAN") {
      setPipelineState(PIPELINE_STATES.PORT_SCAN);
      setPipelineError(null);
      setSaveStatus("saving");
      const phaseStart = Date.now();

      try {
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");

        const { data: assetData } = await api.post("/scan/asset-discovery", {
          hosts:         activeDiscoveryHosts,
          intensity,
          scan_id:       scanId,
          pipeline_mode: pipelineMode,
          phases:        [1, 2],
        }, { signal });

        if (!assetData.success) throw new Error(assetData.error || "Port scan failed");

        portHosts = safeArr(assetData.data);
        if (!portHosts.length) {
          throw new Error("Port scan completed but returned no hosts.");
        }

        setPhase2Results(portHosts);
        setPhase2Summary(assetData.summary || null);
        setLocalPortHosts(portHosts);
        timings.portScan = ((Date.now() - phaseStart) / 1000).toFixed(1);
        setPipelinePhaseTimings({ ...timings });

      } catch (err) {
        if (err.name === "AbortError") {
          setPipelineState(PIPELINE_STATES.CANCELLED);
          setSaveStatus("");
          return;
        }
        const detail = err.response?.data?.detail || err.message || "Port scan failed";
        setPipelineError({ phase: "PORT_SCAN", message: detail });
        setPipelineState(PIPELINE_STATES.ERROR);
        setSaveStatus("error");
        setTimeout(() => setSaveStatus(""), 4000);
        return;
      }
    }

    /* ── Phase 3: Vulnerability Audit ─────────────────────────────────────── */
    setPipelineState(PIPELINE_STATES.VULN_SCAN);
    const phase3Start = Date.now();

    try {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");

      const hostsForAudit = portHosts.length ? portHosts : safeArr(phase2Results);

      const { data: auditData } = await api.post("/scan/advanced-scan", {
        hosts:         hostsForAudit,
        scan_id:       scanId,
        pipeline_mode: pipelineMode,
        phases:        [1, 2, 3, 4],
      }, { signal });

      if (!auditData.success) throw new Error(auditData.error || "Vulnerability audit failed");

      const auditHosts = safeArr(auditData.data);
      if (!auditHosts.length) {
        throw new Error("Vulnerability audit completed but returned no hosts.");
      }

      setPhase3Summary(auditData.summary || null);
      setPhase3AuditResults(auditHosts);
      setLocalVulnResults(auditHosts);
      setExpanded(new Set(auditHosts.filter(h => h.is_active).map(h => h.ip_address)));
      timings.vulnScan = ((Date.now() - phase3Start) / 1000).toFixed(1);
      setPipelinePhaseTimings({ ...timings });

      // Pipeline complete — transition to REPORT_READY
      setPipelineState(PIPELINE_STATES.REPORT_READY);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 4000);

    } catch (err) {
      if (err.name === "AbortError") {
        setPipelineState(PIPELINE_STATES.CANCELLED);
        setSaveStatus("");
        return;
      }
      const detail = err.response?.data?.detail || err.message || "Vulnerability audit failed";
      setPipelineError({ phase: "VULN_SCAN", message: detail });
      setPipelineState(PIPELINE_STATES.ERROR);
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    }
  }, [
    activeDiscoveryHosts, intensity, scanId, pipelineMode, phase2Results,
    setPipelineState, setPipelineError, setSaveStatus,
    setPhase2Results, setPhase2Summary, setPhase3Summary, setPhase3AuditResults,
    setPipelinePhaseTimings, pipelinePhaseTimings, abortRef,
  ]);

  /* ── Event handlers ─────────────────────────────────────────────────────── */

  const handleRetry = () => {
    pipelineStarted.current = true;
    runFullPipeline(pipelineError?.phase || "PORT_SCAN");
  };

  const handleCancel = () => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
    setPipelineState(PIPELINE_STATES.CANCELLED);
  };

  const handleRestart = () => {
    setLocalPortHosts([]);
    setLocalVulnResults([]);
    setPhase2Results([]);
    setPhase2Summary(null);
    setPhase3AuditResults([]);
    setPhase3Summary(null);
    setExpanded(new Set());
    setPipelineError(null);
    pipelineStarted.current = true;
    runFullPipeline("PORT_SCAN");
  };

  const proceedToReport = () => {
    // Open the report modal instead of navigating
    setShowReportModal(true);
  };

  const toggleExpand = (ip) => {
    const next = new Set(expanded);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setExpanded(next);
  };

  /* ── Guard ──────────────────────────────────────────────────────────────── */
  if (!safePhase1Hosts.length) return null;

  /* ── Derived state ──────────────────────────────────────────────────────── */
  const isScanning = [
    PIPELINE_STATES.PORT_SCAN,
    PIPELINE_STATES.VULN_SCAN,
  ].includes(pipelineState);
  const isDone = [PIPELINE_STATES.REPORT_READY, PIPELINE_STATES.COMPLETE].includes(pipelineState);
  const isError = pipelineState === PIPELINE_STATES.ERROR;
  const isCancelled = pipelineState === PIPELINE_STATES.CANCELLED;
  const currentStep = localVulnResults.length ? 3 : localPortHosts.length ? 2 : 1;
  const activeMsg = PHASE_MESSAGES[pipelineState];
  
  // Filter display logic for each section
  const displayDiscoveryHosts = filter1 === "active" ? activeDiscoveryHosts : safePhase1Hosts;
  const activePortHosts = localPortHosts.filter(h => h.is_active);
  const displayPortHosts = filter2 === "active" ? activePortHosts : localPortHosts;
  const activeVulnHosts = localVulnResults.filter(h => h.is_active);
  const displayVulnHosts = filter3 === "active" ? activeVulnHosts : localVulnResults;

  return (
    <AppLayout pageTitle="Advanced Scan" saveStatus={saveStatus}>
      <ScanStepper current={currentStep} />

      <div className="page-inner">

        {/* ── Header ──────────────────────────────────────────────────────── */}
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Advanced Scan</h2>
            <p className="page-subtitle">
              Full pipeline execution from <code className="ip-code">{target}</code>
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {isScanning && (
              <button className="btn btn--cancel" onClick={handleCancel}>
                ✕ Cancel Scan
              </button>
            )}
            <button className="btn btn--ghost" onClick={() => navigate("/scan")}>← Back</button>
          </div>
        </div>

        {/* ── Discovery Summary ───────────────────────────────────────────── */}
        <div className="summary-bar" style={{ marginBottom: 16 }}>
          <span className="summary-item"><b>{phase1Summary?.total_hosts ?? safePhase1Hosts.length}</b> Total discovered</span>
          <span className="summary-item summary-item--active"><b>{phase1Summary?.active_hosts ?? activeDiscoveryHosts.length}</b> Active</span>
          <span className="summary-item"><b>{phase1Summary?.inactive_hosts ?? safePhase1Hosts.length - activeDiscoveryHosts.length}</b> Inactive</span>
          <span className="summary-item"><b>{fmtSec(phase1Summary?.scan_duration)}s</b> Discovery time</span>
        </div>

        {/* ── Error State ─────────────────────────────────────────────────── */}
        {isError && pipelineError && (
          <div className="pipeline-error-card">
            <div className="pipeline-error-header">
              <span className="pipeline-error-icon">⚠</span>
              <div>
                <strong>Pipeline failed at {pipelineError.phase === "PORT_SCAN" ? "Port Scan" : "Vulnerability Audit"}</strong>
                <p className="pipeline-error-detail">{pipelineError.message}</p>
              </div>
            </div>
            <div className="pipeline-error-actions">
              <button className="btn btn--primary" onClick={handleRetry}>
                ↻ Retry from {pipelineError.phase === "PORT_SCAN" ? "Port Scan" : "Vulnerability Audit"}
              </button>
              <button className="btn btn--ghost" onClick={handleRestart}>
                ↺ Restart Full Pipeline
              </button>
            </div>
          </div>
        )}

        {/* ── Cancelled State ─────────────────────────────────────────────── */}
        {isCancelled && (
          <div className="pipeline-cancelled-card">
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: "1.4rem" }}>⏹</span>
              <div>
                <strong>Scan Cancelled</strong>
                <p className="muted" style={{ margin: "4px 0 0" }}>The pipeline was stopped by user request.</p>
              </div>
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button className="btn btn--primary" onClick={handleRestart}>
                ↺ Restart Pipeline
              </button>
              <button className="btn btn--ghost" onClick={() => navigate("/scan")}>
                ← New Scan
              </button>
            </div>
          </div>
        )}

        {/* ── Active Phase Progress ───────────────────────────────────────── */}
        {isScanning && activeMsg && (
          <div className="pipeline-progress-card">
            <div className="pipeline-progress-header">
              <div className="pipeline-pulse" />
              <div>
                <h3 className="pipeline-progress-title">{activeMsg.title}</h3>
                <p className="pipeline-progress-desc">{activeMsg.desc}</p>
              </div>
            </div>
            <div className="progress-bar progress-bar--pipeline">
              <div className="progress-fill progress-fill--animated" />
            </div>
            <div className="pipeline-progress-meta">
              {pipelineState === PIPELINE_STATES.PORT_SCAN && (
                <span className="muted" style={{ fontSize: 12 }}>
                  Phase 2 of 3 · Intensity: <strong>{intensity}</strong>
                </span>
              )}
              {pipelineState === PIPELINE_STATES.VULN_SCAN && (
                <span className="muted" style={{ fontSize: 12 }}>
                  Phase 3 of 3 · {localPortHosts.length} host{localPortHosts.length !== 1 ? "s" : ""} queued for audit
                </span>
              )}
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* SECTION 1: Discovery Results                                      */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        <section className="pipeline-section pipeline-section--done">
          <div className="pipeline-section-header">
            <div>
              <h3 className="section-title"><span className="section-badge section-badge--done">✓</span> 1. Discovery Results</h3>
              <p className="muted">Live hosts detected during Phase 1.</p>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "16px 0", flexWrap: "wrap" }}>
            <div className="filter-tabs">
              {[
                ["active", `Active (${activeDiscoveryHosts.length})`],
                ["all",    `All (${safePhase1Hosts.length})`],
              ].map(([val, lbl]) => (
                <button
                  key={val}
                  className={`filter-tab ${filter1 === val ? "filter-tab--active" : ""}`}
                  onClick={() => setFilter1(val)}
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
                  <th>Device</th>
                  <th>Status</th>
                  <th>Method</th>
                  <th>MAC</th>
                  <th>Vendor</th>
                </tr>
              </thead>
              <tbody>
                {displayDiscoveryHosts.map(host => {
                  let displayHost = host.hostname;
                  if (!displayHost || displayHost === "Unknown") {
                      if (host.mdns_name) displayHost = host.mdns_name;
                      else if (host.netbios_names && host.netbios_names.length) displayHost = host.netbios_names[0].name;
                  }
                  const devCat = host.snmp_device_type || host.device_category || "unknown";

                  return (
                    <tr key={host.ip_address} className={host.is_active ? "row--active" : "row--inactive"}>
                      <td><code className="ip-code">{host.ip_address}</code></td>
                      <td>{displayHost || <span className="muted">—</span>}</td>
                      <td>
                        {devCat !== "unknown" ? (
                          <span style={{ fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", padding: "2px 6px", borderRadius: 4, textTransform: "capitalize" }}>
                            {devCat}
                          </span>
                        ) : <span className="muted">—</span>}
                      </td>
                      <td>
                        <span className={`status-dot ${host.is_active ? "status-dot--up" : "status-dot--down"}`} />
                        {host.is_active ? "Active" : "Inactive"}
                      </td>
                      <td>{host.discovery_method || <span className="muted">—</span>}</td>
                      <td>{host.mac_address || <span className="muted">—</span>}</td>
                      <td>{host.vendor || <span className="muted">—</span>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* SECTION 2: Port Scan Results (appears after Phase 2 completes)    */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        {localPortHosts.length > 0 && (
          <section className="pipeline-section pipeline-section--reveal">
            <div className="pipeline-section-header">
              <div>
                <h3 className="section-title"><span className="section-badge section-badge--done">✓</span> 2. Port Scan Results</h3>
                <p className="muted">Open services discovered during Phase 2.</p>
              </div>
              {pipelinePhaseTimings.portScan && (
                <span className="pipeline-timing">{pipelinePhaseTimings.portScan}s</span>
              )}
            </div>

            <div className="summary-bar" style={{ marginBottom: 16 }}>
              <span className="summary-item"><b>{phase2Summary?.total_hosts ?? localPortHosts.length}</b> Hosts scanned</span>
              <span className="summary-item summary-item--active">
                <b>{phase2Summary?.hosts_with_ports ?? localPortHosts.filter(h => h.open_ports?.length).length}</b> Have open ports
              </span>
              <span className="summary-item"><b>{fmtSec(phase2Summary?.scan_duration)}s</b> Duration</span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "16px 0", flexWrap: "wrap" }}>
              <div className="filter-tabs">
                {[
                  ["active", `Active (${activePortHosts.length})`],
                  ["all",    `All (${localPortHosts.length})`],
                ].map(([val, lbl]) => (
                  <button
                    key={val}
                    className={`filter-tab ${filter2 === val ? "filter-tab--active" : ""}`}
                    onClick={() => setFilter2(val)}
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
                    <th>Device</th>
                    <th>Open Ports</th>
                    <th>Vendor</th>
                    <th>OS</th>
                  </tr>
                </thead>
                <tbody>
                  {displayPortHosts.map(host => {
                    let displayHost = host.hostname;
                    if (!displayHost || displayHost === "Unknown") {
                        if (host.mdns_name) displayHost = host.mdns_name;
                        else if (host.netbios_names && host.netbios_names.length) displayHost = host.netbios_names[0].name;
                    }
                    const devCat = host.snmp_device_type || host.device_category || "unknown";

                    return (
                      <tr key={host.ip_address} className={host.is_active ? "row--active" : "row--inactive"}>
                        <td><code className="ip-code">{host.ip_address}</code></td>
                        <td>{displayHost || <span className="muted">—</span>}</td>
                        <td>
                          {devCat !== "unknown" ? (
                            <span style={{ fontSize: 11, background: "var(--bg)", border: "1px solid var(--border)", padding: "2px 6px", borderRadius: 4, textTransform: "capitalize" }}>
                              {devCat}
                            </span>
                          ) : <span className="muted">—</span>}
                        </td>
                        <td>{(host.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || <span className="muted">—</span>}</td>
                        <td>{host.vendor || <span className="muted">—</span>}</td>
                        <td>{host.os_fingerprint_full?.os || host.os_guess || <span className="muted">—</span>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* SECTION 3: Vulnerability Results (appears after Phase 3)          */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        {localVulnResults.length > 0 && (
          <section className="pipeline-section pipeline-section--reveal">
            <div className="pipeline-section-header">
              <div>
                <h3 className="section-title"><span className="section-badge section-badge--done">✓</span> 3. Vulnerability Results</h3>
                <p className="muted">Phase 3 completed — vulnerability findings below.</p>
              </div>
              {pipelinePhaseTimings.vulnScan && (
                <span className="pipeline-timing">{pipelinePhaseTimings.vulnScan}s</span>
              )}
            </div>

            <div className="summary-bar" style={{ marginBottom: 16 }}>
              <span className="summary-item"><b>{phase3Summary?.total_hosts ?? localVulnResults.length}</b> Audited</span>
              <span className="summary-item summary-item--danger"><b>{phase3Summary?.critical_hosts ?? 0}</b> Critical</span>
              <span className="summary-item summary-item--warn"><b>{phase3Summary?.high_risk_hosts ?? 0}</b> High risk</span>
              <span className="summary-item"><b>{fmtSec(phase3Summary?.scan_duration)}s</b> Duration</span>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "16px 0", flexWrap: "wrap" }}>
              <div className="filter-tabs">
                {[
                  ["active", `Active (${activeVulnHosts.length})`],
                  ["all",    `All (${localVulnResults.length})`],
                ].map(([val, lbl]) => (
                  <button
                    key={val}
                    className={`filter-tab ${filter3 === val ? "filter-tab--active" : ""}`}
                    onClick={() => setFilter3(val)}
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
                    <th>Device</th>
                    <th>Risk</th>
                    <th>Open Ports</th>
                    <th>CVEs / Active</th>
                    <th>OS</th>
                  </tr>
                </thead>
                <tbody>
                  {displayVulnHosts.map(host => {
                    const devCat  = host.snmp_device_type || host.device_category || "unknown";
                    const catMeta = DEVICE_CAT_META[devCat] || DEVICE_CAT_META.unknown;
                    const activeFindings = countActiveFindings(host);
                    return (
                      <tr key={host.ip_address} className={host.is_active ? "row--active" : "row--inactive"}>
                        <td>
                          <code className="ip-code">{host.ip_address}</code>
                          {(() => {
                            let hName = host.hostname;
                            if (!hName || hName === "Unknown") {
                              if (host.mdns_name) hName = host.mdns_name;
                              else if (host.netbios_names && host.netbios_names.length) hName = host.netbios_names[0].name;
                            }
                            return hName && hName !== "Unknown" ? <div className="muted small" style={{marginTop: 4}}>{hName}</div> : null;
                          })()}
                        </td>
                        <td>
                          {/* GAP-07: rich device category badge with icon + color */}
                          {devCat !== "unknown" ? (
                            <span title={`Classified via: ${host.device_category_signal || "unknown"}`} style={{
                              fontSize: 11,
                              background: `${catMeta.color}18`,
                              border: `1px solid ${catMeta.color}55`,
                              color: catMeta.color,
                              padding: "2px 7px",
                              borderRadius: 4,
                              fontWeight: 600,
                              whiteSpace: "nowrap",
                            }}>
                              {catMeta.icon} {catMeta.label}
                            </span>
                          ) : <span className="muted">—</span>}
                        </td>
                        <td>
                          <span style={{ color: SEV_COLOR[host.host_risk_level] || "#60a5fa", fontWeight: 700, fontSize: 12 }}>
                            {host.host_risk_level || "Info"}
                          </span>
                        </td>
                        <td>{(host.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || <span className="muted">—</span>}</td>
                        <td>
                          {/* GAP-06: CVE count + active exploit findings badge */}
                          <span style={{
                            color: (host.cves?.length ?? 0) > 0 ? SEV_COLOR.High : "var(--text-faint)",
                            fontFamily: "var(--mono)", fontSize: 12
                          }}>
                            {(host.cves || []).length}
                          </span>
                          {activeFindings > 0 && (
                            <span title="Active exploit conditions detected (Heartbleed, EternalBlue, LDAP anon, default creds, etc.)" style={{
                              marginLeft: 6,
                              fontSize: 10,
                              background: "rgba(255,77,77,0.15)",
                              color: "#ff4d4d",
                              border: "1px solid rgba(255,77,77,0.35)",
                              borderRadius: 3,
                              padding: "1px 5px",
                              fontWeight: 700,
                            }}>
                              ⚡{activeFindings} active
                            </span>
                          )}
                        </td>
                        <td>{host.os_fingerprint_full?.os || host.os_guess || <span className="muted">—</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* PIPELINE COMPLETE — View Risk Report CTA                          */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        {isDone && localVulnResults.length > 0 && (
          <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 12, marginTop: 32 }}>
            <button 
              className="btn btn--primary btn--lg" 
              onClick={proceedToReport}
              style={{
                transition: "all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1)",
              }}
              onMouseEnter={(e) => {
                e.target.style.transform = "scale(1.03)";
                e.target.style.boxShadow = "0 12px 28px rgba(13, 110, 253, 0.25)";
              }}
              onMouseLeave={(e) => {
                e.target.style.transform = "scale(1)";
                e.target.style.boxShadow = "0 4px 12px rgba(13, 110, 253, 0.15)";
              }}
              onMouseDown={(e) => {
                e.target.style.transform = "scale(0.97)";
              }}
              onMouseUp={(e) => {
                e.target.style.transform = "scale(1.03)";
              }}
            >
              📊 View Risk Report →
            </button>
          </div>
        )}

      </div>

      {/* ════════════════════════════════════════════════════════════════════════ */}
      {/* RISK REPORT MODAL                                                       */}
      {/* ════════════════════════════════════════════════════════════════════════ */}
      <Modal 
        isOpen={showReportModal} 
        onClose={() => setShowReportModal(false)}
        title="Risk Report - Full Assessment"
        subtitle={`Scan #${scanId} • Target: ${target}`}
      >
        <div style={{ maxHeight: "80vh", overflowY: "auto" }}>
          {/* Report Header */}
          <div style={{ 
            padding: "16px", 
            background: "var(--bg-app)", 
            borderRadius: "8px", 
            marginBottom: "16px", 
            border: "1px solid var(--border)" 
          }}>
            <h3 style={{ margin: 0, fontWeight: 600, marginBottom: 8 }}>✓ Full Pipeline Complete</h3>
            <p style={{ margin: 0, fontSize: "0.9rem", color: "var(--text-muted)" }}>
              All scan phases finished successfully. Complete vulnerability analysis and risk assessment below.
            </p>
          </div>

          {/* Summary Stats Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: 24 }}>
            <div style={{
              padding: "16px",
              background: "rgba(34, 197, 94, 0.05)",
              border: "1px solid rgba(34, 197, 94, 0.2)",
              borderRadius: "8px"
            }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontWeight: 500 }}>Total Hosts Audited</span>
              <p style={{ margin: "8px 0 0", fontSize: "2rem", fontWeight: 700, color: "#22c55e" }}>
                {phase3Summary?.total_hosts ?? localVulnResults.length}
              </p>
            </div>
            <div style={{
              padding: "16px",
              background: "rgba(239, 68, 68, 0.05)",
              border: "1px solid rgba(239, 68, 68, 0.2)",
              borderRadius: "8px"
            }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontWeight: 500 }}>Total CVEs Found</span>
              <p style={{ margin: "8px 0 0", fontSize: "2rem", fontWeight: 700, color: "#ef4444" }}>
                {localVulnResults.reduce((sum, h) => sum + (h.cves?.length ?? 0), 0)}
              </p>
            </div>
            <div style={{
              padding: "16px",
              background: "rgba(255, 109, 0, 0.05)",
              border: "1px solid rgba(255, 109, 0, 0.2)",
              borderRadius: "8px"
            }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontWeight: 500 }}>Critical Issues</span>
              <p style={{ margin: "8px 0 0", fontSize: "2rem", fontWeight: 700, color: "#ff6d00" }}>
                {localVulnResults.filter(h => h.host_risk_level === "Critical").length}
              </p>
            </div>
            <div style={{
              padding: "16px",
              background: "rgba(249, 115, 22, 0.05)",
              border: "1px solid rgba(249, 115, 22, 0.2)",
              borderRadius: "8px"
            }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontWeight: 500 }}>High Risk Hosts</span>
              <p style={{ margin: "8px 0 0", fontSize: "2rem", fontWeight: 700, color: "#f97316" }}>
                {localVulnResults.filter(h => h.host_risk_level === "High").length}
              </p>
            </div>
          </div>

          {/* Scan Timing */}
          <div style={{
            padding: "16px",
            background: "var(--bg-app)",
            borderRadius: "8px",
            marginBottom: "24px",
            border: "1px solid var(--border)"
          }}>
            <p style={{ margin: "0 0 12px", fontSize: "0.95rem", fontWeight: 600 }}>📊 Scan Timeline</p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, fontSize: "0.85rem" }}>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Phase 1: Discovery</span>
                <p style={{ margin: "4px 0", fontWeight: 700, fontSize: "1.1rem" }}>{fmtSec(phase1Summary?.scan_duration)}s</p>
              </div>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Phase 2: Port Scan</span>
                <p style={{ margin: "4px 0", fontWeight: 700, fontSize: "1.1rem" }}>{pipelinePhaseTimings.portScan ? fmtSec(pipelinePhaseTimings.portScan) : "—"}s</p>
              </div>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Phase 3: Vulnerability Audit</span>
                <p style={{ margin: "4px 0", fontWeight: 700, fontSize: "1.1rem" }}>{pipelinePhaseTimings.vulnScan ? fmtSec(pipelinePhaseTimings.vulnScan) : "—"}s</p>
              </div>
            </div>
          </div>

          {/* Risk Severity Breakdown */}
          <div style={{
            padding: "16px",
            background: "var(--bg-app)",
            borderRadius: "8px",
            marginBottom: "24px",
            border: "1px solid var(--border)"
          }}>
            <p style={{ margin: "0 0 12px", fontSize: "0.95rem", fontWeight: 600 }}>⚠️ Vulnerability Severity Distribution</p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, fontSize: "0.85rem" }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "#ff4d4d" }}>
                  {(() => {
                    let count = 0;
                    localVulnResults.forEach(h => {
                      (h.cves || []).forEach(cve => {
                        if ((cve.severity || "Info") === "Critical") count++;
                      });
                    });
                    return count;
                  })()}
                </div>
                <span style={{ color: "var(--text-muted)" }}>Critical</span>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "#f97316" }}>
                  {(() => {
                    let count = 0;
                    localVulnResults.forEach(h => {
                      (h.cves || []).forEach(cve => {
                        if ((cve.severity || "Info") === "High") count++;
                      });
                    });
                    return count;
                  })()}
                </div>
                <span style={{ color: "var(--text-muted)" }}>High</span>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "#f59e0b" }}>
                  {(() => {
                    let count = 0;
                    localVulnResults.forEach(h => {
                      (h.cves || []).forEach(cve => {
                        if ((cve.severity || "Info") === "Medium") count++;
                      });
                    });
                    return count;
                  })()}
                </div>
                <span style={{ color: "var(--text-muted)" }}>Medium</span>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "#22c55e" }}>
                  {(() => {
                    let count = 0;
                    localVulnResults.forEach(h => {
                      (h.cves || []).forEach(cve => {
                        if ((cve.severity || "Info") === "Low") count++;
                      });
                    });
                    return count;
                  })()}
                </div>
                <span style={{ color: "var(--text-muted)" }}>Low</span>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "#60a5fa" }}>
                  {(() => {
                    let count = 0;
                    localVulnResults.forEach(h => {
                      (h.cves || []).forEach(cve => {
                        if ((cve.severity || "Info") === "Info") count++;
                      });
                    });
                    return count;
                  })()}
                </div>
                <span style={{ color: "var(--text-muted)" }}>Info</span>
              </div>
            </div>
          </div>

          {/* Host Details Table */}
          <div>
            <p style={{ fontSize: "0.95rem", fontWeight: 600, marginBottom: 12 }}>🖥️ Affected Hosts ({localVulnResults.length} total)</p>
            <div style={{
              overflowX: "auto",
              border: "1px solid var(--border)",
              borderRadius: "8px",
              marginBottom: "24px"
            }}>
              <table style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: "0.85rem"
              }}>
                <thead>
                  <tr style={{ background: "var(--bg-app)" }}>
                    <th style={{ padding: "12px", textAlign: "left", fontWeight: 600, borderBottom: "1px solid var(--border)" }}>IP Address</th>
                    <th style={{ padding: "12px", textAlign: "left", fontWeight: 600, borderBottom: "1px solid var(--border)" }}>Status</th>
                    <th style={{ padding: "12px", textAlign: "left", fontWeight: 600, borderBottom: "1px solid var(--border)" }}>Risk</th>
                    <th style={{ padding: "12px", textAlign: "center", fontWeight: 600, borderBottom: "1px solid var(--border)" }}>Vulnerabilities</th>
                    <th style={{ padding: "12px", textAlign: "center", fontWeight: 600, borderBottom: "1px solid var(--border)" }}>Open Ports</th>
                    <th style={{ padding: "12px", textAlign: "left", fontWeight: 600, borderBottom: "1px solid var(--border)" }}>OS</th>
                  </tr>
                </thead>
                <tbody>
                  {localVulnResults.map((host, idx) => (
                    <tr key={host.ip_address} style={{ borderBottom: idx < localVulnResults.length - 1 ? "1px solid var(--border)" : "none" }}>
                      <td style={{ padding: "12px" }}>
                        <code style={{ fontFamily: "var(--mono)", fontSize: "0.8rem", fontWeight: 600 }}>{host.ip_address}</code>
                      </td>
                      <td style={{ padding: "12px" }}>
                        <span style={{ 
                          display: "inline-block",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          fontSize: "0.75rem",
                          fontWeight: 600,
                          background: host.is_active ? "rgba(34, 197, 94, 0.1)" : "rgba(107, 114, 128, 0.1)",
                          color: host.is_active ? "#22c55e" : "#6b7280"
                        }}>
                          {host.is_active ? "✓ Active" : "○ Inactive"}
                        </span>
                      </td>
                      <td style={{ padding: "12px" }}>
                        <span style={{ color: SEV_COLOR[host.host_risk_level] || "#60a5fa", fontWeight: 700, fontSize: "0.85rem" }}>
                          {host.host_risk_level || "Info"}
                        </span>
                      </td>
                      <td style={{ padding: "12px", textAlign: "center", fontWeight: 700 }}>
                        {host.cves?.length ?? 0}
                      </td>
                      <td style={{ padding: "12px", textAlign: "center", fontSize: "0.8rem" }}>
                        {(host.open_ports || []).length > 0 ? `${(host.open_ports || []).length}` : "—"}
                      </td>
                      <td style={{ padding: "12px", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                        {host.os_guess || "Unknown"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Vulnerability Details by Host */}
          <div>
            <p style={{ fontSize: "0.95rem", fontWeight: 600, marginBottom: 12 }}>🔍 Detailed Vulnerability Analysis</p>
            {localVulnResults.filter(h => (h.cves?.length ?? 0) > 0).map((host) => (
              <div key={host.ip_address} style={{
                marginBottom: "16px",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                overflow: "hidden"
              }}>
                {/* Host Header */}
                <div style={{
                  padding: "12px",
                  background: "var(--bg-app)",
                  borderBottom: "1px solid var(--border)",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center"
                }}>
                  <div>
                    <code style={{ fontFamily: "var(--mono)", fontSize: "0.9rem", fontWeight: 700 }}>{host.ip_address}</code>
                    <span style={{ marginLeft: "12px", color: "var(--text-muted)", fontSize: "0.85rem" }}>
                      {host.hostname || "Unknown"}
                    </span>
                  </div>
                  <span style={{ 
                    color: SEV_COLOR[host.host_risk_level] || "#60a5fa", 
                    fontWeight: 700,
                    fontSize: "0.9rem"
                  }}>
                    {host.host_risk_level} Risk
                  </span>
                </div>

                {/* CVEs List */}
                <div style={{ padding: "12px" }}>
                  {(host.cves || []).map((cve, idx) => (
                    <div key={idx} style={{
                      marginBottom: idx < (host.cves?.length ?? 0) - 1 ? "12px" : 0,
                      paddingBottom: idx < (host.cves?.length ?? 0) - 1 ? "12px" : 0,
                      borderBottom: idx < (host.cves?.length ?? 0) - 1 ? "1px solid var(--border)" : "none"
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
                        <code style={{ 
                          fontFamily: "var(--mono)", 
                          fontSize: "0.85rem", 
                          fontWeight: 700,
                          color: "#2563eb"
                        }}>
                          {cve.cve_id || "Unknown CVE"}
                        </code>
                        <span style={{
                          display: "inline-block",
                          padding: "4px 10px",
                          borderRadius: "4px",
                          fontSize: "0.75rem",
                          fontWeight: 600,
                          color: "#fff",
                          background: SEV_COLOR[cve.severity || "Info"] || "#60a5fa"
                        }}>
                          {cve.severity || "Info"}
                        </span>
                      </div>
                      
                      {cve.cvss_score && (
                        <div style={{ marginBottom: 6 }}>
                          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                            CVSS Score: <strong>{Number(cve.cvss_score || cve.cvss || 0).toFixed(1)}</strong>/10
                          </span>
                        </div>
                      )}

                      {cve.description && (
                        <p style={{
                          margin: "6px 0",
                          fontSize: "0.8rem",
                          color: "var(--text-mid)",
                          lineHeight: 1.4
                        }}>
                          {cve.description || cve.desc || "No description available"}
                        </p>
                      )}

                      {cve.affected_software && (
                        <div style={{ marginTop: 6 }}>
                          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                            <strong>Affected:</strong> {cve.affected_software}
                          </span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {localVulnResults.filter(h => (h.cves?.length ?? 0) > 0).length === 0 && (
              <div style={{
                padding: "24px",
                textAlign: "center",
                color: "var(--text-muted)"
              }}>
                <p>No vulnerabilities found in this scan.</p>
              </div>
            )}
          </div>

          {/* Statistics Summary */}
          <div style={{
            marginTop: "24px",
            padding: "16px",
            background: "rgba(59, 130, 246, 0.05)",
            border: "1px solid rgba(59, 130, 246, 0.2)",
            borderRadius: "8px",
            fontSize: "0.85rem"
          }}>
            <p style={{ margin: "0 0 8px", fontWeight: 600 }}>📈 Report Summary</p>
            <ul style={{ margin: 0, paddingLeft: "20px", color: "var(--text-mid)" }}>
              <li>Total hosts scanned: {phase3Summary?.total_hosts ?? localVulnResults.length}</li>
              <li>Hosts with vulnerabilities: {localVulnResults.filter(h => (h.cves?.length ?? 0) > 0).length}</li>
              <li>Total CVEs identified: {localVulnResults.reduce((sum, h) => sum + (h.cves?.length ?? 0), 0)}</li>
              <li>Critical severity: {(() => { let c = 0; localVulnResults.forEach(h => { (h.cves || []).forEach(cv => { if ((cv.severity || "Info") === "Critical") c++; }); }); return c; })()}</li>
              <li>High severity: {(() => { let c = 0; localVulnResults.forEach(h => { (h.cves || []).forEach(cv => { if ((cv.severity || "Info") === "High") c++; }); }); return c; })()}</li>
              <li>Scan completed at: {new Date().toLocaleString()}</li>
            </ul>
          </div>

          {/* Export Hint */}
          <div style={{
            marginTop: "16px",
            padding: "12px",
            background: "rgba(34, 197, 94, 0.05)",
            border: "1px solid rgba(34, 197, 94, 0.2)",
            borderRadius: "6px",
            fontSize: "0.85rem",
            color: "var(--text-muted)"
          }}>
            📄 <strong>Tip:</strong> Close this modal and navigate to Scan History to export full PDF/XML reports with additional formatting and charts.
          </div>
        </div>
      </Modal>
    </AppLayout>
  );
}
