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
    setPipelineState(PIPELINE_STATES.COMPLETE);
    navigate("/scan/phase4");
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
                  <th>Status</th>
                  <th>Method</th>
                  <th>MAC</th>
                  <th>Vendor</th>
                </tr>
              </thead>
              <tbody>
                {displayDiscoveryHosts.map(host => (
                  <tr key={host.ip_address} className={host.is_active ? "row--active" : "row--inactive"}>
                    <td><code className="ip-code">{host.ip_address}</code></td>
                    <td>{host.hostname || <span className="muted">—</span>}</td>
                    <td>
                      <span className={`status-dot ${host.is_active ? "status-dot--up" : "status-dot--down"}`} />
                      {host.is_active ? "Active" : "Inactive"}
                    </td>
                    <td>{host.discovery_method || <span className="muted">—</span>}</td>
                    <td>{host.mac_address || <span className="muted">—</span>}</td>
                    <td>{host.vendor || <span className="muted">—</span>}</td>
                  </tr>
                ))}
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
                    <th>Open Ports</th>
                    <th>Vendor</th>
                    <th>OS</th>
                  </tr>
                </thead>
                <tbody>
                  {displayPortHosts.map(host => (
                    <tr key={host.ip_address} className={host.is_active ? "row--active" : "row--inactive"}>
                      <td><code className="ip-code">{host.ip_address}</code></td>
                      <td>{host.hostname || <span className="muted">—</span>}</td>
                      <td>{(host.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || <span className="muted">—</span>}</td>
                      <td>{host.vendor || <span className="muted">—</span>}</td>
                      <td>{host.os_guess || <span className="muted">—</span>}</td>
                    </tr>
                  ))}
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
                    <th>Risk</th>
                    <th>Open Ports</th>
                    <th>CVEs</th>
                    <th>OS</th>
                  </tr>
                </thead>
                <tbody>
                  {displayVulnHosts.map(host => (
                    <tr key={host.ip_address} className={host.is_active ? "row--active" : "row--inactive"}>
                      <td><code className="ip-code">{host.ip_address}</code></td>
                      <td>
                        <span style={{ color: SEV_COLOR[host.host_risk_level] || "#60a5fa", fontWeight: 700, fontSize: 12 }}>
                          {host.host_risk_level || "Info"}
                        </span>
                      </td>
                      <td>{(host.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || <span className="muted">—</span>}</td>
                      <td>
                        <span style={{
                          color: (host.cves?.length ?? 0) > 0 ? SEV_COLOR.High : "var(--text-faint)",
                          fontFamily: "var(--mono)", fontSize: 12
                        }}>
                          {(host.cves || []).length}
                        </span>
                      </td>
                      <td>{host.os_guess || <span className="muted">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* ══════════════════════════════════════════════════════════════════ */}
        {/* PIPELINE COMPLETE — View Risk Report CTA                          */}
        {/* ══════════════════════════════════════════════════════════════════ */}
        {isDone && localVulnResults.length > 0 && (
          <div className="pipeline-complete-card">
            <div className="pipeline-complete-left">
              <span className="pipeline-complete-icon">✓</span>
              <div>
                <h3 className="pipeline-complete-title">Pipeline Complete</h3>
                <p className="pipeline-complete-desc">
                  All scan phases finished successfully. View the full Risk Report for detailed analysis and export options.
                </p>
              </div>
            </div>
            <button className="btn btn--primary btn--lg" onClick={proceedToReport}>
              View Risk Report →
            </button>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
