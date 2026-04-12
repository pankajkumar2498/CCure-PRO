/**
 * src/pages/scan/Phase3Results.jsx  [FIXED]
 *
 * ROOT-CAUSE FIXES:
 *  1. Render-time navigate() removed → replaced with useEffect guard.
 *  2. pipelineMode is now read from context. For advanced scan, a
 *     "Proceed to Risk Report →" CTA is shown after the audit runs.
 *  3. Audit results (data.data) are saved to `setPhase3AuditResults`
 *     in context so Phase4Results can access them without prop-drilling.
 */
import { useState, useEffect } from "react";
import { useNavigate }          from "react-router-dom";
import AppLayout                from "../../components/layout/AppLayout";
import ScanStepper              from "../../components/layout/ScanStepper";
import RiskBadge                from "../../components/scan/RiskBadge";
import { useScan }              from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";
import api                      from "../../api/axiosInstance";

const SEV_COLOR = {
  Critical: "#ff4d4d",
  High:     "#f97316",
  Medium:   "#f59e0b",
  Low:      "#22c55e",
  Info:     "#60a5fa",
};

function normalizeCve(cve) {
  const cvss = Number(cve.cvss_score ?? cve.cvss ?? 0) || 0;
  const severity = cve.severity || (
    cvss >= 9 ? "Critical" : cvss >= 7 ? "High" : cvss >= 4 ? "Medium" : cvss > 0 ? "Low" : "Info"
  );
  return {
    cve_id:      cve.cve_id || cve.cve || "Unknown",
    severity,
    cvss_score:  cvss,
    description: cve.description || cve.desc || "",
  };
}

function KV({ k, v, danger, warn }) {
  return (
    <div className="kv-row">
      <span className="kv-key">{k}</span>
      <span className="kv-val" style={danger ? { color: "#ff4d4d" } : warn ? { color: "#f59e0b" } : {}}>
        {v}
      </span>
    </div>
  );
}

function AuditSection({ title, children }) {
  return (
    <div className="audit-section">
      <h4 className="section-title">{title}</h4>
      {children}
    </div>
  );
}

export default function Phase3Results() {
  const navigate = useNavigate();
  const {
    phase1Hosts, phase1Summary,
    phase2Results, phase2Summary,
    phase3AuditResults, phase3Summary,
    scanId, target,
    setPhase2Results, setPhase2Summary,
    setPhase3Summary, setPhase3AuditResults,
    pipelineMode,
    saveStatus, setSaveStatus,
    resetScan,
  } = useScan();

  const [intensity,    setIntensity]    = useState("normal");
  const [phase2Loading, setPhase2Loading] = useState(false);
  const [phase3Loading, setPhase3Loading] = useState(false);
  const [phase2Error,  setPhase2Error]  = useState("");
  const [phase3Error,  setPhase3Error]  = useState("");
  const [expanded,     setExpanded]     = useState(new Set());
  const [portHosts,    setPortHosts]    = useState(() => phase2Results || []);
  const [vulnResults,  setVulnResults]  = useState(() => phase3AuditResults || []);
  const [pipelineAttempted, setPipelineAttempted] = useState(false);

  const safePhase1Hosts = Array.isArray(phase1Hosts) ? phase1Hosts : [];

  useEffect(() => {
    if (!safePhase1Hosts.length) {
      navigate("/scan", { replace: true });
    }
  }, [safePhase1Hosts.length, navigate]);

  useEffect(() => {
    setPortHosts(phase2Results || []);
  }, [phase2Results]);

  useEffect(() => {
    setVulnResults(phase3AuditResults || []);
  }, [phase3AuditResults]);

  if (!safePhase1Hosts.length) return null;
  const safePortHosts = Array.isArray(portHosts) ? portHosts : [];
  const safeVulnResults = Array.isArray(vulnResults) ? vulnResults : [];
  const activeDiscoveryHosts = safePhase1Hosts.filter(h => h.is_active);
  const activePortResults    = safePortHosts.filter(h => h.is_active);
  const currentStep = safeVulnResults.length ? 3 : safePortHosts.length ? 2 : 1;
  const apiError = phase2Error || phase3Error;
  const apiErrorStage = phase2Error ? "Phase 2" : phase3Error ? "Phase 3" : "";

  const formatSeconds = (value) => {
    if (typeof value === "number") return value.toFixed(1);
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed.toFixed(1) : "—";
  };

  const runAdvancedPipeline = async () => {
    const safeArray = (value) => Array.isArray(value) ? value : [];

    if (!activeDiscoveryHosts.length) {
      setPhase2Error("No active hosts were discovered for Advanced Scan.");
      return;
    }

    setPhase2Error("");
    setPhase3Error("");
    setPipelineAttempted(true);
    setPhase2Loading(true);
    setPhase3Loading(false);
    setSaveStatus("saving");

    try {
      const { data: assetData } = await api.post("/scan/asset-discovery", {
        hosts:         activeDiscoveryHosts,
        intensity,
        scan_id:       scanId,
        pipeline_mode: pipelineMode,
        phases:        [1, 2],
      });
      if (!assetData.success) throw new Error(assetData.error || "Port scan failed");

      const assetHosts = safeArray(assetData.data);
      if (!assetHosts.length) {
        throw new Error("Port scan completed successfully but returned no hosts.");
      }
      setPhase2Results(assetHosts);
      setPhase2Summary(assetData.summary || null);
      setPortHosts(assetHosts);
      setPhase2Loading(false);

      setPhase3Loading(true);
      const { data: auditData } = await api.post("/scan/advanced-scan", {
        hosts:         assetHosts,
        scan_id:       scanId,
        pipeline_mode: pipelineMode,
        phases:        [1, 2, 3, 4],
      });
      if (!auditData.success) throw new Error(auditData.error || "Vulnerability audit failed");

      const auditHosts = safeArray(auditData.data);
      if (!auditHosts.length) {
        throw new Error("Vulnerability audit completed successfully but returned no hosts.");
      }
      setPhase3Summary(auditData.summary || null);
      setPhase3AuditResults(auditHosts);
      setVulnResults(auditHosts);
      setExpanded(new Set(auditHosts.filter(h => h.is_active).map(h => h.ip_address)));
      setPhase3Loading(false);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 4000);
    } catch (err) {
      const detail = err.response?.data?.detail || err.message || "Advanced scan failed";
      if (phase2Loading) {
        setPhase2Error(detail);
      } else {
        setPhase3Error(detail);
      }
      setPhase2Loading(false);
      setPhase3Loading(false);
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    }
  };

  const toggleExpand = (ip) => {
    const next = new Set(expanded);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setExpanded(next);
  };

  const proceedToPhase4 = () => {
    navigate("/scan/phase4");
  };

  return (
    <AppLayout pageTitle="Advanced Scan" saveStatus={saveStatus}>
      <ScanStepper current={currentStep} />

      <div className="page-inner">

        <div className="page-title-row">
          <div>
            <h2 className="page-title">Advanced Scan</h2>
            <p className="page-subtitle">
              Full pipeline execution from <code className="ip-code">{target}</code>
            </p>
          </div>
          <button className="btn btn--ghost" onClick={() => navigate("/scan")}>← Back</button>
        </div>

        <div className="summary-bar" style={{ marginBottom: 16 }}>
          <span className="summary-item"><b>{phase1Summary?.total_hosts ?? safePhase1Hosts.length}</b> Total discovered</span>
          <span className="summary-item summary-item--active"><b>{phase1Summary?.active_hosts ?? activeDiscoveryHosts.length}</b> Active</span>
          <span className="summary-item"><b>{phase1Summary?.inactive_hosts ?? safePhase1Hosts.length - activeDiscoveryHosts.length}</b> Inactive</span>
          <span className="summary-item"><b>{formatSeconds(phase1Summary?.scan_duration)}s</b> Discovery time</span>
        </div>

        {apiError && (
          <div className="alert alert--error" style={{ marginBottom: 24 }}>
            <strong>{apiErrorStage} error:</strong> {apiError}
          </div>
        )}

        {pipelineAttempted && !phase2Loading && !phase3Loading && !apiError && !safePortHosts.length && !safeVulnResults.length && (
          <div className="alert alert--warn" style={{ marginBottom: 24 }}>
            <strong>Advanced Scan completed but returned no valid host data.</strong>
            <div>Please retry the scan or check the backend logs for an unexpected response payload.</div>
          </div>
        )}

        <section style={{ marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
            <div>
              <h3 className="section-title">1. Discovery Results</h3>
              <p className="muted">Live hosts detected during Phase 1.</p>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="muted" style={{ fontSize: 12 }}>Scan intensity</span>
              {["light", "normal", "deep"].map(level => (
                <button
                  key={level}
                  className={`filter-tab ${intensity === level ? "filter-tab--active" : ""}`}
                  onClick={() => setIntensity(level)}
                  disabled={phase2Loading || phase3Loading}
                >
                  {level}
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
                {safePhase1Hosts.map(host => (
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

          <div className="phase-footer" style={{ marginTop: 16, justifyContent: "space-between" }}>
            <div>
              <p className="muted" style={{ fontSize: 13, marginBottom: 6 }}>
                Phase 1 complete. Advanced pipeline will continue with Port Scan and Vulnerability Audit.
              </p>
              {phase2Error && <div className="alert alert--error">⚠ {phase2Error}</div>}
            </div>
            {!phase2Loading && !phase3Loading && (
              <button className="btn btn--primary" onClick={runAdvancedPipeline}>
                {safePortHosts.length ? "▶ Continue Vulnerability Audit" : "▶ Continue Advanced Scan"}
              </button>
            )}
          </div>
        </section>

        {phase2Loading && (
          <div className="progress-wrap" style={{ marginBottom: 24 }}>
            <div className="progress-bar"><div className="progress-fill" /></div>
            <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>
              Running Port Scan (Phase 2)…
            </p>
          </div>
        )}

        {safePortHosts.length > 0 && (
          <section style={{ marginBottom: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
              <div>
                <h3 className="section-title">2. Port Scan Results</h3>
                <p className="muted">Open services discovered during Phase 2.</p>
              </div>
            </div>

            <div className="summary-bar" style={{ marginBottom: 16 }}>
              <span className="summary-item"><b>{phase2Summary?.total_hosts ?? safePortHosts.length}</b> Hosts scanned</span>
              <span className="summary-item summary-item--active"><b>{phase2Summary?.hosts_with_ports ?? safePortHosts.filter(h => h.open_ports?.length).length}</b> Have open ports</span>
              <span className="summary-item"><b>{formatSeconds(phase2Summary?.scan_duration)}s</b> Duration</span>
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
                  {safePortHosts.map(host => (
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

        {phase3Loading && (
          <div className="progress-wrap" style={{ marginBottom: 24 }}>
            <div className="progress-bar"><div className="progress-fill" /></div>
            <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>
              Running Vulnerability Audit (Phase 3)…
            </p>
          </div>
        )}

        {phase3Error && <div className="alert alert--error" style={{ marginBottom: 24 }}>⚠ {phase3Error}</div>}

        {safeVulnResults.length > 0 && (
          <section style={{ marginBottom: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
              <div>
                <h3 className="section-title">3. Vulnerability Results</h3>
                <p className="muted">Phase 3 completed — review findings before generating the final report.</p>
              </div>
            </div>

            <div className="summary-bar" style={{ marginBottom: 16 }}>
              <span className="summary-item"><b>{phase3Summary?.total_hosts ?? safeVulnResults.length}</b> Audited</span>
              <span className="summary-item summary-item--danger"><b>{phase3Summary?.critical_hosts ?? 0}</b> Critical</span>
              <span className="summary-item summary-item--warn"><b>{phase3Summary?.high_risk_hosts ?? 0}</b> High risk</span>
              <span className="summary-item"><b>{formatSeconds(phase3Summary?.scan_duration)}s</b> Duration</span>
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
                  {safeVulnResults.map(host => (
                    <tr key={host.ip_address} className={host.is_active ? "row--active" : "row--inactive"}>
                      <td><code className="ip-code">{host.ip_address}</code></td>
                      <td>{host.host_risk_level || "Info"}</td>
                      <td>{(host.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || <span className="muted">—</span>}</td>
                      <td>{(host.cves || []).length}</td>
                      <td>{host.os_guess || <span className="muted">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="phase-footer" style={{ marginTop: 16, justifyContent: "space-between" }}>
              <p className="muted" style={{ fontSize: 13 }}>
                Phase 3 complete. Proceed to the final Risk Report for export and review.
              </p>
              <button className="btn btn--primary" onClick={proceedToPhase4}>
                View Risk Report →
              </button>
            </div>
          </section>
        )}
      </div>
    </AppLayout>
  );
}
