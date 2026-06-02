/**
 * src/pages/scan/Phase2Results.jsx
 *
 * Updated flow: host selection + intensity selection happen on the same Port Scan page.
 * The page now directly executes Asset Discovery when the user clicks Run Port Scan,
 * and shows final Phase 2 results in-place after completion.
 */
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import ScanStepper from "../../components/layout/ScanStepper";
import ExportPanel from "../../components/scan/ExportPanel";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";
import api from "../../api/axiosInstance";
import { stopScan } from "../../api/scans";
import { useAuth } from "../../context/AuthContext";
import { can, denyMessage } from "../../auth/permissions";

const INTENSITIES = ["light", "normal", "deep"];
const VULN_PROFILES = [
  { value: "recommended", label: "Recommended", desc: "Service-aware checks for discovered open ports" },
  { value: "conservative", label: "Conservative", desc: "Lower-impact checks for fragile or OT systems" },
  { value: "deep", label: "Deep", desc: "Broader audit scope for approved maintenance windows" },
];

const RISK_COLOR = {
  Critical: "#ff4d4d",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#22c55e",
  Info: "#60a5fa",
};

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

const hasDetectedServices = (host) =>
  (host?.open_ports?.length || 0) > 0 || (host?.udp_services?.length || 0) > 0;

export default function Phase2Results() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const canExecuteScans = can(user, "scans", "execute");
  const {
    phase1Hosts,
    phase2Results,
    phase2Summary,
    scanId,
    scanNo,
    target,
    pipelineMode,
    saveStatus,
    intensity,
    setIntensity,
    setSaveStatus,
    setPhase2Hosts,
    setPhase2Summary,
    setPhase2Results,
    setPhase3Results,
    setPipelineState,
  } = useScan();
  const [filter, setFilter] = useState("active");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selected, setSelected] = useState(() => new Set(phase1Hosts.filter(h => h.is_active).map(h => h.ip_address)));
  const [vulnProfile, setVulnProfile] = useState("recommended");
  const [expanded, setExpanded] = useState(new Set());
  const [error, setError] = useState("");
  const [hasScanned, setHasScanned] = useState(false);

  useEffect(() => {
    if (phase2Results.length) {
      setResults(phase2Results);
      setHasScanned(true);
      setSelected(new Set(phase2Results.filter(hasDetectedServices).map(h => h.ip_address)));
    }
    if (phase2Summary) {
      setSummary(phase2Summary);
    }
  }, [phase2Results, phase2Summary]);

  useEffect(() => {
    if (!phase1Hosts.length) {
      navigate("/scan/host-discovery", { replace: true });
    }
  }, [phase1Hosts.length, navigate]);

  useEffect(() => {
    if (!hasScanned) {
      setSelected(new Set(phase1Hosts.filter(h => h.is_active).map(h => h.ip_address)));
    }
  }, [phase1Hosts, hasScanned]);

  const discoveredHosts = phase1Hosts;
  const activeHosts = discoveredHosts.filter(h => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : discoveredHosts;
  const selectedHosts = discoveredHosts.filter(h => selected.has(h.ip_address) && h.is_active);
  const selectedCount = selectedHosts.length;

  const canProceedToPhase3 = isPhaseEnabled(pipelineMode, 3);
  const nextPhase = getNextPhase(pipelineMode, 2);

  const toggleHost = (ip) => {
    if (!activeHosts.some(h => h.ip_address === ip)) return;
    const next = new Set(selected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setSelected(next);
  };

  const toggleAll = () => {
    const next = selectedCount === activeHosts.length
      ? new Set()
      : new Set(activeHosts.map(h => h.ip_address));
    setSelected(next);
  };

  const [scanProgress, setScanProgress] = useState(null);
  const baseURL = api.defaults.baseURL || "";
  const wsPrefix = baseURL.replace(/^http/, "ws");
  const buildScanProgressUrl = (scanId, ticket) => {
    return `${wsPrefix}/scans/${scanId}/progress?ticket=${encodeURIComponent(ticket)}`;
  };

  const waitForPhase = async (scanId, phase) => {
    const { data } = await api.post("/auth/ticket");
    const ticket = data.ticket;

    return new Promise((resolve, reject) => {
      const ws = new WebSocket(buildScanProgressUrl(scanId, ticket));
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.phase === phase) {
          setScanProgress(data.progress);
          if (data.progress?.status === "complete" || data.progress?.status === "failed") {
            ws.close();
            resolve(data.progress);
          }
        }
      };
      ws.onerror = () => {
        ws.close();
        reject(new Error(`Phase ${phase} WebSocket failed`));
      };
      setTimeout(() => {
        ws.close();
        reject(new Error(`Phase ${phase} timed out`));
      }, 600000); // 10 mins
    });
  };

  const runScan = async () => {
    if (!canExecuteScans) {
      setError(denyMessage);
      return;
    }
    if (!selectedCount) {
      setError("Select at least one active host before running Port Scan.");
      return;
    }
    if (!intensity) {
      setError("Choose a scan intensity before running Port Scan.");
      return;
    }

    const payloadHosts = discoveredHosts.filter(h => selected.has(h.ip_address));
    setPhase2Hosts(payloadHosts);

    setLoading(true);
    setError("");
    setResults([]);
    setSummary(null);
    setHasScanned(false);
    setExpanded(new Set());
    setSaveStatus("saving");

    try {
      const { data } = await api.post("/scan/asset-discovery", {
        hosts: payloadHosts,
        intensity,
        scan_id: scanId,
        pipeline_mode: pipelineMode,
        phases: [1, 2],
      });

      if (!data.success) throw new Error(data.error || "Phase 2 trigger failed");

      const pResult = await waitForPhase(scanId, 2);
      if (pResult?.status === "failed") {
         throw new Error("Phase 2 background task failed.");
      }

      const { data: fullScan } = await api.get(`/scans/${scanId}`);
      
      setResults(fullScan?.results?.phase2?.data || []);
      setSummary(fullScan?.results?.phase2?.summary || {});
      setPhase2Summary(fullScan?.results?.phase2?.summary || {});
      setPhase2Results(fullScan?.results?.phase2?.data || []);
      setSelected(new Set((fullScan?.results?.phase2?.data || []).filter(hasDetectedServices).map(h => h.ip_address)));
      setHasScanned(true);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Phase 2 failed");
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setLoading(false);
      setScanProgress(null);
    }
  };

  const handleCancel = async () => {
    if (loading && scanId) {
      try {
        await stopScan(scanId);
      } catch (err) {
        console.error("Failed to stop scan in backend:", err);
      }
    }
    setLoading(false);
    setScanProgress(null);
    setError("Scan cancelled by user.");
  };

  const toggleExpand = (ip) => {
    const next = new Set(expanded);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setExpanded(next);
  };

  const proceedToNextPhase = () => {
    if (!canExecuteScans) {
      setError(denyMessage);
      return;
    }
    if (!canProceedToPhase3 || !nextPhase) return;
    if (!selectedCount) {
      setError("Select at least one host with approved scope before running Vulnerability Audit.");
      return;
    }
    setPhase3Results(results.filter(h => selected.has(h.ip_address)));
    setPipelineState(PIPELINE_STATES.IDLE);
    navigate(nextPhase.route, {
      state: {
        vulnerabilityProfile: vulnProfile,
        startPhase: "VULN_SCAN",
      },
    });
  };

  const activeResults = results.filter(h => h.is_active);

  if (!phase1Hosts.length) return null;

  return (
    <AppLayout pageTitle="Port Scan" saveStatus={saveStatus}>
      <ScanStepper current={2} />

      <div className="page-inner">

        <div className="page-title-row">
          <div>
            <h2 className="page-title">Port Scan</h2>
            <p className="page-subtitle">
              Choose hosts and intensity, then run port scanning directly.
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)" }}>Intensity</span>
              <div className="filter-tabs">
                {INTENSITIES.map(i => (
                  <button
                    key={i}
                    className={`filter-tab ${intensity === i ? "filter-tab--active" : ""}`}
                    onClick={() => setIntensity(i)}
                    disabled={loading || !canExecuteScans}
                  >
                    {i}
                  </button>
                ))}
              </div>
            </div>

            <button className="btn btn--ghost" onClick={() => navigate("/scan/host-discovery")}>← Back</button>

            {loading && (
              <button className="btn btn--cancel" onClick={handleCancel}>
                ✕ Cancel Scan
              </button>
            )}

            {!hasScanned && (
              <button className="btn btn--primary" onClick={runScan} disabled={loading || selectedCount === 0 || !intensity || !canExecuteScans}>
                {loading ? <><span className="btn-spinner" /> Scanning…</> : "▶ Run Port Scan"}
              </button>
            )}
          </div>
        </div>

        {/* PHASE 4: Unreachable Banner */}
        {((!summary && activeHosts.length === 0 && discoveredHosts.length > 0) || (summary && (summary.status === "unreachable" || (Number(summary.active_hosts) === 0 && Number(summary.total_hosts) > 0)))) && (
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

        <div className="summary-bar" style={{ marginTop: 16 }}>
          <span className="summary-item"><b>{activeHosts.length}</b> Active hosts available</span>
          <span className="summary-item"><b>{selectedCount}</b> selected</span>
          <span className="summary-item"><b>{intensity || "Choose"}</b> intensity</span>
          <span className="summary-item"><b>{filter === "active" ? activeHosts.length : discoveredHosts.length}</b> shown</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "16px 0", flexWrap: "wrap" }}>
          <div className="filter-tabs">
            {[
              ["active", `Active (${activeHosts.length})`],
              ["all", `All (${discoveredHosts.length})`],
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
          <button className="btn btn--ghost btn--sm" onClick={toggleAll} disabled={loading || !activeHosts.length || !canExecuteScans}>
            {selectedCount === activeHosts.length ? "Deselect all" : "Select all active"}
          </button>
        </div>

        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                <th style={{ width: 36 }} />
                <th>IP Address</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>Vendor</th>
                <th>Method</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {displayHosts.map(host => {
                let displayHost = host.hostname;
                if (!displayHost || displayHost === "Unknown") {
                  if (host.mdns_name) displayHost = host.mdns_name;
                  else if (host.netbios_names && host.netbios_names.length) displayHost = host.netbios_names[0]?.name;
                }

                return (
                  <tr
                    key={host.ip_address}
                    className={host.is_active ? "row--active" : "row--inactive"}
                    onClick={() => host.is_active && toggleHost(host.ip_address)}
                    style={{ cursor: host.is_active ? "pointer" : "default" }}
                  >
                    <td>
                      {host.is_active && (
                        <input
                          type="checkbox"
                          checked={selected.has(host.ip_address)}
                          onChange={() => toggleHost(host.ip_address)}
                          onClick={e => e.stopPropagation()}
                        />
                      )}
                    </td>
                    <td><code className="ip-code">{host.ip_address}</code></td>
                    <td>{textValue(displayHost, <span className="muted">—</span>)}</td>
                    <td>{textValue(host.mac_address, <span className="muted">—</span>)}</td>
                    <td>{textValue(host.vendor, <span className="muted">—</span>)}</td>
                    <td>{textValue(host.discovery_method, <span className="muted">—</span>)}</td>
                    <td>
                      <span className={`status-dot ${host.is_active ? "status-dot--up" : "status-dot--down"}`} />
                      {host.is_active ? "Active" : "Inactive"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {summary && (
          <div className="summary-bar" style={{ marginTop: 16 }}>
            <span className="summary-item"><b>{summary.total_hosts}</b> Hosts scanned</span>
            <span className="summary-item summary-item--active"><b>{summary.hosts_with_ports}</b> Have open ports</span>
            <span className="summary-item"><b>{fmtNumber(summary.scan_duration)}s</b> Duration</span>
            <span className="summary-item summary-item--sel"><b>{selectedCount}</b> selected</span>
          </div>
        )}

        {loading && (
          <div className="progress-wrap">
            <div className="progress-bar"><div className="progress-fill" /></div>
            <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>
              Probing TCP services — takes 5–30 seconds depending on intensity…
            </p>
          </div>
        )}

        {error && <div className="alert alert--error">⚠ {error}</div>}

        {hasScanned && !canProceedToPhase3 && (
          <div className="alert alert--info" style={{ marginBottom: 16 }}>
            ℹ Asset Discovery complete. Port Scanning is the final phase for this scan type.
          </div>
        )}

        {hasScanned && activeResults.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon">🔍</span>
            <p className="empty-state-title">No active hosts returned open ports</p>
          </div>
        )}

        {activeResults.map(host => {
          const portCount = host.open_ports?.length || 0;
          const critPorts = host.open_ports?.filter(p => p.risk === "Critical").length || 0;
          const isExpanded = expanded.has(host.ip_address);
          const isSelected = selected.has(host.ip_address);

          return (
            <div key={host.ip_address} className={`host-card ${isSelected ? "host-card--selected" : ""}`}>
              <div className="host-card-header" onClick={() => toggleHost(host.ip_address)}>
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => toggleHost(host.ip_address)}
                  onClick={e => e.stopPropagation()}
                />

                <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <code className="ip-code" style={{ fontSize: "0.9rem", fontWeight: 700 }}>{host.ip_address}</code>
                  {(() => {
                    let hName = host.hostname;
                    if (!hName || hName === "Unknown") {
                      if (host.mdns_name) hName = host.mdns_name;
                      else if (host.netbios_names && host.netbios_names.length) hName = host.netbios_names[0]?.name;
                    }
                    const safeName = textValue(hName, "");
                    return safeName ? <span className="muted small">{safeName}</span> : null;
                  })()}
                </div>

                <div className="host-card-meta">
                  {portCount > 0
                    ? <span style={{ fontFamily: "var(--mono)", fontSize: 12, background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 8px", borderRadius: 4 }}>
                      {portCount} port{portCount !== 1 ? "s" : ""}
                    </span>
                    : <span className="muted small">No open ports</span>}

                  {critPorts > 0 && (
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "#ff4d4d", background: "rgba(255,77,77,.1)", border: "1px solid rgba(255,77,77,.25)", borderRadius: 3, padding: "2px 7px" }}>
                      {critPorts} Critical
                    </span>
                  )}

                  {host.os_guess && host.os_guess !== "Unknown" && (
                    <span style={{ fontSize: 11, color: "var(--text-muted)", background: "var(--bg-app)", border: "1px solid var(--border)", padding: "2px 8px", borderRadius: 4 }}>
                      {textValue(host.os_guess)}
                    </span>
                  )}
                </div>

                <button
                  className="expand-btn"
                  onClick={e => { e.stopPropagation(); toggleExpand(host.ip_address); }}
                >
                  {isExpanded ? "▲" : "▼"}
                </button>
              </div>

              {isExpanded && (
                <div className="host-card-body">
                  <div style={{ padding: "0 0 16px 0", display: "flex", gap: "24px", flexWrap: "wrap" }}>
                    {/* Detailed OS Fingerprint */}
                    {(host.os_fingerprint_full?.os || (host.os_guess && host.os_guess !== "Unknown")) && (
                      <div style={{ flex: "1 1 250px" }}>
                        <h4 style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>Target OS Fingerprint</h4>
                        <div style={{ background: "var(--bg-highlight)", padding: 12, borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.85rem" }}>
                          {host.os_fingerprint_full?.os ? (
                            <>
                              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                                <span className="muted">OS Guess:</span>
                                <strong>{textValue(host.os_fingerprint_full.os)}</strong>
                              </div>
                              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                                <span className="muted">Confidence:</span>
                                <span style={{
                                  color: host.os_fingerprint_full.confidence === "High" ? "#22c55e" : host.os_fingerprint_full.confidence === "Medium" ? "#f59e0b" : "var(--text-muted)",
                                  fontWeight: 600,
                                }}>
                                  {host.os_fingerprint_full.confidence}
                                  <span style={{ fontWeight: 400, color: "var(--text-muted)", marginLeft: 4, fontSize: "0.8em" }}>
                                    ({host.os_fingerprint_full.match_score ?? 0} pts)
                                  </span>
                                </span>
                              </div>
                            </>
                          ) : (
                            <>
                              <div style={{ display: "flex", justifyContent: "space-between" }}>
                                <span className="muted">OS Guess:</span>
                                <strong>{textValue(host.os_guess)}</strong>
                              </div>
                              <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
                                <span className="muted">Confidence:</span>
                                <span>{textValue(host.os_confidence)}</span>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Network Identity */}
                    {(host.mdns_name || host.mdns_services?.length || (host.netbios_names && host.netbios_names.length > 0) || host.snmp_device_type || host.device_category || host.firewall_likely || host.snmp_info) && (
                      <div style={{ flex: "1 1 250px" }}>
                        <h4 style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>Network Identity</h4>
                        <div style={{ background: "var(--bg-highlight)", padding: 12, borderRadius: 6, border: "1px solid var(--border)", fontSize: "0.85rem" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span className="muted">mDNS:</span>
                            <span>{textValue(host.mdns_name)}</span>
                          </div>
                          {host.mdns_services && host.mdns_services.length > 0 && (
                            <div style={{ marginBottom: 6 }}>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}>
                                {host.mdns_services.slice(0, 6).map(svc => (
                                  <span key={svc} style={{
                                    fontSize: 10, padding: "1px 5px",
                                    background: "rgba(34,211,238,0.1)",
                                    border: "1px solid rgba(34,211,238,0.3)",
                                    color: "#22d3ee", borderRadius: 3,
                                  }}>{textValue(svc, "").replace("._tcp.local", "").replace("._udp.local", "")}</span>
                                ))}
                              </div>
                            </div>
                          )}
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span className="muted">NetBIOS:</span>
                            <span style={{ textAlign: "right" }}>
                              {host.netbios_names && host.netbios_names.length
                                ? host.netbios_names.map(n => textValue(n?.name, "")).filter(Boolean).join(", ")
                                : "—"}
                            </span>
                          </div>
                          {host.netbios_workgroup && (
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                              <span className="muted">Domain:</span>
                              <span style={{ fontWeight: 600, color: "#818cf8" }}>{textValue(host.netbios_workgroup)}</span>
                            </div>
                          )}
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span className="muted">Device Type:</span>
                            <span>{textValue(host.snmp_device_type || host.device_category)}</span>
                          </div>
                          {host.snmp_info?.sys_name && (
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                              <span className="muted">SNMP Name:</span>
                              <span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{textValue(host.snmp_info.sys_name)}</span>
                            </div>
                          )}
                          {host.snmp_info?.sys_location && (
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                              <span className="muted">Location:</span>
                              <span style={{ textAlign: "right", maxWidth: 160, wordBreak: "break-word" }}>{textValue(host.snmp_info.sys_location)}</span>
                            </div>
                          )}
                          {host.snmp_info?.vendor && (
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                              <span className="muted">SNMP Vendor:</span>
                              <span style={{ fontWeight: 600 }}>{textValue(host.snmp_info.vendor)}</span>
                            </div>
                          )}
                          {host.firewall_likely && (
                            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6, paddingTop: 6, borderTop: "1px solid var(--border)" }}>
                              <span className="muted">Firewall:</span>
                              <span style={{
                                fontSize: 11, fontWeight: 700, color: "#f97316",
                                background: "rgba(249,115,22,0.12)",
                                border: "1px solid rgba(249,115,22,0.3)",
                                borderRadius: 4, padding: "1px 6px",
                              }}>🛡 Detected ({host.firewall_confidence})</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* SNMP Interface Table */}
                  {host.snmp_info?.interfaces && host.snmp_info.interfaces.length > 0 && (
                    <div style={{ marginBottom: 20 }}>
                      <h4 style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>
                        SNMP Interfaces ({host.snmp_info.interfaces.length})
                        {host.snmp_info.ip_addresses?.length > 0 && (
                          <span style={{ marginLeft: 8, color: "#60a5fa", textTransform: "none", fontSize: 11 }}>
                            · {host.snmp_info.ip_addresses.length} IP{host.snmp_info.ip_addresses.length !== 1 ? "s" : ""} bound
                          </span>
                        )}
                      </h4>
                      <div style={{ overflowX: "auto" }}>
                        <table className="ports-table">
                          <thead>
                            <tr>
                              <th>#</th>
                              <th>Interface</th>
                              <th>Type</th>
                              <th>MAC</th>
                              <th>Admin</th>
                              <th>Oper</th>
                            </tr>
                          </thead>
                          <tbody>
                            {host.snmp_info.interfaces.map(iface => (
                              <tr key={iface.index}>
                                <td><code className="ip-code">{iface.index}</code></td>
                                <td>{textValue(iface.description)}</td>
                                <td><span style={{ fontSize: 11, color: "var(--text-muted)" }}>{textValue(iface.type)}</span></td>
                                <td><code style={{ fontSize: 11 }}>{textValue(iface.mac)}</code></td>
                                <td><span style={{ color: iface.admin_up ? "#22c55e" : "#ef4444", fontSize: 11 }}>{iface.admin_up ? "Up" : "Down"}</span></td>
                                <td><span style={{ color: iface.oper_up ? "#22c55e" : "#94a3b8", fontSize: 11 }}>{iface.oper_up ? "Up" : "Down"}</span></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      {host.snmp_info.ip_addresses?.length > 0 && (
                        <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6 }}>
                          {host.snmp_info.ip_addresses.map(a => (
                            <span key={a.address} style={{
                              fontSize: 11, fontFamily: "var(--mono)",
                              padding: "2px 7px",
                              background: "rgba(96,165,250,0.1)",
                              border: "1px solid rgba(96,165,250,0.25)",
                              color: "#60a5fa", borderRadius: 4,
                            }} title={`Netmask: ${a.netmask}`}>
                              {textValue(a.address)}/{textValue(a.netmask)}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  <h4 style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>Discovered Services</h4>
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
                              <span style={{ background: "var(--bg)", border: "1px solid var(--border)", padding: "2px 7px", borderRadius: 3, fontSize: 12, fontWeight: 600 }}>
                                {textValue(port.service)}
                              </span>
                            </td>
                            <td style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>
                              {textValue(port.banner || port.version, <span className="muted">—</span>)}
                            </td>
                            <td>
                              <span style={{ color: RISK_COLOR[port.risk] || "#60a5fa", fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700 }}>
                                {port.risk || "Info"}
                              </span>
                            </td>
                            <td>
                              {port.cves?.length > 0
                                ? <span style={{ color: "#f97316", fontFamily: "var(--mono)", fontSize: 11 }}>
                                  {port.cves.length} CVE{port.cves.length > 1 ? "s" : ""}
                                </span>
                                : <span className="muted">—</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="muted" style={{ fontSize: 13, padding: "12px 0" }}>No open ports detected on this host.</p>
                  )}

                  {/* UDP Services — added by port engine patch */}
                  {host.udp_services && host.udp_services.length > 0 && (
                    <>
                      <h4 style={{ fontSize: "0.8rem", textTransform: "uppercase", color: "var(--text-muted)", margin: "16px 0 8px" }}>
                        UDP Services ({host.udp_services.length})
                      </h4>
                      <table className="ports-table">
                        <thead>
                          <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>State</th>
                            <th>Risk</th>
                            <th>Banner</th>
                          </tr>
                        </thead>
                        <tbody>
                          {host.udp_services.map((svc, i) => (
                            <tr key={i}>
                              <td><code className="ip-code">{svc.port}/udp</code></td>
                              <td>
                                <span style={{ background: "var(--bg)", border: "1px solid var(--border)", padding: "2px 7px", borderRadius: 3, fontSize: 12, fontWeight: 600 }}>
                                  {textValue(svc.service)}
                                </span>
                              </td>
                              <td>
                                <span style={{
                                  color: svc.state === "open" ? "#22c55e" : svc.state === "open|filtered" ? "#f59e0b" : "var(--text-muted)",
                                  fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700,
                                }}>
                                  {textValue(svc.state)}
                                </span>
                              </td>
                              <td>
                                <span style={{ color: RISK_COLOR[svc.risk] || "#60a5fa", fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700 }}>
                                  {svc.risk || "Info"}
                                </span>
                              </td>
                              <td style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--mono)" }}>
                                {textValue(svc.banner, <span className="muted">—</span>)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {summary && results.length > 0 && pipelineMode !== "advanced" && pipelineMode !== "vulnerability_audit" && (
          <ExportPanel results={results} summary={summary} scanId={scanId} scanNo={scanNo} target={target} pipelineMode={pipelineMode} />
        )}

        {hasScanned && canProceedToPhase3 && (
          <div className="phase-footer">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <p className="muted" style={{ fontSize: 13, margin: 0 }}>
                {selectedCount === 0
                  ? "Select hosts with approved scope before running a vulnerability audit."
                  : `${selectedCount} host${selectedCount > 1 ? "s" : ""} queued for vulnerability audit.`}
              </p>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)" }}>Audit profile</span>
                <div className="filter-tabs">
                  {VULN_PROFILES.map(profile => (
                    <button
                      key={profile.value}
                      className={`filter-tab ${vulnProfile === profile.value ? "filter-tab--active" : ""}`}
                      onClick={() => setVulnProfile(profile.value)}
                      title={profile.desc}
                      disabled={!canExecuteScans}
                    >
                      {profile.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <button className="btn btn--danger" onClick={proceedToNextPhase} disabled={selectedCount === 0 || !canExecuteScans}>
              Run Vulnerability Audit →
            </button>
          </div>
        )}

      </div>
    </AppLayout>
  );
}
