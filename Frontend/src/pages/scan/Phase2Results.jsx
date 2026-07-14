/**
 * src/pages/scan/Phase2Results.jsx
 *
 * Pattern B — Pure Reporting Screen
 *
 * Port scan results are produced by the backend auto-chain (Phase 1 → Phase 2).
 * All configuration (intensity, OS detection) was captured upfront on NewScan.jsx.
 * This page only loads and displays already-computed Phase 2 data.
 *
 * The "Proceed to Vulnerability Audit" action is preserved — it passes scan results
 * forward to Phase 3 and is a result-review action, not a scan trigger.
 */
import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import ScanStepper from "../../components/layout/ScanStepper";
import ExportPanel from "../../components/scan/ExportPanel";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { isPhaseEnabled, getNextPhase } from "../../config/scanConfig";
import api from "../../api/axiosInstance";
import { useAuth } from "../../context/AuthContext";
import { can, denyMessage } from "../../auth/permissions";

const VULN_PROFILES = [
  {
    value: "recommended",
    label: "Recommended",
    desc: "Service-aware checks for discovered open ports",
  },
  {
    value: "conservative",
    label: "Conservative",
    desc: "Lower-impact checks for fragile or OT systems",
  },
  {
    value: "deep",
    label: "Deep",
    desc: "Broader audit scope for approved maintenance windows",
  },
];

const RISK_COLOR = {
  Critical: "#ff4d4d",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#22c55e",
  Info: "#60a5fa",
};

const textValue = (value, fallback = "—") => {
  if (value == null || value === "" || value === "Unknown" || value === "N/A")
    return fallback;
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  )
    return String(value);
  if (Array.isArray(value))
    return (
      value
        .map((v) => textValue(v, ""))
        .filter(Boolean)
        .join(", ") || fallback
    );
  if (typeof value === "object")
    return (
      value.name || value.vendor || value.address || value.value || fallback
    );
  return fallback;
};

const fmtNumber = (value, digits = 1, fallback = "—") => {
  const num = Number(value);
  return Number.isFinite(num) ? num.toFixed(digits) : fallback;
};

const hasDetectedServices = (host) =>
  (host?.open_ports?.length || 0) > 0 || (host?.udp_services?.length || 0) > 0;

const getCategoryLabel = (cat) => {
  const labels = {
    router: "Router",
    switch: "Switch",
    firewall: "Firewall",
    wireless_ap: "Wireless AP",
    printer: "Printer",
    iot: "IoT/ICS",
    server: "Server",
    endpoint: "Endpoint",
    voip: "VoIP",
    storage: "Storage",
    network_appliance: "Net Appliance",
    scada_ics: "Industrial/OT",
    virtual_machine: "Virtual Machine",
    unknown: "Unknown",
  };
  return labels[cat] || cat;
};

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
    setSaveStatus,
    setPhase2Results,
    setPhase2Summary,
    setPhase3Results,
    setPipelineState,
    executionMode,
  } = useScan();
  const [filter, setFilter] = useState("active");
  const [results, setResults] = useState(() =>
    phase2Results.length ? phase2Results : [],
  );
  const [summary, setSummary] = useState(() => phase2Summary || null);
  const [vulnProfile, setVulnProfile] = useState("recommended");
  const [expanded, setExpanded] = useState(new Set());
  const [error, setError] = useState("");
  // phase2Running = true while port scan is still in progress (no results yet)
  const [phase2Running, setPhase2Running] = useState(
    phase2Results.length === 0,
  );
  const [phase2Polling, setPhase2Polling] = useState(false);
  const hasResults = results.length > 0;

  const [selected, setSelected] = useState(() => new Set());
  const selectionInitialized = useRef(false);

  const showCheckboxes = executionMode === "interactive";
  const finalSelectedHosts = showCheckboxes
    ? results.filter((h) => h.is_active && selected.has(h.ip_address))
    : results.filter((h) => h.is_active && hasDetectedServices(h));
  const selectedCount = finalSelectedHosts.length;

  const toggleHost = (ip) => {
    const next = new Set(selected);
    next.has(ip) ? next.delete(ip) : next.add(ip);
    setSelected(next);
  };

  // Initialize selected hosts when results are loaded
  useEffect(() => {
    if (results.length > 0) {
      if (!selectionInitialized.current) {
        const defaultSelected = results
          .filter((h) => h.is_active && hasDetectedServices(h))
          .map((h) => h.ip_address);
        setSelected(new Set(defaultSelected));
        selectionInitialized.current = true;
      }
    } else {
      selectionInitialized.current = false;
    }
  }, [results]);

  // Auto-redirect in Automatic mode to Phase 3 if enabled
  useEffect(() => {
    if (
      hasResults &&
      executionMode === "automatic" &&
      isPhaseEnabled(pipelineMode, 3)
    ) {
      const autoQueue = results.filter(
        (h) => h.is_active && hasDetectedServices(h),
      );
      setPhase3Results(autoQueue);
      navigate("/scan/vulnerability-audit");
    }
  }, [
    hasResults,
    executionMode,
    pipelineMode,
    results,
    navigate,
    setPhase3Results,
  ]);

  // ── Sync from context whenever Phase1Results polling saves data ──────────────
  useEffect(() => {
    if (phase2Results.length) {
      setResults(phase2Results);
      setPhase2Running(false);
      setPhase2Polling(false);
    }
    if (phase2Summary) setSummary(phase2Summary);
  }, [phase2Results, phase2Summary]);

  // ── Update pipeline state in context to drive the stepper ──────────────────
  useEffect(() => {
    if (phase2Running) {
      setPipelineState(PIPELINE_STATES.PORT_SCAN);
    } else if (hasResults) {
      const hasPhase3 = isPhaseEnabled(pipelineMode, 3);
      setPipelineState(
        hasPhase3 ? PIPELINE_STATES.IDLE : PIPELINE_STATES.COMPLETE,
      );
    }
  }, [phase2Running, hasResults, pipelineMode, setPipelineState]);

  // ── Polling loop — runs while phase2Running and scanId is known ────────────
  // Handles first load when Phase 2 is still executing and direct navigation.
  useEffect(() => {
    if (!scanId || !phase2Running) return;
    let stopped = false;
    setPhase2Polling(true);

    const applyResults = (p2Data, p2Sum) => {
      setResults(p2Data);
      setPhase2Results(p2Data);
      if (p2Sum) {
        setSummary(p2Sum);
        setPhase2Summary(p2Sum);
      }
      setPhase2Running(false);
      setPhase2Polling(false);
    };

    const poll = async () => {
      // Immediate first check on mount
      try {
        const { data: scan } = await api.get(`/scans/${scanId}`);
        if (stopped) return;
        const d = scan?.results?.phase2?.data;
        if (Array.isArray(d) && d.length > 0) {
          applyResults(d, scan?.results?.phase2?.summary);
          return;
        }
      } catch {
        /* ignore */
      }

      // Then poll every 4s
      while (!stopped) {
        await new Promise((r) => setTimeout(r, 4000));
        if (stopped) break;
        try {
          const { data: scan } = await api.get(`/scans/${scanId}`);
          const d = scan?.results?.phase2?.data;
          const s = scan?.results?.phase2?.summary;
          if (Array.isArray(d) && d.length > 0) {
            applyResults(d, s);
            break;
          }
          if (scan?.status === "complete" || scan?.status === "failed") {
            setPhase2Running(false);
            setPhase2Polling(false);
            if (scan?.status === "failed") {
              setError("Port scan failed on the backend.");
              setPipelineState(PIPELINE_STATES.ERROR);
            }
            break;
          }
        } catch {
          /* ignore transient errors */
        }
      }
    };

    poll();
    return () => {
      stopped = true;
    };
  }, [scanId, phase2Running]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!phase1Hosts.length) {
      navigate("/scan/host-discovery", { replace: true });
    }
  }, [phase1Hosts.length, navigate]);

  const discoveredHosts = phase1Hosts;
  const activeHosts = discoveredHosts.filter((h) => h.is_active);
  const displayHosts = filter === "active" ? activeHosts : discoveredHosts;

  const canProceedToPhase3 = isPhaseEnabled(pipelineMode, 3);
  const nextPhase = getNextPhase(pipelineMode, 2);

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
      setError(
        "No active hosts with open ports selected to run Vulnerability Audit.",
      );
      return;
    }
    setPhase3Results(finalSelectedHosts);
    setPipelineState(PIPELINE_STATES.IDLE);
    navigate(nextPhase.route, {
      state: {
        vulnerabilityProfile: vulnProfile,
        startPhase: "VULN_SCAN",
      },
    });
  };

  const activeResults = results.filter((h) => h.is_active);

  if (!phase1Hosts.length) return null;

  // Stepper advances: step 2 = port scan active, step 3 = port scan complete
  const stepperCurrent = hasResults ? 3 : 2;

  return (
    <AppLayout pageTitle="Port Scan Results" saveStatus={saveStatus}>
      <ScanStepper current={stepperCurrent} />

      <div className="page-inner">
        <div className="page-title-row">
          <div>
            <h2 className="page-title">Port Scan Results</h2>
            <p className="page-subtitle">
              Target: <code className="ip-code">{target}</code>
              {scanId && (
                <span className="muted"> · Scan No. {scanNo ?? "—"}</span>
              )}
            </p>
          </div>
          <button
            className="btn btn--ghost"
            onClick={() => navigate("/scan/host-discovery")}
          >
            ← Back
          </button>
        </div>

        {/* PHASE 4: Unreachable Banner */}
        {((!summary &&
          activeHosts.length === 0 &&
          discoveredHosts.length > 0) ||
          (summary &&
            (summary.status === "unreachable" ||
              (Number(summary.active_hosts) === 0 &&
                Number(summary.total_hosts) > 0)))) && (
          <div
            style={{
              margin: "16px 0",
              padding: "16px 20px",
              borderRadius: 8,
              background: "rgba(245, 158, 11, 0.08)",
              border: "1px solid rgba(245, 158, 11, 0.3)",
              display: "flex",
              alignItems: "center",
              gap: 16,
              color: "#92400e",
            }}
          >
            <span style={{ fontSize: 24 }}>⚠️</span>
            <div>
              <strong style={{ display: "block", fontSize: 16 }}>
                Host is unavailable/down/unreachable
              </strong>
              <p style={{ margin: "4px 0 0", fontSize: 14, opacity: 0.9 }}>
                The discovery scan completed but the target did not respond.
                Verify the IP address and network connectivity before
                re-scanning.
              </p>
            </div>
          </div>
        )}

        {/* ── Port Scan Running: progress banner ─────────────────────────── */}
        {phase2Running && (
          <div
            className="pipeline-progress-card"
            style={{ marginTop: 16, marginBottom: 8, padding: "16px 20px" }}
          >
            <div
              className="pipeline-progress-header"
              style={{ marginBottom: 12 }}
            >
              <div className="pipeline-pulse" />
              <div>
                <h3
                  className="pipeline-progress-title"
                  style={{ fontSize: "0.95rem" }}
                >
                  Port Scan Running…
                </h3>
                <p
                  className="pipeline-progress-desc"
                  style={{ fontSize: "0.8rem", marginTop: 2 }}
                >
                  Probing TCP/UDP services on discovered hosts — results will
                  appear automatically when complete.
                </p>
              </div>
            </div>
            <div
              className="progress-bar progress-bar--pipeline"
              style={{ height: 4 }}
            >
              <div className="progress-fill progress-fill--animated" />
            </div>
          </div>
        )}

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            margin: "16px 0",
            flexWrap: "wrap",
          }}
        >
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
        </div>

        <div className="results-table-wrap">
          <table className="results-table">
            <thead>
              <tr>
                {showCheckboxes && (
                  <th style={{ width: 40, paddingRight: 0 }}>
                    <input
                      type="checkbox"
                      checked={
                        activeHosts.length > 0 &&
                        activeHosts.every((h) => selected.has(h.ip_address))
                      }
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelected(
                            new Set(activeHosts.map((h) => h.ip_address)),
                          );
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
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {displayHosts.map((host) => {
                let displayHost = host.hostname;
                if (!displayHost || displayHost === "Unknown") {
                  if (host.mdns_name) displayHost = host.mdns_name;
                  else if (host.netbios_names && host.netbios_names.length)
                    displayHost = host.netbios_names[0]?.name;
                }

                return (
                  <tr
                    key={host.ip_address}
                    className={host.is_active ? "row--active" : "row--inactive"}
                  >
                    {showCheckboxes && (
                      <td style={{ paddingRight: 0 }}>
                        <input
                          type="checkbox"
                          checked={selected.has(host.ip_address)}
                          onChange={() => toggleHost(host.ip_address)}
                          disabled={!host.is_active || !canExecuteScans}
                          style={{ cursor: "pointer" }}
                        />
                      </td>
                    )}
                    <td>
                      <code className="ip-code">{host.ip_address}</code>
                    </td>
                    <td>
                      {textValue(displayHost, <span className="muted">—</span>)}
                    </td>
                    <td>
                      {textValue(
                        host.mac_address,
                        <span className="muted">—</span>,
                      )}
                    </td>
                    <td>
                      {textValue(host.vendor, <span className="muted">—</span>)}
                    </td>
                    <td>
                      {textValue(
                        host.discovery_method,
                        <span className="muted">—</span>,
                      )}
                    </td>
                    <td>
                      <span
                        className={`status-dot ${host.is_active ? "status-dot--up" : "status-dot--down"}`}
                      />
                      {host.is_active ? "Active" : "Inactive"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {summary && (
          <div
            className="summary-bar"
            style={{
              marginTop: 16,
              display: "flex",
              flexWrap: "wrap",
              gap: "10px",
            }}
          >
            <span className="summary-item">
              <b>{summary.total_hosts}</b> Hosts scanned
            </span>
            <span className="summary-item summary-item--active">
              <b>{summary.hosts_with_ports}</b> Have open ports
            </span>
            <span className="summary-item">
              <b>{fmtNumber(summary.scan_duration)}s</b> Duration
            </span>
            <span className="summary-item summary-item--sel">
              <b>{selectedCount}</b> queued for audit
            </span>
            {summary.custom_ports && (
              <span
                className="summary-item"
                style={{
                  color: "#60a5fa",
                  background: "rgba(96,165,250,0.1)",
                  border: "1px solid rgba(96,165,250,0.25)",
                  padding: "2px 8px",
                  borderRadius: "4px",
                }}
                title={summary.custom_ports}
              >
                🔌 Custom Ports:{" "}
                <b>
                  {summary.custom_ports.length > 25
                    ? summary.custom_ports.substring(0, 22) + "..."
                    : summary.custom_ports}
                </b>
              </span>
            )}
          </div>
        )}

        {error && <div className="alert alert--error">⚠ {error}</div>}

        {hasResults && activeResults.length === 0 && (
          <div className="empty-state">
            <span className="empty-state-icon">🔍</span>
            <p className="empty-state-title">
              No active hosts returned open ports
            </p>
          </div>
        )}

        {activeResults.map((host) => {
          const portCount = host.open_ports?.length || 0;
          const critPorts =
            host.open_ports?.filter((p) => p.risk === "Critical").length || 0;
          const isExpanded = expanded.has(host.ip_address);

          return (
            <div key={host.ip_address} className="host-card">
              <div
                className="host-card-header"
                onClick={() => toggleExpand(host.ip_address)}
                style={{ cursor: "pointer" }}
              >
                {showCheckboxes && (
                  <input
                    type="checkbox"
                    checked={selected.has(host.ip_address)}
                    onChange={() => toggleHost(host.ip_address)}
                    onClick={(e) => e.stopPropagation()}
                    disabled={!canExecuteScans}
                    style={{ marginRight: 8, cursor: "pointer" }}
                  />
                )}
                <div
                  style={{
                    flex: 1,
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    flexWrap: "wrap",
                  }}
                >
                  <code
                    className="ip-code"
                    style={{ fontSize: "0.9rem", fontWeight: 700 }}
                  >
                    {host.ip_address}
                  </code>
                  {(() => {
                    let hName = host.hostname;
                    if (!hName || hName === "Unknown") {
                      if (host.mdns_name) hName = host.mdns_name;
                      else if (host.netbios_names && host.netbios_names.length)
                        hName = host.netbios_names[0]?.name;
                    }
                    const safeName = textValue(hName, "");
                    return safeName ? (
                      <span className="muted small">{safeName}</span>
                    ) : null;
                  })()}
                </div>

                <div className="host-card-meta">
                  {portCount > 0 ? (
                    <span
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: 12,
                        background: "var(--bg-app)",
                        border: "1px solid var(--border)",
                        padding: "2px 8px",
                        borderRadius: 4,
                      }}
                    >
                      {portCount} port{portCount !== 1 ? "s" : ""}
                    </span>
                  ) : (
                    <span className="muted small">No open ports</span>
                  )}

                  {critPorts > 0 && (
                    <span
                      style={{
                        fontFamily: "var(--mono)",
                        fontSize: 11,
                        color: "#ff4d4d",
                        background: "rgba(255,77,77,.1)",
                        border: "1px solid rgba(255,77,77,.25)",
                        borderRadius: 3,
                        padding: "2px 7px",
                      }}
                    >
                      {critPorts} Critical
                    </span>
                  )}

                  {host.os_guess && host.os_guess !== "Unknown" && (
                    <span
                      style={{
                        fontSize: 11,
                        color: "var(--text-muted)",
                        background: "var(--bg-app)",
                        border: "1px solid var(--border)",
                        padding: "2px 8px",
                        borderRadius: 4,
                      }}
                    >
                      {textValue(host.os_guess)}
                    </span>
                  )}
                </div>

                <button
                  className="expand-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleExpand(host.ip_address);
                  }}
                >
                  {isExpanded ? "▲" : "▼"}
                </button>
              </div>

              {isExpanded && (
                <div className="host-card-body">
                  <div
                    style={{
                      padding: "0 0 16px 0",
                      display: "flex",
                      gap: "24px",
                      flexWrap: "wrap",
                    }}
                  >
                    {/* Detailed OS Fingerprint */}
                    {(host.os_fingerprint_full?.os ||
                      (host.os_guess && host.os_guess !== "Unknown")) && (
                      <div style={{ flex: "1 1 250px" }}>
                        <h4
                          style={{
                            fontSize: "0.8rem",
                            textTransform: "uppercase",
                            color: "var(--text-muted)",
                            marginBottom: 8,
                          }}
                        >
                          Target OS Fingerprint
                        </h4>
                        <div
                          style={{
                            background: "var(--bg-highlight)",
                            padding: 12,
                            borderRadius: 6,
                            border: "1px solid var(--border)",
                            fontSize: "0.85rem",
                          }}
                        >
                          {host.os_fingerprint_full?.os ? (
                            <>
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  marginBottom: 4,
                                }}
                              >
                                <span className="muted">OS Guess:</span>
                                <strong>
                                  {textValue(host.os_fingerprint_full.os)}
                                </strong>
                              </div>
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  marginBottom: 4,
                                }}
                              >
                                <span className="muted">Confidence:</span>
                                <span
                                  style={{
                                    color:
                                      host.os_fingerprint_full.confidence ===
                                      "High"
                                        ? "#22c55e"
                                        : host.os_fingerprint_full
                                              .confidence === "Medium"
                                          ? "#f59e0b"
                                          : "var(--text-muted)",
                                    fontWeight: 600,
                                  }}
                                >
                                  {host.os_fingerprint_full.confidence}
                                  <span
                                    style={{
                                      fontWeight: 400,
                                      color: "var(--text-muted)",
                                      marginLeft: 4,
                                      fontSize: "0.8em",
                                    }}
                                  >
                                    ({host.os_fingerprint_full.match_score ?? 0}{" "}
                                    pts)
                                  </span>
                                </span>
                              </div>
                            </>
                          ) : (
                            <>
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                }}
                              >
                                <span className="muted">OS Guess:</span>
                                <strong>{textValue(host.os_guess)}</strong>
                              </div>
                              <div
                                style={{
                                  display: "flex",
                                  justifyContent: "space-between",
                                  marginTop: 4,
                                }}
                              >
                                <span className="muted">Confidence:</span>
                                <span>{textValue(host.os_confidence)}</span>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Network Identity */}
                    {(host.mdns_name ||
                      host.mdns_services?.length ||
                      (host.netbios_names && host.netbios_names.length > 0) ||
                      host.snmp_device_type ||
                      host.device_category ||
                      host.firewall_likely ||
                      host.snmp_info) && (
                      <div style={{ flex: "1 1 250px" }}>
                        <h4
                          style={{
                            fontSize: "0.8rem",
                            textTransform: "uppercase",
                            color: "var(--text-muted)",
                            marginBottom: 8,
                          }}
                        >
                          Network Identity
                        </h4>
                        <div
                          style={{
                            background: "var(--bg-highlight)",
                            padding: 12,
                            borderRadius: 6,
                            border: "1px solid var(--border)",
                            fontSize: "0.85rem",
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              marginBottom: 4,
                            }}
                          >
                            <span className="muted">mDNS:</span>
                            <span>{textValue(host.mdns_name)}</span>
                          </div>
                          {host.mdns_services &&
                            host.mdns_services.length > 0 && (
                              <div style={{ marginBottom: 6 }}>
                                <div
                                  style={{
                                    display: "flex",
                                    flexWrap: "wrap",
                                    gap: 3,
                                    marginTop: 2,
                                  }}
                                >
                                  {host.mdns_services.slice(0, 6).map((svc) => (
                                    <span
                                      key={svc}
                                      style={{
                                        fontSize: 10,
                                        padding: "1px 5px",
                                        background: "rgba(34,211,238,0.1)",
                                        border:
                                          "1px solid rgba(34,211,238,0.3)",
                                        color: "#22d3ee",
                                        borderRadius: 3,
                                      }}
                                    >
                                      {textValue(svc, "")
                                        .replace("._tcp.local", "")
                                        .replace("._udp.local", "")}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              marginBottom: 4,
                            }}
                          >
                            <span className="muted">NetBIOS:</span>
                            <span style={{ textAlign: "right" }}>
                              {host.netbios_names && host.netbios_names.length
                                ? host.netbios_names
                                    .map((n) => textValue(n?.name, ""))
                                    .filter(Boolean)
                                    .join(", ")
                                : "—"}
                            </span>
                          </div>
                          {host.netbios_workgroup && (
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                marginBottom: 4,
                              }}
                            >
                              <span className="muted">Domain:</span>
                              <span
                                style={{ fontWeight: 600, color: "#818cf8" }}
                              >
                                {textValue(host.netbios_workgroup)}
                              </span>
                            </div>
                          )}
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              marginBottom: 4,
                            }}
                          >
                            <span className="muted">Device Type:</span>
                            <span>
                              {textValue(
                                host.snmp_device_type ||
                                  getCategoryLabel(host.device_category),
                              )}
                            </span>
                          </div>
                          {host.snmp_info?.sys_name && (
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                marginBottom: 4,
                              }}
                            >
                              <span className="muted">SNMP Name:</span>
                              <span
                                style={{
                                  fontFamily: "var(--mono)",
                                  fontSize: 11,
                                }}
                              >
                                {textValue(host.snmp_info.sys_name)}
                              </span>
                            </div>
                          )}
                          {host.snmp_info?.sys_location && (
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                marginBottom: 4,
                              }}
                            >
                              <span className="muted">Location:</span>
                              <span
                                style={{
                                  textAlign: "right",
                                  maxWidth: 160,
                                  wordBreak: "break-word",
                                }}
                              >
                                {textValue(host.snmp_info.sys_location)}
                              </span>
                            </div>
                          )}
                          {host.snmp_info?.vendor && (
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                marginBottom: 4,
                              }}
                            >
                              <span className="muted">SNMP Vendor:</span>
                              <span style={{ fontWeight: 600 }}>
                                {textValue(host.snmp_info.vendor)}
                              </span>
                            </div>
                          )}
                          {host.firewall_likely && (
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                marginTop: 6,
                                paddingTop: 6,
                                borderTop: "1px solid var(--border)",
                              }}
                            >
                              <span className="muted">Firewall:</span>
                              <span
                                style={{
                                  fontSize: 11,
                                  fontWeight: 700,
                                  color: "#f97316",
                                  background: "rgba(249,115,22,0.12)",
                                  border: "1px solid rgba(249,115,22,0.3)",
                                  borderRadius: 4,
                                  padding: "1px 6px",
                                }}
                              >
                                🛡 Detected ({host.firewall_confidence})
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* SNMP Interface Table */}
                  {host.snmp_info?.interfaces &&
                    host.snmp_info.interfaces.length > 0 && (
                      <div style={{ marginBottom: 20 }}>
                        <h4
                          style={{
                            fontSize: "0.8rem",
                            textTransform: "uppercase",
                            color: "var(--text-muted)",
                            marginBottom: 8,
                          }}
                        >
                          SNMP Interfaces ({host.snmp_info.interfaces.length})
                          {host.snmp_info.ip_addresses?.length > 0 && (
                            <span
                              style={{
                                marginLeft: 8,
                                color: "#60a5fa",
                                textTransform: "none",
                                fontSize: 11,
                              }}
                            >
                              · {host.snmp_info.ip_addresses.length} IP
                              {host.snmp_info.ip_addresses.length !== 1
                                ? "s"
                                : ""}{" "}
                              bound
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
                              {host.snmp_info.interfaces.map((iface) => (
                                <tr key={iface.index}>
                                  <td>
                                    <code className="ip-code">
                                      {iface.index}
                                    </code>
                                  </td>
                                  <td>{textValue(iface.description)}</td>
                                  <td>
                                    <span
                                      style={{
                                        fontSize: 11,
                                        color: "var(--text-muted)",
                                      }}
                                    >
                                      {textValue(iface.type)}
                                    </span>
                                  </td>
                                  <td>
                                    <code style={{ fontSize: 11 }}>
                                      {textValue(iface.mac)}
                                    </code>
                                  </td>
                                  <td>
                                    <span
                                      style={{
                                        color: iface.admin_up
                                          ? "#22c55e"
                                          : "#ef4444",
                                        fontSize: 11,
                                      }}
                                    >
                                      {iface.admin_up ? "Up" : "Down"}
                                    </span>
                                  </td>
                                  <td>
                                    <span
                                      style={{
                                        color: iface.oper_up
                                          ? "#22c55e"
                                          : "#94a3b8",
                                        fontSize: 11,
                                      }}
                                    >
                                      {iface.oper_up ? "Up" : "Down"}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        {host.snmp_info.ip_addresses?.length > 0 && (
                          <div
                            style={{
                              marginTop: 8,
                              display: "flex",
                              flexWrap: "wrap",
                              gap: 6,
                            }}
                          >
                            {host.snmp_info.ip_addresses.map((a) => (
                              <span
                                key={a.address}
                                style={{
                                  fontSize: 11,
                                  fontFamily: "var(--mono)",
                                  padding: "2px 7px",
                                  background: "rgba(96,165,250,0.1)",
                                  border: "1px solid rgba(96,165,250,0.25)",
                                  color: "#60a5fa",
                                  borderRadius: 4,
                                }}
                                title={`Netmask: ${a.netmask}`}
                              >
                                {textValue(a.address)}/{textValue(a.netmask)}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                  <h4
                    style={{
                      fontSize: "0.8rem",
                      textTransform: "uppercase",
                      color: "var(--text-muted)",
                      marginBottom: 8,
                    }}
                  >
                    Discovered Services
                  </h4>
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
                            <td>
                              <code className="ip-code">{port.port}/tcp</code>
                            </td>
                            <td>
                              <span
                                style={{
                                  background: "var(--bg)",
                                  border: "1px solid var(--border)",
                                  padding: "2px 7px",
                                  borderRadius: 3,
                                  fontSize: 12,
                                  fontWeight: 600,
                                }}
                              >
                                {textValue(port.service)}
                              </span>
                            </td>
                            <td
                              style={{
                                fontSize: 12,
                                color: "var(--text-muted)",
                                fontFamily: "var(--mono)",
                              }}
                            >
                              {textValue(
                                port.banner || port.version,
                                <span className="muted">—</span>,
                              )}
                            </td>
                            <td>
                              <span
                                style={{
                                  color: RISK_COLOR[port.risk] || "#60a5fa",
                                  fontFamily: "var(--mono)",
                                  fontSize: 11,
                                  fontWeight: 700,
                                }}
                              >
                                {port.risk || "Info"}
                              </span>
                            </td>
                            <td>
                              {port.cves?.length > 0 ? (
                                <span
                                  style={{
                                    color: "#f97316",
                                    fontFamily: "var(--mono)",
                                    fontSize: 11,
                                  }}
                                >
                                  {port.cves.length} CVE
                                  {port.cves.length > 1 ? "s" : ""}
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
                    <p
                      className="muted"
                      style={{ fontSize: 13, padding: "12px 0" }}
                    >
                      No open ports detected on this host.
                    </p>
                  )}

                  {/* UDP Services — added by port engine patch */}
                  {host.udp_services && host.udp_services.length > 0 && (
                    <>
                      <h4
                        style={{
                          fontSize: "0.8rem",
                          textTransform: "uppercase",
                          color: "var(--text-muted)",
                          margin: "16px 0 8px",
                        }}
                      >
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
                              <td>
                                <code className="ip-code">{svc.port}/udp</code>
                              </td>
                              <td>
                                <span
                                  style={{
                                    background: "var(--bg)",
                                    border: "1px solid var(--border)",
                                    padding: "2px 7px",
                                    borderRadius: 3,
                                    fontSize: 12,
                                    fontWeight: 600,
                                  }}
                                >
                                  {textValue(svc.service)}
                                </span>
                              </td>
                              <td>
                                <span
                                  style={{
                                    color:
                                      svc.state === "open"
                                        ? "#22c55e"
                                        : svc.state === "open|filtered"
                                          ? "#f59e0b"
                                          : "var(--text-muted)",
                                    fontFamily: "var(--mono)",
                                    fontSize: 11,
                                    fontWeight: 700,
                                  }}
                                >
                                  {textValue(svc.state)}
                                </span>
                              </td>
                              <td>
                                <span
                                  style={{
                                    color: RISK_COLOR[svc.risk] || "#60a5fa",
                                    fontFamily: "var(--mono)",
                                    fontSize: 11,
                                    fontWeight: 700,
                                  }}
                                >
                                  {svc.risk || "Info"}
                                </span>
                              </td>
                              <td
                                style={{
                                  fontSize: 12,
                                  color: "var(--text-muted)",
                                  fontFamily: "var(--mono)",
                                }}
                              >
                                {textValue(
                                  svc.banner,
                                  <span className="muted">—</span>,
                                )}
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

        {summary &&
          results.length > 0 &&
          pipelineMode !== "advanced" &&
          pipelineMode !== "vulnerability_audit" && (
            <ExportPanel
              results={results}
              summary={summary}
              scanId={scanId}
              scanNo={scanNo}
              target={target}
              pipelineMode={pipelineMode}
            />
          )}

        {hasResults && canProceedToPhase3 && (
          <div className="phase-footer">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <p className="muted" style={{ fontSize: 13, margin: 0 }}>
                {selectedCount === 0
                  ? "No active hosts with open ports found to run vulnerability audit."
                  : `${selectedCount} host${selectedCount > 1 ? "s" : ""} queued for vulnerability audit.`}
              </p>
              <div
                style={{
                  display: "flex",
                  gap: 8,
                  flexWrap: "wrap",
                  alignItems: "center",
                }}
              >
                <span
                  style={{
                    fontSize: "0.75rem",
                    fontWeight: 600,
                    color: "var(--text-muted)",
                  }}
                >
                  Audit profile
                </span>
                <div className="filter-tabs">
                  {VULN_PROFILES.map((profile) => (
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
            <button
              className="btn btn--danger"
              onClick={proceedToNextPhase}
              disabled={selectedCount === 0 || !canExecuteScans}
            >
              Run Vulnerability Audit →
            </button>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
