/**
 * src/pages/scan/NewScan.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Scan setup page with "Active Mission" view.
 */
import "../../styles/NewScan.css";
import { useState, useCallback, useEffect, useRef } from "react";
import { useNavigate, useLocation, useParams } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { buildPhasePayload, getScanPipeline } from "../../config/scanConfig";
import api from "../../api/axiosInstance";
import { can } from "../../auth/permissions";
import { useAuth } from "../../context/AuthContext";
import ScanQuotaBar from "../../components/scan/ScanQuotaBar";
import { detectTargetType, parseExcludeIpsJS } from "../../utils/ipValidation";

/* ── Constants ─────────────────────────────────────────────────────────────── */

const DISCOVERY_INTENSITIES = [
  {
    value: "light",
    label: "Light",
    icon: "⚡",
    desc: "Fastest — may miss firewalled hosts",
    badge: "Fastest",
    badgeStyle: {
      background: "rgba(34,211,238,0.12)",
      color: "#22d3ee",
      border: "1px solid rgba(34,211,238,0.3)",
    },
  },
  {
    value: "normal",
    label: "Normal",
    icon: "⚖",
    desc: "Fast-first with coverage fallback",
    badge: "Recommended",
    badgeStyle: {
      background: "rgba(34,197,94,0.12)",
      color: "#22c55e",
      border: "1px solid rgba(34,197,94,0.3)",
    },
  },
  {
    value: "deep",
    label: "Deep",
    icon: "🔬",
    desc: "Max coverage — best for firewalled nets",
    badge: "Thorough",
    badgeStyle: {
      background: "rgba(245,158,11,0.12)",
      color: "#d97706",
      border: "1px solid rgba(245,158,11,0.3)",
    },
  },
];

const SCAN_INTENSITIES = [
  {
    value: "light",
    label: "Light",
    icon: "🏃",
    desc: "Fast scan, fewer ports",
  },
  {
    value: "normal",
    label: "Normal",
    icon: "⚖",
    desc: "Balanced port coverage",
  },
  { value: "deep", label: "Deep", icon: "🔭", desc: "Full port range scan" },
];

const PORT_SCAN_INTENSITIES = [
  { value: "light", label: "Light", icon: "⚡", desc: "Quick top-ports only" },
  {
    value: "normal",
    label: "Normal",
    icon: "⚖",
    desc: "Balanced port coverage",
  },
  {
    value: "deep",
    label: "Deep",
    icon: "🔭",
    desc: "Full port range — comprehensive",
  },
];

const QUICK_TARGETS = [
  "10.180.4.1",
  "10.180.6.0/24",
  "10.180.6.45",
  "10.180.6.14",
];

const PIPELINE_BADGE = {
  basic: { label: "Basic Scan", cls: "ns-badge--basic" },
  asset: { label: "Asset Discovery", cls: "ns-badge--asset" },
  advanced: { label: "Vulnerability Audit", cls: "ns-badge--advanced" },
  vulnerability_audit: {
    label: "Vulnerability Audit",
    cls: "ns-badge--advanced",
  },
};

const SENSITIVE_PORTS = [2375, 2376, 6443, 10250];

const PORT_PROFILES = {
  it: {
    label: "IT Infrastructure",
    ports:
      "21,22,23,25,53,67,80,88,110,111,123,135,137,139,143,161,389,443,445,465,587,623,636,902,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,10250,27017",
  },
  scada: {
    label: "SCADA / OT",
    ports:
      "102,502,789,1089,1091,2222,2404,2455,4000,4840,4911,5007,9600,18245,20000,44818,47808,55000,55003",
  },
  web: {
    label: "Web Services",
    ports: "80,443,3000,5000,8000,8080,8443,8888,9000,9090,9443",
  },
  database: {
    label: "Database",
    ports: "1433,1521,3306,5432,6379,9042,9200,27017,28017",
  },
  remote: {
    label: "Remote Access",
    ports: "22,23,3389,5900,5985,5986",
  },
  custom: {
    label: "Custom",
    ports: "",
  },
};

/* ── Helpers ───────────────────────────────────────────────────────────────── */

const fmtTime = (date) =>
  date.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const fmtElapsed = (startMs) => {
  const secs = Math.floor((Date.now() - startMs) / 1000);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
};

/* SVG progress ring circumference for r=22 */
const RING_R = 22;
const RING_C = 2 * Math.PI * RING_R; // ≈ 138.23

/* ── HostCard sub-component ─────────────────────────────────────────────────── */

function HostCard({ host, isNew }) {
  const hostname =
    host.hostname && host.hostname !== "Unknown" ? host.hostname : null;
  const mac =
    host.mac_address && host.mac_address !== "N/A" ? host.mac_address : null;

  const isEnrichingHostname = host._enriching_hostname === true;
  const isEnrichingMac = host._enriching_mac === true;

  const hostnameContent = isEnrichingHostname ? (
    <span className="am-host-field-resolving">Resolving…</span>
  ) : hostname ? (
    <span className="am-host-field-enriched">{hostname}</span>
  ) : (
    <span className="muted">—</span>
  );

  const macContent = isEnrichingMac ? (
    <span className="am-host-field-resolving">Resolving…</span>
  ) : mac ? (
    <span className="am-host-field-enriched">{mac}</span>
  ) : (
    <span className="muted">—</span>
  );

  return (
    <div className={`am-host-card${isNew ? " am-host-card--new" : ""}`}>
      <div className="am-host-col-status">
        <span className="am-host-alive-dot" />
      </div>
      <div className="am-host-col-ip" title={host.ip_address}>
        {host.ip_address}
      </div>
      <div
        className={`am-host-col-hostname${isEnrichingHostname ? " am-enriching" : ""}`}
        title={hostname || ""}
      >
        {hostnameContent}
      </div>
      <div
        className={`am-host-col-mac${isEnrichingMac ? " am-enriching" : ""}`}
      >
        {macContent}
      </div>
    </div>
  );
}

/* ── Active Mission sub-component ──────────────────────────────────────────── */

function ActiveMission({
  scanState,
  onRunInBackground,
  onViewResults,
  onNewScan,
}) {
  const { target, scanNo, pipelineMode } = scanState;
  const {
    status,
    progress,
    discovered,
    totalIps,
    discoveredHosts,
    newHostIps,
    startMs,
    error,
  } = scanState;

  const [elapsed, setElapsed] = useState("0s");
  const hostsListRef = useRef(null);

  useEffect(() => {
    if (status === "running") {
      const id = setInterval(() => setElapsed(fmtElapsed(startMs)), 1000);
      return () => clearInterval(id);
    }
  }, [status, startMs]);

  useEffect(() => {
    if (hostsListRef.current) {
      hostsListRef.current.scrollTop = hostsListRef.current.scrollHeight;
    }
  }, [discoveredHosts]);

  const pct = Math.max(0, Math.min(100, progress));
  const offset = RING_C - (pct / 100) * RING_C;
  const isRunning = status === "running";
  const isComplete = status === "complete";
  const isFailed = status === "failed";
  const isUnreachable =
    status === "unreachable" || (isComplete && discovered === 0);

  const dotClass = isFailed
    ? "am-live-dot--failed"
    : isUnreachable
      ? "am-live-dot--warning"
      : isComplete
        ? "am-live-dot--complete"
        : "";
  const ringClass = isFailed
    ? "am-ring-fill--failed"
    : isUnreachable
      ? "am-ring-fill--warning"
      : isComplete
        ? "am-ring-fill--complete"
        : "";
  const badgeClass = isFailed
    ? "am-status-badge--failed"
    : isUnreachable
      ? "am-status-badge--warning"
      : isComplete
        ? "am-status-badge--complete"
        : "am-status-badge--running";
  const badgeLabel = isFailed
    ? "Failed"
    : isUnreachable
      ? "Unreachable"
      : isComplete
        ? "Complete"
        : "Live Scanning";
  const stripClass = isFailed
    ? "am-progress-strip-fill--failed"
    : isUnreachable
      ? "am-progress-strip-fill--warning"
      : isComplete
        ? "am-progress-strip-fill--complete"
        : "";

  const pipelineLabel =
    {
      basic: "Host Discovery",
      asset: "Asset Discovery",
      advanced: "Vulnerability Audit",
      vulnerability_audit: "Vulnerability Audit",
    }[pipelineMode] || "Scan";

  return (
    <div className="am-page">
      <div className="am-topbar">
        <div className="am-topbar-left">
          <span className={`am-live-dot ${dotClass}`} />
          <span className="am-mission-label">Active Mission</span>
          {scanNo && <span className="am-scan-no">#{scanNo}</span>}
        </div>
        <div className="am-actions">
          {!isComplete && !isFailed && !isUnreachable && (
            <button className="am-btn-bg" onClick={onRunInBackground}>
              📥 Run in Background
            </button>
          )}
          <button className="am-btn-new" onClick={onNewScan}>
            ← New Scan
          </button>
        </div>
      </div>

      <div className="am-card">
        <div className="am-console-header">
          <div className="am-console-header-left">
            <div className="am-progress-ring-wrap">
              <svg className="am-progress-ring" viewBox="0 0 52 52">
                <circle className="am-ring-track" cx="26" cy="26" r={RING_R} />
                <circle
                  className={`am-ring-fill ${ringClass}`}
                  cx="26"
                  cy="26"
                  r={RING_R}
                  strokeDasharray={RING_C}
                  strokeDashoffset={offset}
                />
              </svg>
              <div className="am-ring-pct">
                {isUnreachable ? "!" : `${pct}%`}
              </div>
            </div>
            <div className="am-header-info">
              <div className="am-header-title">{pipelineLabel}</div>
              <div className="am-header-target">{target}</div>
            </div>
          </div>
          <div className={`am-status-badge ${badgeClass}`}>
            {isRunning && <span className="am-status-spinner" />}
            {badgeLabel}
          </div>
        </div>

        {isUnreachable && (
          <div className="am-unreachable-banner">
            <div className="am-unreachable-icon">⚠️</div>
            <div className="am-unreachable-text">
              <strong>Target Unreachable</strong>
              <p>
                The host <code>{target}</code> did not respond to discovery
                probes.
              </p>
              <div className="am-unreachable-tips">
                <span>Possible reasons:</span>
                <ul>
                  <li>Host is currently powered off.</li>
                  <li>Firewall is dropping ICMP/TCP packets.</li>
                  <li>Target is in a different network segment.</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        <div className="am-progress-strip">
          <div
            className={`am-progress-strip-fill ${stripClass}`}
            style={{ width: isUnreachable ? "100%" : `${pct}%` }}
          />
        </div>

        <div className="am-stats-bar">
          <div className="am-stat">
            <span
              className={`am-stat-value ${discovered > 0 ? "am-stat-value--green" : ""}`}
            >
              {discovered}
            </span>
            <span className="am-stat-label">Hosts Found</span>
          </div>
          <div className="am-stat">
            <span className="am-stat-value am-stat-value--accent">
              {totalIps || "—"}
            </span>
            <span className="am-stat-label">Total IPs</span>
          </div>
          <div className="am-stat">
            <span className="am-stat-value">{pct}%</span>
            <span className="am-stat-label">Progress</span>
          </div>
          <div className="am-stat">
            <span className="am-stat-value">{elapsed}</span>
            <span className="am-stat-label">Elapsed</span>
          </div>
        </div>

        <div className="am-hosts-panel">
          <div className="am-hosts-header">
            <div className="am-hosts-header-left">
              <span className="am-hosts-icon">🖥</span>
              <span className="am-hosts-title">Discovered Systems</span>
              {discoveredHosts.length > 0 && (
                <span className="am-hosts-count-badge">
                  {discoveredHosts.length}
                </span>
              )}
            </div>
            {isRunning && (
              <div className="am-hosts-scanning-label">
                <span className="am-hosts-scanning-dot" />
                scanning…
              </div>
            )}
          </div>
          {discoveredHosts.length === 0 ? (
            <div className="am-hosts-empty">
              <div className="am-hosts-empty-radar">
                <div className="am-hosts-empty-ring" />
                <div className="am-hosts-empty-ring" />
                <div className="am-hosts-empty-ring" />
                <div className="am-hosts-empty-dot" />
              </div>
              <div className="am-hosts-empty-text">
                Scanning subnet… waiting for active hosts.
              </div>
            </div>
          ) : (
            <div className="am-hosts-list" ref={hostsListRef}>
              {discoveredHosts.map((h) => (
                <HostCard
                  key={h.ip_address}
                  host={h}
                  isNew={newHostIps.includes(h.ip_address)}
                />
              ))}
            </div>
          )}
        </div>

        <div className="am-console-footer">
          <span className="am-footer-elapsed">
            {isRunning
              ? `Elapsed: ${elapsed}`
              : isComplete
                ? "Scan complete"
                : "Scan ended"}
          </span>
          <div className="am-footer-actions">
            {!isComplete && !isFailed && (
              <button className="am-btn-bg" onClick={onRunInBackground}>
                📥 Run in Background
              </button>
            )}
            {isComplete && (
              <button className="am-btn-view-results" onClick={onViewResults}>
                View Results →
              </button>
            )}
            {isFailed && (
              <button className="am-btn-new" onClick={onNewScan}>
                ↩ Try Again
              </button>
            )}
          </div>
        </div>
      </div>
      {error && (
        <div className="am-error-card">
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

/* ── Main Component ─────────────────────────────────────────────────────────── */

export default function NewScan() {
  const navigate = useNavigate();
  const location = useLocation();
  const { scanId: urlScanId } = useParams();
  const { user } = useAuth();
  const canExecuteScans = can(user, "scans", "execute");

  const {
    target,
    setTarget,
    pipelineMode,
    intensity,
    setIntensity,
    discoveryIntensity,
    setDiscoveryIntensity,
    osDetection,
    setOsDetection,
    portScanIntensity,
    setPortScanIntensity,
    setPhase1Hosts,
    setPhase1Summary,
    setScanId,
    setScanNo,
    setPipelineState,
    setPipelineMode,
    autoRunAdvancedSingleTarget,
    ctxScanNo,
    executionMode,
    setExecutionMode,
    portScanMode,
    setPortScanMode,
    customPorts,
    setCustomPorts,
    portProfile,
    setPortProfile,
    excludePorts,
    setExcludePorts,
    excludeIps,
    setExcludeIps,
  } = useScan();

  const isActiveRoute = !!urlScanId;
  const [view, setView] = useState(isActiveRoute ? "mission" : "setup");
  const [loading, setLoading] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [error, setError] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [quotaBlocked, setQuotaBlocked] = useState(false);
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [parsedTargets, setParsedTargets] = useState([]);
  const [uploadSummary, setUploadSummary] = useState({
    total: 0,
    valid: 0,
    invalid: 0,
    invalidEntries: [],
    duplicates: 0,
    show: false,
  });
  const [customPortsError, setCustomPortsError] = useState("");
  const [parsedCustomPortsCount, setParsedCustomPortsCount] = useState(0);

  // Authenticated checks — a policy option on the Vulnerability Audit, not a
  // separate scan. Only stored credentials qualify: the pipeline runs
  // unattended, so there is nothing to hold a one-time secret for.
  const [credentialedEnabled, setCredentialedEnabled] = useState(false);
  const [credentialsList, setCredentialsList] = useState([]);
  const [selectedCredIds, setSelectedCredIds] = useState([]);

  // SNMP settings for topology mapping (optional)
  const [snmpEnabled, setSnmpEnabled] = useState(false);
  const [snmpVersion, setSnmpVersion] = useState("v2c");
  const [snmpCommunity, setSnmpCommunity] = useState("public");
  const [snmpUsername, setSnmpUsername] = useState("");
  const [snmpAuthProtocol, setSnmpAuthProtocol] = useState("SHA");
  const [snmpAuthPassphrase, setSnmpAuthPassphrase] = useState("");
  const [snmpPrivProtocol, setSnmpPrivProtocol] = useState("");
  const [snmpPrivPassphrase, setSnmpPrivPassphrase] = useState("");
  const [snmpContextName, setSnmpContextName] = useState("");

  const [excludePortsEnabled, setExcludePortsEnabled] = useState(
    () => !!excludePorts,
  );
  const [excludePortsError, setExcludePortsError] = useState("");
  const [, setParsedExcludePortsCount] = useState(0);
  const [sensitivePortsFound, setSensitivePortsFound] = useState(false);

  const [excludeIpsEnabled, setExcludeIpsEnabled] = useState(
    () => !!excludeIps,
  );
  const [excludeIpsError, setExcludeIpsError] = useState("");

  // Load the org's stored credentials the first time authenticated checks are
  // switched on, rather than on every visit to this page.
  useEffect(() => {
    if (!credentialedEnabled || credentialsList.length) return;
    let cancelled = false;
    api
      .get("/compliance/credentials")
      .then((res) => {
        if (!cancelled) setCredentialsList(res.data || []);
      })
      .catch((err) => {
        console.error("Failed to load credentials for scan", err);
      });
    return () => {
      cancelled = true;
    };
  }, [credentialedEnabled, credentialsList.length]);

  const parseCustomPortsJS = (portsStr) => {
    if (!portsStr || !portsStr.trim()) {
      return { ports: [], error: "", sensitiveFound: false };
    }
    const clean = portsStr.replace(/\s+/g, "");
    if (!/^[0-9,-]+$/.test(clean)) {
      return {
        ports: [],
        error:
          "Invalid characters. Only numbers, commas, and hyphens are allowed.",
        sensitiveFound: false,
      };
    }
    const tokens = clean.split(",");
    const portsSet = new Set();

    for (const token of tokens) {
      if (!token) continue;
      if (token.includes("-")) {
        const rangeParts = token.split("-");
        if (rangeParts.length !== 2) {
          return {
            ports: [],
            error: `Invalid range format: "${token}"`,
            sensitiveFound: false,
          };
        }
        const start = parseInt(rangeParts[0], 10);
        const end = parseInt(rangeParts[1], 10);
        if (isNaN(start) || isNaN(end)) {
          return {
            ports: [],
            error: `Invalid range bounds: "${token}"`,
            sensitiveFound: false,
          };
        }
        if (start > end) {
          return {
            ports: [],
            error: `Range start must be <= end: "${token}"`,
            sensitiveFound: false,
          };
        }
        if (start < 1 || end > 65535) {
          return {
            ports: [],
            error: `Ports must be between 1 and 65535: "${token}"`,
            sensitiveFound: false,
          };
        }
        for (let p = start; p <= end; p++) {
          if (portsSet.has(p)) {
            return {
              ports: [],
              error: `Duplicate port detected: ${p}`,
              sensitiveFound: false,
            };
          }
          portsSet.add(p);
        }
      } else {
        const p = parseInt(token, 10);
        if (isNaN(p)) {
          return {
            ports: [],
            error: `Invalid port number: "${token}"`,
            sensitiveFound: false,
          };
        }
        if (p < 1 || p > 65535) {
          return {
            ports: [],
            error: `Port must be between 1 and 65535: ${p}`,
            sensitiveFound: false,
          };
        }
        if (portsSet.has(p)) {
          return {
            ports: [],
            error: `Duplicate port detected: ${p}`,
            sensitiveFound: false,
          };
        }
        portsSet.add(p);
      }
    }

    const portsArray = Array.from(portsSet);
    const sensitiveFound = portsArray.some((p) => SENSITIVE_PORTS.includes(p));
    return { ports: portsArray, error: "", sensitiveFound };
  };

  const parseExcludePortsJS = (portsStr) => {
    if (!portsStr || !portsStr.trim()) {
      return { ports: [], error: "" };
    }
    const clean = portsStr.replace(/\s+/g, "");
    if (!/^[0-9,-]+$/.test(clean)) {
      return {
        ports: [],
        error:
          "Invalid characters. Only numbers, commas, and hyphens are allowed.",
      };
    }
    const tokens = clean.split(",");
    const portsSet = new Set();

    for (const token of tokens) {
      if (!token) continue;
      if (token.includes("-")) {
        const rangeParts = token.split("-");
        if (rangeParts.length !== 2) {
          return { ports: [], error: `Invalid range format: "${token}"` };
        }
        const start = parseInt(rangeParts[0], 10);
        const end = parseInt(rangeParts[1], 10);
        if (isNaN(start) || isNaN(end)) {
          return { ports: [], error: `Invalid range bounds: "${token}"` };
        }
        if (start > end) {
          return { ports: [], error: `Range start must be <= end: "${token}"` };
        }
        if (start < 1 || end > 65535) {
          return {
            ports: [],
            error: `Ports must be between 1 and 65535: "${token}"`,
          };
        }
        for (let p = start; p <= end; p++) {
          if (portsSet.has(p)) {
            return { ports: [], error: `Duplicate port detected: ${p}` };
          }
          portsSet.add(p);
        }
      } else {
        const p = parseInt(token, 10);
        if (isNaN(p)) {
          return { ports: [], error: `Invalid port number: "${token}"` };
        }
        if (p < 1 || p > 65535) {
          return { ports: [], error: `Port must be between 1 and 65535: ${p}` };
        }
        if (portsSet.has(p)) {
          return { ports: [], error: `Duplicate port detected: ${p}` };
        }
        portsSet.add(p);
      }
    }

    const portsArray = Array.from(portsSet);
    return { ports: portsArray, error: "" };
  };

  const handleCustomPortsChange = (val) => {
    setCustomPorts(val);
    const { ports, error, sensitiveFound } = parseCustomPortsJS(val);
    setCustomPortsError(error);
    setParsedCustomPortsCount(ports.length);
    setSensitivePortsFound(sensitiveFound);
  };

  const handleExcludeToggleChange = (checked) => {
    setExcludePortsEnabled(checked);
    if (!checked) {
      setExcludePorts("");
    }
  };

  const handleExcludeIpsToggleChange = (checked) => {
    setExcludeIpsEnabled(checked);
    if (!checked) {
      setExcludeIps("");
    }
  };

  useEffect(() => {
    if (excludeIps) {
      const { error } = parseExcludeIpsJS(excludeIps);
      setExcludeIpsError(error);
    } else {
      setExcludeIpsError("");
    }
  }, [excludeIps]);

  const excludeTokens = excludePorts
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  const handleRemoveExcludeToken = (tokenToRemove) => {
    const updatedTokens = excludeTokens.filter((t) => t !== tokenToRemove);
    setExcludePorts(updatedTokens.join(", "));
  };

  const getPreviewData = () => {
    const isPortMode = portScanMode === "port";
    let typeLabel = isPortMode ? "Port-Based Scan" : "Intensity-Based Scan";
    let targetPortsLabel = "";
    let finalCount = "";

    if (isPortMode) {
      const profileLabel = PORT_PROFILES[portProfile]?.label || "Custom";
      targetPortsLabel = `${profileLabel}`;
      if (portProfile === "custom") {
        finalCount = `${parsedCustomPortsCount} custom port${parsedCustomPortsCount !== 1 ? "s" : ""}`;
      } else {
        const baseCount = PORT_PROFILES[portProfile]?.ports
          ? PORT_PROFILES[portProfile].ports.split(",").length
          : 0;
        finalCount = `${baseCount} port${baseCount !== 1 ? "s" : ""}`;
      }
    } else {
      const depthLabel =
        { light: "Light Scan", normal: "Normal Scan", deep: "Deep Scan" }[
          portScanIntensity
        ] || "Normal Scan";
      targetPortsLabel = depthLabel;
      finalCount =
        {
          light: "Top 100 ports",
          normal: "Top 1000 ports",
          deep: "All 65535 ports",
        }[portScanIntensity] || "Top 1000 ports";
    }

    let excludedLabel = "None";
    if (excludePortsEnabled && excludePorts.trim()) {
      const { ports, error } = parseExcludePortsJS(excludePorts);
      if (!error && ports.length > 0) {
        excludedLabel = `${ports.join(", ")} (${ports.length} port${ports.length !== 1 ? "s" : ""})`;
      } else if (error) {
        excludedLabel = "Invalid exclude ports string";
      }
    }

    return { typeLabel, targetPortsLabel, finalCount, excludedLabel };
  };

  const preview = getPreviewData();

  useEffect(() => {
    if (pipelineMode !== "asset" || portScanMode !== "port") {
      setCustomPortsError("");
      setParsedCustomPortsCount(0);
      setSensitivePortsFound(false);
      return;
    }
    const activePortsStr =
      portProfile === "custom"
        ? customPorts
        : PORT_PROFILES[portProfile]?.ports || "";
    if (activePortsStr) {
      const { ports, error, sensitiveFound } =
        parseCustomPortsJS(activePortsStr);
      setCustomPortsError(error);
      setParsedCustomPortsCount(ports.length);
      setSensitivePortsFound(sensitiveFound);
    } else {
      setCustomPortsError("");
      setParsedCustomPortsCount(0);
      setSensitivePortsFound(false);
    }
  }, [pipelineMode, portScanMode, portProfile, customPorts]);

  useEffect(() => {
    if (excludePorts) {
      const { ports, error } = parseExcludePortsJS(excludePorts);
      setExcludePortsError(error);
      setParsedExcludePortsCount(ports.length);
    } else {
      setExcludePortsError("");
      setParsedExcludePortsCount(0);
    }
  }, [excludePorts]);

  const [missionState, setMissionState] = useState({
    status: "running",
    progress: 0,
    discovered: 0,
    totalIps: 0,
    discoveredHosts: [],
    newHostIps: [],
    startMs: Date.now(),
    error: "",
    scanId: null,
    scanNo: null,
  });
  const missionScanIdRef = useRef(null);
  const pollHostsRef = useRef(null);
  const hostFirstSeenRef = useRef(new Map());
  const latestDiscoveredHostsRef = useRef([]);

  const pipeline = getScanPipeline(pipelineMode || "basic");
  const badgeMeta = PIPELINE_BADGE[pipelineMode] || PIPELINE_BADGE.basic;
  const btnLabel =
    pipelineMode === "asset"
      ? `Start Discovery · ${discoveryIntensity || "normal"}`
      : "Start Scan";

  const startHostPolling = useCallback((scanId) => {
    if (pollHostsRef.current) clearInterval(pollHostsRef.current);
    pollHostsRef.current = setInterval(async () => {
      try {
        const { data: scan } = await api.get(`/scans/${scanId}`);
        const hosts = (scan?.results?.phase1?.data || []).filter(
          (h) => h.is_active,
        );
        if (!hosts.length) return;
        const now = fmtTime(new Date());
        hosts.forEach((h) => {
          if (!hostFirstSeenRef.current.has(h.ip_address))
            hostFirstSeenRef.current.set(h.ip_address, now);
        });
        const enriched = hosts.map((h) => ({
          ...h,
          _seenAt: hostFirstSeenRef.current.get(h.ip_address),
          _enriching_hostname: !h.hostname || h.hostname === "Unknown",
          _enriching_mac: !h.mac_address || h.mac_address === "N/A",
        }));
        latestDiscoveredHostsRef.current = enriched;
        setMissionState((prev) => {
          const existingIps = new Set(
            prev.discoveredHosts.map((x) => x.ip_address),
          );
          const newOnes = enriched
            .filter((h) => !existingIps.has(h.ip_address))
            .map((h) => h.ip_address);
          if (newOnes.length > 0)
            setTimeout(
              () => setMissionState((p) => ({ ...p, newHostIps: [] })),
              3000,
            );
          return {
            ...prev,
            discoveredHosts: enriched,
            newHostIps: newOnes,
            discovered: enriched.length,
          };
        });
      } catch {
        /* ignore */
      }
    }, 2500);
  }, []);

  const stopHostPolling = useCallback(() => {
    if (pollHostsRef.current) {
      clearInterval(pollHostsRef.current);
      pollHostsRef.current = null;
    }
  }, []);

  const baseURL = api.defaults.baseURL || "";
  const wsPrefix = baseURL.replace(/^http/, "ws");
  const listenForProgress = useCallback(
    async (scanId) => {
      let ticket;
      try {
        const res = await api.post("/auth/ticket");
        ticket = res.data.ticket;
      } catch {
        return null;
      }
      return new Promise((resolve) => {
        const ws = new WebSocket(
          `${wsPrefix}/scans/${scanId}/progress?ticket=${encodeURIComponent(ticket)}`,
        );
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            const prog = data.progress || {};
            setMissionState((prev) => {
              const next = {
                ...prev,
                totalIps: prog.total_ips ?? prev.totalIps,
                progress:
                  prog.status === "complete" || prog.status === "unreachable"
                    ? 100
                    : prog.status === "failed"
                      ? prev.progress
                      : Math.max(
                          prev.progress,
                          Math.round(
                            ((prog.discovered || 0) /
                              Math.max(prog.total_ips || 1, 1)) *
                              85,
                          ),
                        ),
              };
              const incomingHosts = prog.hosts;
              if (Array.isArray(incomingHosts) && incomingHosts.length > 0) {
                const now = fmtTime(new Date());
                if (prog.status === "enriching") {
                  const patchMap = new Map(
                    incomingHosts.map((h) => [h.ip_address, h]),
                  );
                  const merged = prev.discoveredHosts.map((existing) => {
                    const patch = patchMap.get(existing.ip_address);
                    if (!patch) return existing;
                    const updated = {
                      ...existing,
                      hostname:
                        patch.hostname && patch.hostname !== "Unknown"
                          ? patch.hostname
                          : existing.hostname,
                      mac_address:
                        patch.mac_address && patch.mac_address !== "N/A"
                          ? patch.mac_address
                          : existing.mac_address,
                      vendor:
                        patch.vendor && patch.vendor !== "Unknown"
                          ? patch.vendor
                          : existing.vendor,
                    };
                    if (patch.hostname !== undefined)
                      updated._enriching_hostname = false;
                    if (patch.mac_address !== undefined)
                      updated._enriching_mac = false;
                    return updated;
                  });
                  const existingIps = new Set(
                    prev.discoveredHosts.map((x) => x.ip_address),
                  );
                  const brandNew = incomingHosts
                    .filter((h) => !existingIps.has(h.ip_address))
                    .map((h) => ({
                      ...h,
                      _seenAt:
                        hostFirstSeenRef.current.get(h.ip_address) || now,
                      _enriching_hostname: false,
                      _enriching_mac: false,
                    }));
                  next.discoveredHosts = [...merged, ...brandNew];
                  next.discovered = next.discoveredHosts.length;
                  latestDiscoveredHostsRef.current = next.discoveredHosts;
                } else {
                  incomingHosts.forEach((h) => {
                    if (!hostFirstSeenRef.current.has(h.ip_address))
                      hostFirstSeenRef.current.set(h.ip_address, now);
                  });
                  const enriched = incomingHosts.map((h) => ({
                    ...h,
                    _seenAt: hostFirstSeenRef.current.get(h.ip_address),
                    _enriching_hostname:
                      !h.hostname || h.hostname === "Unknown",
                    _enriching_mac: !h.mac_address || h.mac_address === "N/A",
                  }));
                  const existingIps = new Set(
                    prev.discoveredHosts.map((x) => x.ip_address),
                  );
                  const newIps = enriched
                    .filter((h) => !existingIps.has(h.ip_address))
                    .map((h) => h.ip_address);
                  if (newIps.length > 0)
                    setTimeout(
                      () => setMissionState((p) => ({ ...p, newHostIps: [] })),
                      3000,
                    );
                  next.discoveredHosts = enriched;
                  next.discovered = enriched.length;
                  next.newHostIps = newIps;
                  latestDiscoveredHostsRef.current = next.discoveredHosts;
                }
              }
              return next;
            });
            if (
              prog.status === "complete" ||
              prog.status === "failed" ||
              prog.status === "unreachable" ||
              data.phase > 1
            ) {
              ws.close();
              resolve({ status: prog.status || "complete" });
            }
          } catch {
            /* ignore */
          }
        };
        ws.onerror = () => {
          ws.close();
          resolve({ status: "unknown" });
        };
        setTimeout(() => {
          if (ws.readyState === WebSocket.OPEN) ws.close();
          resolve({ status: "timeout" });
        }, 600000);
      });
    },
    [wsPrefix],
  );

  /* ── Strict Target Validation Helpers ──────────────────────────────────────── */

  /* The `accept` attribute on the <input> is a picker hint and nothing more:
     it does not apply to drag-and-drop, and the drop zone below feeds the same
     function. These guards are the ones that actually run on every path.

     Nothing here is a security boundary — the file never leaves the browser,
     and only the extracted target strings are POSTed, which the API
     re-validates from scratch. This is about not handing the operator
     "No valid targets found." when the real answer is "that is a .zip", and
     not calling readAsText() on something large enough to hang the tab. */
  const MAX_TARGET_FILE_BYTES = 5 * 1024 * 1024;
  const ACCEPTED_TARGET_EXTENSIONS = [".txt", ".csv"];

  const processFile = (file) => {
    if (!file) return;

    const name = (file.name || "").toLowerCase();
    if (!ACCEPTED_TARGET_EXTENSIONS.some((ext) => name.endsWith(ext))) {
      setError(
        `Unsupported file format: ${file.name || "unnamed file"}. ` +
          `Upload a ${ACCEPTED_TARGET_EXTENSIONS.join(" or ")} file with one target per line.`,
      );
      return;
    }

    if (file.size === 0) {
      setError(`${file.name} is empty — no targets to import.`);
      return;
    }

    if (file.size > MAX_TARGET_FILE_BYTES) {
      setError(
        `${file.name} is ${(file.size / (1024 * 1024)).toFixed(1)} MB, above the ` +
          `${MAX_TARGET_FILE_BYTES / (1024 * 1024)} MB limit for a target list.`,
      );
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => {
      setError(`Could not read ${file.name}.`);
    };
    reader.onload = (event) => {
      const rawTokens = event.target.result
        .replace(/\s*-\s*/g, "-")
        .split(/[,\s;]+/)
        .map((t) => t.trim())
        .filter(Boolean);

      const valid = [];
      const inv = [];
      const seen = new Set();
      let dups = 0;

      rawTokens.forEach((t) => {
        const clean = t.replace(/[^\w.:/[\]-]/g, "");
        if (
          !clean ||
          clean.toLowerCase() === "target" ||
          clean.toLowerCase() === "ipaddress"
        )
          return;
        if (seen.has(clean)) {
          dups++;
          return;
        }

        const type = detectTargetType(clean);
        if (type) {
          valid.push({ value: clean, type });
          seen.add(clean);
        } else {
          inv.push(clean);
        }
      });

      if (valid.length > 0) {
        setError("");
        setTarget(valid.map((r) => r.value).join(", "));
        setParsedTargets(valid);
        setUploadSummary({
          total: valid.length + inv.length + dups,
          valid: valid.length,
          invalid: inv.length,
          invalidEntries: inv,
          duplicates: dups,
          show: true,
        });
      } else {
        setError(
          `No valid targets found in ${file.name}. Expected one IP, CIDR or range per line.`,
        );
      }
    };
    reader.readAsText(file);
  };

  const handleRemoveTarget = (indexToRemove) => {
    const updatedParsed = parsedTargets.filter(
      (_, idx) => idx !== indexToRemove,
    );
    setParsedTargets(updatedParsed);

    const updatedTargetString = updatedParsed.map((pt) => pt.value).join(", ");
    setTarget(updatedTargetString);

    setUploadSummary((prev) => {
      const newValid = Math.max(0, prev.valid - 1);
      const newTotal = Math.max(0, prev.total - 1);
      return {
        ...prev,
        total: newTotal,
        valid: newValid,
        show: newValid > 0,
      };
    });
  };

  const handleScan = async () => {
    if (!canExecuteScans || !target.trim()) return;
    const trimmedTarget = target.trim();

    if (pipelineMode === "asset") {
      if (portScanMode === "port") {
        const activePortsStr =
          portProfile === "custom"
            ? customPorts
            : PORT_PROFILES[portProfile]?.ports || "";
        if (!activePortsStr || !activePortsStr.trim()) {
          setError("Ports list cannot be empty.");
          return;
        }
        const { error } = parseCustomPortsJS(activePortsStr);
        if (error) {
          setError(error);
          return;
        }
      }
    }

    if (excludePortsEnabled && excludePorts.trim()) {
      const { error } = parseExcludePortsJS(excludePorts);
      if (error) {
        setError(`Exclude ports error: ${error}`);
        return;
      }
    }

    if (excludeIpsEnabled && excludeIps.trim()) {
      const { error } = parseExcludeIpsJS(excludeIps);
      if (error) {
        setError(`Exclude IPs error: ${error}`);
        return;
      }
    }

    hostFirstSeenRef.current = new Map();
    latestDiscoveredHostsRef.current = [];
    setMissionState({
      status: "running",
      progress: 5,
      discovered: 0,
      totalIps: 0,
      discoveredHosts: [],
      newHostIps: [],
      startMs: Date.now(),
      error: "",
      scanId: null,
      scanNo: null,
    });
    setView("mission");
    setLoading(true);
    setPipelineState(PIPELINE_STATES.DISCOVERY);
    try {
      const scanOptions = {
        ...(snmpEnabled
          ? {
              snmp: {
                version: snmpVersion,
                ...(snmpVersion !== "v3" ? { community: snmpCommunity } : {}),
                ...(snmpVersion === "v3"
                  ? {
                      username: snmpUsername,
                      auth_protocol: snmpAuthProtocol,
                      auth_passphrase: snmpAuthPassphrase,
                      ...(snmpPrivProtocol
                        ? {
                            priv_protocol: snmpPrivProtocol,
                            priv_passphrase: snmpPrivPassphrase,
                          }
                        : {}),
                      ...(snmpContextName
                        ? { context_name: snmpContextName }
                        : {}),
                    }
                  : {}),
              },
            }
          : {}),
        ...(credentialedEnabled && selectedCredIds.length
          ? {
              credentials: selectedCredIds.map((id) => ({
                credential_id: id,
              })),
            }
          : {}),
      };
      const hasScanOptions = Object.keys(scanOptions).length > 0;

      const payload = buildPhasePayload(pipelineMode || "basic", {
        targets: trimmedTarget
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        scan_type: "adaptive",
        execution_mode: executionMode,
        ...(pipelineMode === "asset"
          ? { discovery_intensity: discoveryIntensity }
          : {}),
        ...(pipelineMode === "asset"
          ? {
              port_scan_intensity:
                portScanMode === "port" ? "custom" : portScanIntensity,
              ...(portScanMode === "port"
                ? {
                    custom_ports:
                      portProfile === "custom"
                        ? customPorts
                        : PORT_PROFILES[portProfile].ports,
                  }
                : {}),
            }
          : {}),
        ...(pipelineMode === "asset" ||
        pipelineMode === "advanced" ||
        pipelineMode === "vulnerability_audit"
          ? { os_detection: osDetection }
          : {}),
        ...(excludePorts && excludePorts.trim()
          ? { exclude_ports: excludePorts.trim() }
          : {}),
        ...(excludeIps && excludeIps.trim()
          ? { exclude_ips: excludeIps.trim() }
          : {}),
        ...(rateLimit ? { rate_limit: parseInt(rateLimit, 10) } : {}),
        // SNMP and credentials both live under `options`, so they are merged
        // into one object — sending them as separate `options` keys would let
        // whichever came last silently discard the other.
        ...(hasScanOptions ? { options: scanOptions } : {}),
      });
      const { data } = await api.post("/scan/host-discovery", payload);
      if (!data.success) throw new Error(data.error);
      const sid = data.scan_id,
        sno = data.scan_no ?? data.display_id;

      navigate(`/scan/active/${sid}`, {
        replace: true,
        state: {
          missionMode: true,
          scanId: sid,
          scanNo: sno,
          target: trimmedTarget,
          pipelineMode: pipelineMode || "basic",
        },
      });
    } catch (err) {
      stopHostPolling();
      setMissionState((prev) => ({
        ...prev,
        status: "failed",
        error: err.message,
      }));
    } finally {
      setLoading(false);
    }
  };

  const handleRunInBackground = useCallback(
    () => navigate("/scan-history"),
    [navigate],
  );
  const handleViewResults = useCallback(() => {
    if (executionMode === "interactive") {
      navigate("/scan/host-discovery");
      return;
    }
    if (pipelineMode === "asset") {
      navigate("/scan/asset-discovery");
      return;
    }
    if (
      (pipelineMode === "advanced" || pipelineMode === "vulnerability_audit") &&
      autoRunAdvancedSingleTarget
    ) {
      navigate("/scan/vulnerability-audit", {
        state: { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" },
      });
      return;
    }
    navigate(
      pipelineMode === "advanced" || pipelineMode === "vulnerability_audit"
        ? "/scan/vulnerability-audit"
        : "/scan/host-discovery",
    );
  }, [navigate, pipelineMode, autoRunAdvancedSingleTarget, executionMode]);

  const handleNewScan = useCallback(() => {
    stopHostPolling();
    navigate("/scan/new");
    setView("setup");
    setMissionState({
      status: "running",
      progress: 0,
      discovered: 0,
      totalIps: 0,
      discoveredHosts: [],
      newHostIps: [],
      startMs: Date.now(),
      error: "",
      scanId: null,
      scanNo: null,
    });
    setLoading(false);
  }, [stopHostPolling, navigate]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        setShowAdvanced(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const hasAutoRunRef = useRef(false);

  // Everything this bootstrap calls that is rebuilt each render — the scan
  // context's session-storage-backed setters, the polling helpers, and
  // `handleScan` — is reached through a ref rather than named as a dependency.
  // It is a one-shot: both branches latch `hasAutoRunRef`, so re-running it is
  // pure waste, and listing those values made it re-run on literally every
  // render. The dependency array below now holds exactly the values that decide
  // *whether* the bootstrap should fire.
  const bootstrapRef = useRef(null);
  bootstrapRef.current = {
    setTarget,
    setPipelineMode,
    setScanId,
    setScanNo,
    setPhase1Hosts,
    setPhase1Summary,
    startHostPolling,
    listenForProgress,
    stopHostPolling,
    handleScan,
    executionMode,
  };

  useEffect(() => {
    const boot = bootstrapRef.current;
    const effectiveScanId = location.state?.scanId || urlScanId;
    const isMission = location.state?.missionMode || !!urlScanId;

    if (isMission && !hasAutoRunRef.current && effectiveScanId) {
      hasAutoRunRef.current = true;
      const {
        scanNo,
        target: rt,
        pipelineMode: rm,
      } = location.state || { scanId: effectiveScanId };

      setView("mission");
      setMissionState((prev) => ({
        ...prev,
        scanId: effectiveScanId,
        scanNo: scanNo || prev.scanNo,
        status: "running",
        progress: 10,
        startMs: Date.now(),
      }));
      missionScanIdRef.current = effectiveScanId;
      if (rt) boot.setTarget(rt);
      if (rm) boot.setPipelineMode(rm);
      boot.setScanId(effectiveScanId);
      if (scanNo) boot.setScanNo(scanNo);

      boot.startHostPolling(effectiveScanId);
      boot.listenForProgress(effectiveScanId).then((res) => {
        boot.stopHostPolling();
        const fs =
          res?.status === "failed"
            ? "failed"
            : res?.status === "unreachable"
              ? "unreachable"
              : "complete";
        api.get(`/scans/${effectiveScanId}`).then(({ data: f }) => {
          const d =
              f?.results?.phase1?.data || latestDiscoveredHostsRef.current,
            active = d.filter((h) => h.is_active);
          bootstrapRef.current.setPhase1Hosts(d);
          bootstrapRef.current.setPhase1Summary(
            f?.results?.phase1?.summary || {},
          );
          setMissionState((prev) => ({
            ...prev,
            status: fs,
            progress:
              fs === "failed" || fs === "unreachable" ? prev.progress : 100,
            discovered: active.length,
            discoveredHosts: active,
          }));
          if (
            fs !== "failed" &&
            fs !== "unreachable" &&
            (rm || f?.pipeline_mode) !== "basic"
          ) {
            if (
              ((rm || f?.pipeline_mode) === "advanced" ||
                (rm || f?.pipeline_mode) === "vulnerability_audit") &&
              active.length === 1
            )
              navigate("/scan/vulnerability-audit", {
                replace: true,
                state: {
                  autoRunAdvancedSingleTarget: true,
                  startPhase: "PORT_SCAN",
                },
              });
            else {
              if (bootstrapRef.current.executionMode === "interactive") {
                navigate("/scan/host-discovery", { replace: true });
              } else {
                navigate("/scan/asset-discovery", { replace: true });
              }
            }
          }
        });
      });

      // Clean up state but stay on the active URL
      if (location.state?.missionMode) {
        navigate(`/scan/active/${effectiveScanId}`, {
          replace: true,
          state: {},
        });
      }
    } else if (
      location.state?.autoRun &&
      !hasAutoRunRef.current &&
      canExecuteScans &&
      target &&
      !loading &&
      !quotaBlocked
    ) {
      hasAutoRunRef.current = true;
      navigate(".", { replace: true, state: {} });
      setTimeout(() => bootstrapRef.current.handleScan(), 100);
    }
  }, [
    location.state,
    urlScanId,
    canExecuteScans,
    target,
    loading,
    quotaBlocked,
    navigate,
  ]);

  if (view === "mission")
    return (
      <AppLayout pageTitle="Active Scan Mission">
        <ActiveMission
          scanState={{
            ...missionState,
            target,
            scanNo: missionState.scanNo ?? ctxScanNo,
            pipelineMode: pipelineMode || "basic",
          }}
          onRunInBackground={handleRunInBackground}
          onViewResults={handleViewResults}
          onNewScan={handleNewScan}
        />
      </AppLayout>
    );

  return (
    <AppLayout pageTitle="New Scan">
      <div className="ns-page">
        <div className="ns-hero">
          <button className="ns-back" onClick={() => navigate("/dashboard")}>
            ← Back
          </button>
          <div className={`ns-badge ${badgeMeta.cls}`}>{badgeMeta.label}</div>
          <h1 className="ns-title">{pipeline.label}</h1>
          <p className="ns-sub">{pipeline.description}</p>
        </div>
        <ScanQuotaBar
          onQuotaChange={({ quota_exceeded, concurrent_exceeded }) =>
            setQuotaBlocked(quota_exceeded || concurrent_exceeded)
          }
        />
        <div className="ns-card">
          <div className="ns-section">
            <div className="ns-label">
              Target <span className="ns-label-hint">IP, CIDR, or range</span>
            </div>
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => processFile(e.target.files[0])}
              accept=".txt,.csv"
              style={{ display: "none" }}
            />
            <div
              className={`ns-drop-zone ${isDragging ? "ns-drop-zone--active" : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                if (e.dataTransfer.files?.length)
                  processFile(e.dataTransfer.files[0]);
              }}
            >
              <div className="ns-input-row">
                <div className="ns-input-wrap">
                  <span className="ns-input-icon">🎯</span>
                  <input
                    className="ns-input"
                    value={target}
                    onChange={(e) => {
                      setTarget(e.target.value);
                      if (uploadSummary.show)
                        setUploadSummary((p) => ({ ...p, show: false }));
                      if (parsedTargets.length) setParsedTargets([]);
                    }}
                    onKeyDown={(e) =>
                      e.key === "Enter" &&
                      canExecuteScans &&
                      !loading &&
                      handleScan()
                    }
                    placeholder="10.180.6.0/24   ·   10.180.6.1-50"
                    disabled={loading || !canExecuteScans}
                    autoFocus
                  />
                </div>
                <button
                  className="ns-browse-btn"
                  onClick={() => fileInputRef.current.click()}
                  disabled={loading || !canExecuteScans}
                >
                  📂 Upload File
                </button>
              </div>
            </div>
            {uploadSummary.show && (
              <div className="ns-upload-summary">
                <div className="ns-summary-content">
                  <div className="ns-summary-main">
                    <span className="ns-summary-stat">
                      Total: <strong>{uploadSummary.total}</strong>
                    </span>
                    <span className="ns-summary-stat ns-stat--valid">
                      Valid: <strong>{uploadSummary.valid}</strong>
                    </span>
                    {uploadSummary.invalid > 0 && (
                      <span className="ns-summary-stat ns-stat--invalid">
                        Invalid: <strong>{uploadSummary.invalid}</strong>
                      </span>
                    )}
                    {uploadSummary.duplicates > 0 && (
                      <span className="ns-summary-stat ns-stat--dup">
                        Duplicates: <strong>{uploadSummary.duplicates}</strong>
                      </span>
                    )}
                  </div>
                  {uploadSummary.invalid > 0 && (
                    <p className="ns-summary-hint">
                      Some invalid entries were ignored.
                      <button
                        className="ns-export-btn"
                        onClick={() => {
                          const blob = new Blob(
                            [uploadSummary.invalidEntries.join("\n")],
                            { type: "text/plain" },
                          );
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = "invalid_targets.txt";
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                      >
                        📥 Export Invalid
                      </button>
                    </p>
                  )}
                </div>
                <button
                  className="ns-summary-close"
                  onClick={() => {
                    setUploadSummary((p) => ({ ...p, show: false }));
                    setParsedTargets([]);
                  }}
                >
                  ×
                </button>
              </div>
            )}

            {/* Target List Preview Grid */}
            {parsedTargets.length > 0 && (
              <div className="ns-preview-section">
                <div className="ns-preview-header">
                  <span className="ns-label">Target List Preview</span>
                  <button
                    className="ns-preview-clear"
                    onClick={() => {
                      setParsedTargets([]);
                      setTarget("");
                      setUploadSummary((p) => ({ ...p, show: false }));
                    }}
                  >
                    Clear Targets
                  </button>
                </div>
                <div className="ns-preview-table-wrap">
                  <table className="ns-preview-table">
                    <thead>
                      <tr>
                        <th className="ns-pt-idx">#</th>
                        <th>Target Value</th>
                        <th>Type</th>
                        <th
                          style={{ textAlign: "right", paddingRight: "20px" }}
                        >
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {parsedTargets.map((pt, idx) => (
                        <tr key={idx}>
                          <td className="ns-pt-idx">{idx + 1}</td>
                          <td className="ns-pt-val">{pt.value}</td>
                          <td>
                            <span
                              className={`ns-pt-badge ns-pt-badge--${pt.type.toLowerCase()}`}
                            >
                              {pt.type}
                            </span>
                          </td>
                          <td
                            style={{ textAlign: "right", paddingRight: "10px" }}
                          >
                            <button
                              type="button"
                              onClick={() => handleRemoveTarget(idx)}
                              title="Remove target"
                              style={{
                                background: "transparent",
                                border: "none",
                                color: "#ef4444",
                                cursor: "pointer",
                                fontSize: "0.78rem",
                                fontWeight: "600",
                                padding: "4px 10px",
                                borderRadius: "6px",
                                transition: "all 0.15s ease",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: "4px",
                              }}
                              onMouseEnter={(e) => {
                                e.currentTarget.style.background =
                                  "rgba(239, 68, 68, 0.08)";
                              }}
                              onMouseLeave={(e) => {
                                e.currentTarget.style.background =
                                  "transparent";
                              }}
                            >
                              ❌ Remove
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            <div className="ns-chips">
              <span className="ns-chips-label">Quick:</span>
              {QUICK_TARGETS.map((t) => (
                <button
                  key={t}
                  className="ns-chip"
                  onClick={() => setTarget(t)}
                  disabled={loading || !canExecuteScans}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
          {pipelineMode === "asset" && (
            <>
              <div className="ns-divider" />
              <div className="ns-section">
                <div className="ns-label">Discovery Profile</div>
                <div className="ns-segmented-control">
                  {DISCOVERY_INTENSITIES.map((di) => (
                    <button
                      key={di.value}
                      type="button"
                      className={`ns-segmented-btn ${discoveryIntensity === di.value ? "ns-segmented-btn--active" : ""}`}
                      onClick={() => setDiscoveryIntensity(di.value)}
                      disabled={loading || !canExecuteScans}
                    >
                      <span className="ns-segmented-icon">{di.icon}</span>
                      {di.label}
                    </button>
                  ))}
                </div>
                {(() => {
                  const activeDi = DISCOVERY_INTENSITIES.find(
                    (di) => di.value === discoveryIntensity,
                  );
                  return activeDi ? (
                    <div className="ns-segmented-desc">
                      {activeDi.desc}
                      {activeDi.badge && (
                        <span
                          className="ns-desc-badge"
                          style={activeDi.badgeStyle}
                        >
                          {activeDi.badge}
                        </span>
                      )}
                    </div>
                  ) : null;
                })()}
              </div>
            </>
          )}

          {(pipelineMode === "advanced" ||
            pipelineMode === "vulnerability_audit") && (
            <>
              <div className="ns-divider" />
              <div className="ns-section">
                <div className="ns-label">Scan Profile</div>
                <div className="ns-segmented-control">
                  {SCAN_INTENSITIES.map((si) => (
                    <button
                      key={si.value}
                      type="button"
                      className={`ns-segmented-btn ${intensity === si.value ? "ns-segmented-btn--active" : ""}`}
                      onClick={() => setIntensity(si.value)}
                      disabled={loading || !canExecuteScans}
                    >
                      <span className="ns-segmented-icon">{si.icon}</span>
                      {si.label}
                    </button>
                  ))}
                </div>
                {(() => {
                  const activeSi = SCAN_INTENSITIES.find(
                    (si) => si.value === intensity,
                  );
                  return activeSi ? (
                    <div className="ns-segmented-desc">{activeSi.desc}</div>
                  ) : null;
                })()}
              </div>
            </>
          )}

          {/* Advanced Settings Trigger Button */}
          <button
            type="button"
            className="ns-drawer-trigger-btn"
            onClick={() => setShowAdvanced(true)}
            disabled={loading}
          >
            ⚙️ Configure Advanced Settings
          </button>

          {error && <div className="ns-error">⚠ {error}</div>}
          <div className="ns-divider" />
          <button
            id="ns-start-btn"
            className="ns-start-btn"
            onClick={handleScan}
            disabled={
              loading || !target.trim() || !canExecuteScans || quotaBlocked
            }
          >
            {btnLabel} →
          </button>
        </div>
      </div>

      {/* Slide-out Drawer for Advanced Settings */}
      <div
        className={`ns-drawer-backdrop ${showAdvanced ? "ns-drawer-backdrop--open" : ""}`}
        onClick={() => setShowAdvanced(false)}
      />
      <div className={`ns-drawer ${showAdvanced ? "ns-drawer--open" : ""}`}>
        <div className="ns-drawer-header">
          <div className="ns-drawer-title-wrap">
            <span className="ns-drawer-icon">⚙️</span>
            <span className="ns-drawer-title">Advanced Settings</span>
          </div>
          <button
            type="button"
            className="ns-drawer-close"
            onClick={() => setShowAdvanced(false)}
            title="Close Settings (Esc)"
          >
            ✕
          </button>
        </div>

        <div className="ns-drawer-body">
          {/* 1. Port Scan Configuration (Asset Discovery Mode Only) */}
          {pipelineMode === "asset" && (
            <>
              <div className="ns-adv-section">
                <div className="ns-label">Scan Configuration Model</div>
                <div className="ns-scan-type-cards">
                  <div
                    className={`ns-type-card ${portScanMode === "intensity" ? "ns-type-card--selected" : ""}`}
                    onClick={() => setPortScanMode("intensity")}
                  >
                    <div className="ns-type-card-icon">⚡</div>
                    <div className="ns-type-card-title">
                      Intensity-Based Scan
                    </div>
                    <div className="ns-type-card-desc">
                      Predefined scan depths (Light, Normal, Deep) without
                      selecting individual ports.
                    </div>
                  </div>
                  <div
                    className={`ns-type-card ${portScanMode === "port" ? "ns-type-card--selected" : ""}`}
                    onClick={() => setPortScanMode("port")}
                  >
                    <div className="ns-type-card-icon">🔌</div>
                    <div className="ns-type-card-title">Port-Based Scan</div>
                    <div className="ns-type-card-desc">
                      Select predefined templates (IT, SCADA, Web, Database,
                      Remote) or input custom ports.
                    </div>
                  </div>
                </div>
              </div>

              {portScanMode === "intensity" ? (
                <div className="ns-adv-section" style={{ marginTop: "12px" }}>
                  <div className="ns-label" style={{ marginBottom: "8px" }}>
                    Port Scan Intensity{" "}
                    <span className="ns-label-hint">
                      depth of Phase 2 port scan
                    </span>
                  </div>
                  <div className="ns-segmented-control">
                    {PORT_SCAN_INTENSITIES.map((pi) => (
                      <button
                        key={pi.value}
                        type="button"
                        className={`ns-segmented-btn ${portScanIntensity === pi.value ? "ns-segmented-btn--active" : ""}`}
                        onClick={() => setPortScanIntensity(pi.value)}
                        disabled={loading || !canExecuteScans}
                      >
                        <span className="ns-segmented-icon">{pi.icon}</span>
                        {pi.label}
                      </button>
                    ))}
                  </div>
                  {(() => {
                    const activePi = PORT_SCAN_INTENSITIES.find(
                      (pi) => pi.value === portScanIntensity,
                    );
                    return activePi ? (
                      <div className="ns-segmented-desc">{activePi.desc}</div>
                    ) : null;
                  })()}
                </div>
              ) : (
                <div className="ns-adv-section" style={{ marginTop: "12px" }}>
                  <div className="ns-label" style={{ marginBottom: "8px" }}>
                    Port Profile
                  </div>
                  <div
                    className="ns-select-wrap"
                    style={{ marginBottom: "12px" }}
                  >
                    <select
                      className="ns-select ns-port-profile-select"
                      value={portProfile}
                      onChange={(e) => setPortProfile(e.target.value)}
                      disabled={loading || !canExecuteScans}
                    >
                      {Object.entries(PORT_PROFILES).map(([key, prof]) => (
                        <option key={key} value={key}>
                          {prof.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Port pills display for predefined profiles */}
                  {portProfile !== "custom" &&
                    PORT_PROFILES[portProfile]?.ports && (
                      <div
                        className="ns-port-pills-section"
                        style={{ marginBottom: "12px" }}
                      >
                        <div
                          className="ns-label-hint"
                          style={{ marginBottom: "6px" }}
                        >
                          Included Ports (
                          {PORT_PROFILES[portProfile].ports.split(",").length}{" "}
                          total)
                        </div>
                        <div className="ns-port-pills-wrap">
                          {PORT_PROFILES[portProfile].ports
                            .split(",")
                            .map((pStr) => {
                              const pNum = parseInt(pStr, 10);
                              const isSensitive =
                                SENSITIVE_PORTS.includes(pNum);
                              return (
                                <span
                                  key={pStr}
                                  className={`ns-port-pill ${isSensitive ? "ns-port-pill--sensitive" : ""}`}
                                >
                                  {pStr}
                                </span>
                              );
                            })}
                        </div>
                      </div>
                    )}

                  {/* Custom Ports Input (when profile = custom) */}
                  {portProfile === "custom" && (
                    <div style={{ marginTop: "12px" }}>
                      <div className="ns-label" style={{ marginBottom: "8px" }}>
                        Custom Ports / Ranges{" "}
                        <span className="ns-label-hint">
                          e.g. 22, 80, 443, 8080-8090
                        </span>
                      </div>
                      <div className="ns-input-wrap">
                        <span className="ns-input-icon">🔌</span>
                        <input
                          type="text"
                          className="ns-input"
                          value={customPorts}
                          onChange={(e) =>
                            handleCustomPortsChange(e.target.value)
                          }
                          placeholder="e.g. 22,80,443,8000-8100"
                          disabled={loading || !canExecuteScans}
                        />
                      </div>

                      <div className="ns-chips" style={{ marginTop: "10px" }}>
                        <span className="ns-chips-label">Presets:</span>
                        {Object.entries(PORT_PROFILES)
                          .filter(([k]) => k !== "custom")
                          .map(([k, prof]) => (
                            <button
                              key={k}
                              type="button"
                              className="ns-chip"
                              onClick={() =>
                                handleCustomPortsChange(prof.ports)
                              }
                              disabled={loading || !canExecuteScans}
                            >
                              {prof.label}
                            </button>
                          ))}
                      </div>

                      {customPortsError && (
                        <div
                          className="ns-error"
                          style={{
                            marginTop: "8px",
                            background: "rgba(239,68,68,0.08)",
                            border: "1px solid rgba(239,68,68,0.2)",
                            color: "#ef4444",
                            padding: "10px",
                            borderRadius: "8px",
                            fontSize: "0.85rem",
                          }}
                        >
                          ⚠ {customPortsError}
                        </div>
                      )}

                      {!customPortsError && parsedCustomPortsCount > 0 && (
                        <div
                          className="ns-estimation-banner"
                          style={{
                            marginTop: "12px",
                            background: "rgba(34,197,94,0.06)",
                            border: "1px solid rgba(34,197,94,0.15)",
                            color: "#4ade80",
                            padding: "12px",
                            borderRadius: "8px",
                            fontSize: "0.85rem",
                          }}
                        >
                          <div
                            style={{
                              fontWeight: "600",
                              marginBottom: "4px",
                              color: "#22c55e",
                            }}
                          >
                            ⚡ Scan Estimation
                          </div>
                          <div
                            style={{
                              color: "#a3a3a3",
                              display: "grid",
                              gridTemplateColumns: "auto 1fr",
                              gap: "4px 12px",
                            }}
                          >
                            <span>Unique ports:</span>{" "}
                            <strong style={{ color: "#e5e5e5" }}>
                              {parsedCustomPortsCount}
                            </strong>
                            <span>Est. packets per host:</span>{" "}
                            <strong style={{ color: "#e5e5e5" }}>
                              {parsedCustomPortsCount} packets
                            </strong>
                            <span>Est. duration per host:</span>{" "}
                            <strong style={{ color: "#e5e5e5" }}>
                              {Math.max(
                                1,
                                Math.round(parsedCustomPortsCount / 50),
                              )}{" "}
                              -{" "}
                              {Math.max(
                                2,
                                Math.round(parsedCustomPortsCount / 10),
                              )}{" "}
                              seconds
                            </strong>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {/* Exclude Ports Section */}
          <div
            className="ns-adv-section ns-exclude-section"
            style={{
              borderTop: "1.5px solid var(--border)",
              paddingTop: "16px",
            }}
          >
            <div className="ns-inline-row">
              <div className="ns-inline-label">
                <span className="ns-label-main">🚫 Exclude Specific Ports</span>
                <span className="ns-label-hint">
                  Exclude sensitive or firewalled ports from scanning
                </span>
              </div>
              <div className="ns-switch-wrapper">
                <label className="ns-switch">
                  <input
                    type="checkbox"
                    checked={excludePortsEnabled}
                    onChange={(e) =>
                      handleExcludeToggleChange(e.target.checked)
                    }
                  />
                  <span className="ns-slider round"></span>
                </label>
              </div>
            </div>

            {excludePortsEnabled && (
              <div style={{ marginTop: "12px" }}>
                <div className="ns-input-wrap">
                  <span className="ns-input-icon">🚫</span>
                  <input
                    type="text"
                    className="ns-input"
                    value={excludePorts}
                    onChange={(e) => setExcludePorts(e.target.value)}
                    placeholder="e.g. 2375,2376,6443,10250 or 80-90"
                    disabled={loading || !canExecuteScans}
                  />
                </div>

                {excludeTokens.length > 0 && (
                  <div
                    className="ns-exclude-tags-wrap"
                    style={{
                      marginTop: "8px",
                      display: "flex",
                      flexWrap: "wrap",
                      gap: "6px",
                    }}
                  >
                    {excludeTokens.map((token, idx) => (
                      <span key={`${token}-${idx}`} className="ns-exclude-tag">
                        {token}
                        <button
                          type="button"
                          className="ns-exclude-tag-remove"
                          onClick={() => handleRemoveExcludeToken(token)}
                          disabled={loading || !canExecuteScans}
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                )}

                <div className="ns-chips" style={{ marginTop: "8px" }}>
                  <span className="ns-chips-label">Quick:</span>
                  <button
                    type="button"
                    className="ns-chip"
                    onClick={() => setExcludePorts("2375,2376,6443,10250")}
                    disabled={loading || !canExecuteScans}
                  >
                    Exclude Sensitive Ports
                  </button>
                </div>

                {excludePortsError && (
                  <div
                    className="ns-error"
                    style={{
                      marginTop: "8px",
                      background: "rgba(239,68,68,0.08)",
                      border: "1px solid rgba(239,68,68,0.2)",
                      color: "#ef4444",
                      padding: "10px",
                      borderRadius: "8px",
                      fontSize: "0.85rem",
                    }}
                  >
                    ⚠ {excludePortsError}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Exclude IPs Section */}
          <div
            className="ns-adv-section ns-exclude-section"
            style={{
              borderTop: "1.5px solid var(--border)",
              paddingTop: "16px",
            }}
          >
            <div className="ns-inline-row">
              <div className="ns-inline-label">
                <span className="ns-label-main">
                  🚫 Exclude Specific IPs / Subnets
                </span>
                <span className="ns-label-hint">
                  Exclude sensitive target hosts or subnets from scanning
                </span>
              </div>
              <div className="ns-switch-wrapper">
                <label className="ns-switch">
                  <input
                    type="checkbox"
                    checked={excludeIpsEnabled}
                    onChange={(e) =>
                      handleExcludeIpsToggleChange(e.target.checked)
                    }
                  />
                  <span className="ns-slider round"></span>
                </label>
              </div>
            </div>

            {excludeIpsEnabled && (
              <div style={{ marginTop: "12px" }}>
                <div className="ns-input-wrap">
                  <span className="ns-input-icon">🚫</span>
                  <input
                    type="text"
                    className="ns-input"
                    value={excludeIps}
                    onChange={(e) => setExcludeIps(e.target.value)}
                    placeholder="e.g. 10.180.12.10,10.190.0.0/16"
                    disabled={loading || !canExecuteScans}
                  />
                </div>

                {excludeIpsError && (
                  <div
                    className="ns-error"
                    style={{
                      marginTop: "8px",
                      background: "rgba(239,68,68,0.08)",
                      border: "1px solid rgba(239,68,68,0.2)",
                      color: "#ef4444",
                      padding: "10px",
                      borderRadius: "8px",
                      fontSize: "0.85rem",
                    }}
                  >
                    ⚠ {excludeIpsError}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Sensitive Warning Banner */}
          {sensitivePortsFound && (
            <div
              className="ns-sensitive-banner"
              style={{
                marginTop: "12px",
                background: "rgba(245,158,11,0.08)",
                borderLeft: "3px solid #f59e0b",
                color: "#fbbf24",
                padding: "12px",
                borderRadius: "8px",
                fontSize: "0.85rem",
              }}
            >
              <div style={{ fontWeight: "600", marginBottom: "4px" }}>
                ⚠️ Sensitive Ports Detected
              </div>
              <p style={{ margin: 0, color: "#d4d4d8" }}>
                Your selection includes sensitive ports (Docker API{" "}
                <code>2375/2376</code>, Kubernetes <code>6443/10250</code>).
                While these are allowed, scanning them can trigger intrusion
                detection systems or crash services if they are not configured
                correctly.
              </p>
            </div>
          )}

          {/* Live Preview Panel (Asset mode only) */}
          {pipelineMode === "asset" && (
            <div className="ns-scan-preview" style={{ marginTop: "16px" }}>
              <div className="ns-scan-preview-header">
                🎯 Scan Configuration Preview
              </div>
              <div className="ns-scan-preview-grid">
                <div className="ns-preview-item">
                  <span className="ns-preview-label">Scan Type</span>
                  <span className="ns-preview-val">{preview.typeLabel}</span>
                </div>
                <div className="ns-preview-item">
                  <span className="ns-preview-label">
                    Target Profile / Depth
                  </span>
                  <span className="ns-preview-val">
                    {preview.targetPortsLabel}
                  </span>
                </div>
                <div className="ns-preview-item">
                  <span className="ns-preview-label">Ports Count</span>
                  <span className="ns-preview-val">{preview.finalCount}</span>
                </div>
                <div className="ns-preview-item">
                  <span className="ns-preview-label">Excluded Ports</span>
                  <span className="ns-preview-val">
                    {preview.excludedLabel}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* 2. OS Detection (shown for asset / advanced / vulnerability_audit) */}
          {(pipelineMode === "asset" ||
            pipelineMode === "advanced" ||
            pipelineMode === "vulnerability_audit") && (
            <div
              className="ns-inline-row"
              style={{
                borderTop: "1.5px solid var(--border)",
                paddingTop: "16px",
              }}
            >
              <div className="ns-inline-label">
                <span className="ns-label-main">OS Detection</span>
                <span className="ns-label-hint">
                  Fingerprint target operating systems
                </span>
              </div>
              <div className="ns-switch-wrapper">
                <label className="ns-switch">
                  <input
                    type="checkbox"
                    checked={osDetection}
                    onChange={(e) => setOsDetection(e.target.checked)}
                    disabled={loading || !canExecuteScans}
                  />
                  <span className="ns-slider round"></span>
                </label>
                <span className="ns-switch-status-text">
                  {osDetection ? "ON (Fingerprint)" : "OFF (Faster Scan)"}
                </span>
              </div>
            </div>
          )}

          {/* 3. Execution Mode (shown for asset / advanced / vulnerability_audit) */}
          {(pipelineMode === "asset" ||
            pipelineMode === "advanced" ||
            pipelineMode === "vulnerability_audit") && (
            <div className="ns-inline-row">
              <div className="ns-inline-label">
                <span className="ns-label-main">Execution Mode</span>
                <span className="ns-label-hint">
                  Automatic full chain vs interactive vetting
                </span>
              </div>
              <div className="ns-select-wrap">
                <select
                  className="ns-select"
                  value={executionMode}
                  onChange={(e) => setExecutionMode(e.target.value)}
                  disabled={loading || !canExecuteScans}
                >
                  <option value="automatic">Automatic (Full Chain)</option>
                  <option value="interactive">
                    Interactive (Vetted Steps)
                  </option>
                </select>
              </div>
            </div>
          )}

          {/* 4. Rate Limit (PPS) */}
          <div className="ns-adv-section">
            <div className="ns-label">
              Rate Limit (PPS){" "}
              <span className="ns-label-hint">limit packets per second</span>
            </div>
            <div className="ns-input-wrap">
              <span className="ns-input-icon">⏱</span>
              <input
                type="number"
                className="ns-input"
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value)}
                placeholder="e.g. 500"
                disabled={loading || !canExecuteScans}
              />
            </div>
          </div>

          {/* 5. Authenticated checks (Vulnerability Audit only).
              Credentials are a policy option on the ordinary scan, not a
              separate scan type: discovery, port scanning and unauthenticated
              checks run first, then each reachable host is logged into and the
              local results are merged into the same report. */}
          {(pipelineMode === "advanced" ||
            pipelineMode === "vulnerability_audit") && (
            <div
              className="ns-adv-section"
              style={{
                borderTop: "1.5px solid var(--border)",
                paddingTop: "16px",
              }}
            >
              <div className="ns-inline-row">
                <div className="ns-inline-label">
                  <span className="ns-label-main">
                    🔐 Authenticated Checks (Credentialed)
                  </span>
                  <span className="ns-label-hint">
                    Log in to each host and match installed packages, then
                    correlate with the port scan to find what is actually
                    exposed
                  </span>
                </div>
                <label className="ns-toggle">
                  <input
                    type="checkbox"
                    checked={credentialedEnabled}
                    onChange={(e) => setCredentialedEnabled(e.target.checked)}
                    disabled={loading || !canExecuteScans}
                  />
                  <span className="ns-toggle-slider" />
                </label>
              </div>

              {credentialedEnabled && (
                <div
                  style={{
                    marginTop: "12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "10px",
                  }}
                >
                  {credentialsList.length === 0 ? (
                    <p
                      className="ns-label-hint"
                      style={{ margin: 0, lineHeight: 1.6 }}
                    >
                      No stored credentials are registered for this
                      organisation. Add one under the Credentials Manager in{" "}
                      <button
                        type="button"
                        onClick={() => navigate("/compliance")}
                        style={{
                          background: "none",
                          border: "none",
                          color: "var(--accent)",
                          textDecoration: "underline",
                          padding: 0,
                          font: "inherit",
                          cursor: "pointer",
                        }}
                      >
                        Compliance
                      </button>
                      , then re-run this scan. Only stored credentials are
                      accepted here — a pipeline scan runs unattended, so
                      one-time credentials cannot be held for it.
                    </p>
                  ) : (
                    <>
                      <span
                        className="ns-label-hint"
                        style={{ lineHeight: 1.6 }}
                      >
                        Select the credentials to try. Each host is audited with
                        the first one whose scope covers it; hosts with no
                        matching credential, or with the SSH port closed, are
                        reported as unauthenticated and listed in the
                        scan&apos;s coverage.
                      </span>
                      {credentialsList.map((c) => {
                        const checked = selectedCredIds.includes(c.id);
                        return (
                          <label
                            key={c.id}
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 10,
                              fontSize: "0.84rem",
                              cursor: "pointer",
                            }}
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() =>
                                setSelectedCredIds((prev) =>
                                  checked
                                    ? prev.filter((id) => id !== c.id)
                                    : [...prev, c.id],
                                )
                              }
                              disabled={loading || !canExecuteScans}
                            />
                            <span style={{ fontWeight: 600 }}>{c.name}</span>
                            <span
                              className="ns-label-hint"
                              style={{ fontFamily: "var(--mono)" }}
                            >
                              {c.username}@:{c.port ?? 22}
                            </span>
                          </label>
                        );
                      })}
                    </>
                  )}
                </div>
              )}
            </div>
          )}

          {/* 6. SNMP / Network Topology (optional, all modes) */}
          <div
            className="ns-adv-section"
            style={{
              borderTop: "1.5px solid var(--border)",
              paddingTop: "16px",
            }}
          >
            <div className="ns-inline-row">
              <div className="ns-inline-label">
                <span className="ns-label-main">
                  🗺️ Network Topology (SNMP)
                </span>
                <span className="ns-label-hint">
                  Enable SNMP to discover network connections
                </span>
              </div>
              <label className="ns-toggle">
                <input
                  type="checkbox"
                  checked={snmpEnabled}
                  onChange={(e) => setSnmpEnabled(e.target.checked)}
                  disabled={loading || !canExecuteScans}
                />
                <span className="ns-toggle-slider" />
              </label>
            </div>

            {snmpEnabled && (
              <div
                className="ns-snmp-settings"
                style={{
                  marginTop: "12px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px",
                }}
              >
                <div className="ns-inline-row">
                  <div className="ns-inline-label">
                    <span className="ns-label-main">SNMP Version</span>
                  </div>
                  <div className="ns-select-wrap">
                    <select
                      className="ns-select"
                      value={snmpVersion}
                      onChange={(e) => setSnmpVersion(e.target.value)}
                      disabled={loading}
                    >
                      <option value="v1">v1</option>
                      <option value="v2c">v2c</option>
                      <option value="v3">v3</option>
                    </select>
                  </div>
                </div>

                {snmpVersion !== "v3" ? (
                  <div className="ns-adv-section">
                    <div className="ns-label">Community String</div>
                    <div className="ns-input-wrap">
                      <span className="ns-input-icon">🔑</span>
                      <input
                        type="text"
                        className="ns-input"
                        value={snmpCommunity}
                        onChange={(e) => setSnmpCommunity(e.target.value)}
                        placeholder="public"
                        disabled={loading}
                      />
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="ns-adv-section">
                      <div className="ns-label">Username</div>
                      <div className="ns-input-wrap">
                        <span className="ns-input-icon">👤</span>
                        <input
                          type="text"
                          className="ns-input"
                          value={snmpUsername}
                          onChange={(e) => setSnmpUsername(e.target.value)}
                          placeholder="SNMPv3 username"
                          disabled={loading}
                        />
                      </div>
                    </div>
                    <div className="ns-inline-row">
                      <div className="ns-inline-label">
                        <span className="ns-label-main">Auth Protocol</span>
                      </div>
                      <div className="ns-select-wrap">
                        <select
                          className="ns-select"
                          value={snmpAuthProtocol}
                          onChange={(e) => setSnmpAuthProtocol(e.target.value)}
                          disabled={loading}
                        >
                          <option value="MD5">MD5</option>
                          <option value="SHA">SHA</option>
                          <option value="SHA256">SHA-256</option>
                        </select>
                      </div>
                    </div>
                    <div className="ns-adv-section">
                      <div className="ns-label">Auth Passphrase</div>
                      <div className="ns-input-wrap">
                        <span className="ns-input-icon">🔐</span>
                        <input
                          type="password"
                          className="ns-input"
                          value={snmpAuthPassphrase}
                          onChange={(e) =>
                            setSnmpAuthPassphrase(e.target.value)
                          }
                          placeholder="Auth passphrase"
                          disabled={loading}
                        />
                      </div>
                    </div>
                    <div className="ns-inline-row">
                      <div className="ns-inline-label">
                        <span className="ns-label-main">Privacy Protocol</span>
                        <span className="ns-label-hint">optional</span>
                      </div>
                      <div className="ns-select-wrap">
                        <select
                          className="ns-select"
                          value={snmpPrivProtocol}
                          onChange={(e) => setSnmpPrivProtocol(e.target.value)}
                          disabled={loading}
                        >
                          <option value="">None (authNoPriv)</option>
                          <option value="DES">DES</option>
                          <option value="AES128">AES-128</option>
                          <option value="AES256">AES-256</option>
                        </select>
                      </div>
                    </div>
                    {snmpPrivProtocol && (
                      <div className="ns-adv-section">
                        <div className="ns-label">Privacy Passphrase</div>
                        <div className="ns-input-wrap">
                          <span className="ns-input-icon">🔒</span>
                          <input
                            type="password"
                            className="ns-input"
                            value={snmpPrivPassphrase}
                            onChange={(e) =>
                              setSnmpPrivPassphrase(e.target.value)
                            }
                            placeholder="Privacy passphrase"
                            disabled={loading}
                          />
                        </div>
                      </div>
                    )}
                    <div className="ns-adv-section">
                      <div className="ns-label">
                        Context Name{" "}
                        <span className="ns-label-hint">
                          optional, VLAN-aware switches
                        </span>
                      </div>
                      <div className="ns-input-wrap">
                        <span className="ns-input-icon">📋</span>
                        <input
                          type="text"
                          className="ns-input"
                          value={snmpContextName}
                          onChange={(e) => setSnmpContextName(e.target.value)}
                          placeholder="e.g. vlan-100"
                          disabled={loading}
                        />
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="ns-drawer-footer">
          <button
            type="button"
            className="ns-drawer-save-btn"
            onClick={() => setShowAdvanced(false)}
          >
            Save & Close
          </button>
        </div>
      </div>
    </AppLayout>
  );
}
