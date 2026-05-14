/**
 * src/pages/scan/NewScan.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Scan setup page with "Active Mission" view.
 *
 * VIEWS
 *   "setup"   → Target input + intensity selectors + Start button
 *   "mission" → Live scan console (progress ring, log stream, stats)
 *
 * On scan start → transitions to "mission" view (no redirect).
 * User must explicitly click:
 *   "Run in Background" → navigate to /scan-history
 *   "View Results"      → navigate to the correct results page (only when done)
 *   "← New Scan"        → resets and goes back to setup view
 */
import "../../styles/NewScan.css";
import { useState, useCallback, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import AppLayout from "../../components/layout/AppLayout";
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { buildPhasePayload, getScanPipeline } from "../../config/scanConfig";
import api from "../../api/axiosInstance";
import { can, denyMessage } from "../../auth/permissions";
import { useAuth } from "../../context/AuthContext";
import ScanQuotaBar from "../../components/scan/ScanQuotaBar";

/* ── Constants ─────────────────────────────────────────────────────────────── */

const DISCOVERY_INTENSITIES = [
  {
    value: "light",
    label: "Light",
    icon: "⚡",
    desc: "Fastest — may miss firewalled hosts",
    badge: "Fastest",
    badgeStyle: { background: "rgba(34,211,238,0.12)", color: "#22d3ee", border: "1px solid rgba(34,211,238,0.3)" },
  },
  {
    value: "normal",
    label: "Normal",
    icon: "⚖",
    desc: "Fast-first with coverage fallback",
    badge: "Recommended",
    badgeStyle: { background: "rgba(34,197,94,0.12)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.3)" },
  },
  {
    value: "deep",
    label: "Deep",
    icon: "🔬",
    desc: "Max coverage — best for firewalled nets",
    badge: "Thorough",
    badgeStyle: { background: "rgba(245,158,11,0.12)", color: "#d97706", border: "1px solid rgba(245,158,11,0.3)" },
  },
];

const SCAN_INTENSITIES = [
  { value: "light", label: "Light", icon: "🏃", desc: "Fast scan, fewer ports" },
  { value: "normal", label: "Normal", icon: "⚖", desc: "Balanced port coverage" },
  { value: "deep", label: "Deep", icon: "🔭", desc: "Full port range scan" },
];

const QUICK_TARGETS = ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24", "192.168.1.1"];

const PIPELINE_BADGE = {
  basic: { label: "Basic Scan", cls: "ns-badge--basic" },
  asset: { label: "Asset Discovery", cls: "ns-badge--asset" },
  advanced: { label: "Advanced Scan", cls: "ns-badge--advanced" },
};

/* ── Helpers ───────────────────────────────────────────────────────────────── */

const fmtTime = (date) =>
  date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

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
  const hostname = host.hostname && host.hostname !== "Unknown" ? host.hostname : null;
  const mac = host.mac_address && host.mac_address !== "N/A" ? host.mac_address : null;
  
  // Track enrichment state for each field
  const isEnrichingHostname = host._enriching_hostname === true;
  const isEnrichingMac = host._enriching_mac === true;
  
  // Determine display content
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
      <div className="am-host-col-ip" title={host.ip_address}>{host.ip_address}</div>
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

function ActiveMission({ scanState, onRunInBackground, onViewResults, onNewScan }) {
  const { target, scanNo, pipelineMode } = scanState;
  const { status, progress, discovered, totalIps, discoveredHosts, newHostIps, startMs, error } = scanState;

  const [elapsed, setElapsed] = useState("0s");
  const hostsListRef = useRef(null);

  // Elapsed timer
  useEffect(() => {
    if (status === "running") {
      const id = setInterval(() => setElapsed(fmtElapsed(startMs)), 1000);
      return () => clearInterval(id);
    }
  }, [status, startMs]);

  // Auto-scroll hosts list to bottom when new hosts arrive
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

  const dotClass = isFailed ? "am-live-dot--failed" : isComplete ? "am-live-dot--complete" : "";
  const ringClass = isFailed ? "am-ring-fill--failed" : isComplete ? "am-ring-fill--complete" : "";
  const badgeClass = isFailed ? "am-status-badge--failed" : isComplete ? "am-status-badge--complete" : "am-status-badge--running";
  const badgeLabel = isFailed ? "Failed" : isComplete ? "Complete" : "Live Scanning";
  const stripClass = isFailed ? "am-progress-strip-fill--failed" : isComplete ? "am-progress-strip-fill--complete" : "";

  const pipelineLabel = { basic: "Host Discovery", asset: "Asset Discovery", advanced: "Advanced Scan" }[pipelineMode] || "Scan";

  return (
    <div className="am-page">
      {/* Top-bar */}
      <div className="am-topbar">
        <div className="am-topbar-left">
          <span className={`am-live-dot ${dotClass}`} />
          <span className="am-mission-label">Active Mission</span>
          {scanNo && <span className="am-scan-no">#{scanNo}</span>}
        </div>
        <div className="am-actions">
          {!isComplete && !isFailed && (
            <button className="am-btn-bg" onClick={onRunInBackground}>
              📥 Run in Background
            </button>
          )}
          <button className="am-btn-new" onClick={onNewScan}>
            ← New Scan
          </button>
        </div>
      </div>

      {/* Main console card */}
      <div className="am-card">

        {/* Dark console header */}
        <div className="am-console-header">
          <div className="am-console-header-left">
            {/* SVG progress ring */}
            <div className="am-progress-ring-wrap">
              <svg className="am-progress-ring" viewBox="0 0 52 52">
                <circle className="am-ring-track" cx="26" cy="26" r={RING_R} />
                <circle
                  className={`am-ring-fill ${ringClass}`}
                  cx="26" cy="26" r={RING_R}
                  strokeDasharray={RING_C}
                  strokeDashoffset={offset}
                />
              </svg>
              <div className="am-ring-pct">{pct}%</div>
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

        {/* Progress strip */}
        <div className="am-progress-strip">
          <div className={`am-progress-strip-fill ${stripClass}`} style={{ width: `${pct}%` }} />
        </div>

        {/* Stats bar */}
        <div className="am-stats-bar">
          <div className="am-stat">
            <span className={`am-stat-value ${discovered > 0 ? "am-stat-value--green" : ""}`}>
              {discovered}
            </span>
            <span className="am-stat-label">Hosts Found</span>
          </div>
          <div className="am-stat">
            <span className="am-stat-value am-stat-value--accent">{totalIps || "—"}</span>
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

        {/* Live discovered hosts panel */}
        <div className="am-hosts-panel">
          <div className="am-hosts-header">
            <div className="am-hosts-header-left">
              <span className="am-hosts-icon">🖥</span>
              <span className="am-hosts-title">Discovered Systems</span>
              {discoveredHosts.length > 0 && (
                <span className="am-hosts-count-badge">{discoveredHosts.length}</span>
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
                <span>Results will appear here as hosts are discovered.</span>
              </div>
            </div>
          ) : (
            <div className="am-hosts-list" ref={hostsListRef}>
              {discoveredHosts.map(h => (
                <HostCard
                  key={h.ip_address}
                  host={h}
                  isNew={newHostIps.includes(h.ip_address)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="am-console-footer">
          <span className="am-footer-elapsed">
            {isRunning ? `Elapsed: ${elapsed}` : isComplete ? "Scan complete" : "Scan ended"}
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

      {/* Error banner */}
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
  const { user } = useAuth();
  const canExecuteScans = can(user, "scans", "execute");

  const {
    target, setTarget,
    pipelineMode,
    intensity, setIntensity,
    discoveryIntensity, setDiscoveryIntensity,
    setPhase1Hosts, setPhase1Summary,
    setScanId, setScanNo, setSaveStatus,
    setPipelineState,
    scanId: ctxScanId,
    scanNo: ctxScanNo,
  } = useScan();

  const [view, setView] = useState("setup");  // "setup" | "mission"
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [quotaBlocked, setQuotaBlocked] = useState(false);

  // Mission-view state
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
  const missionScanIdRef  = useRef(null);
  const pollHostsRef      = useRef(null);
  const hostFirstSeenRef  = useRef(new Map()); // ip → time string

  const pipeline  = getScanPipeline(pipelineMode || "basic");
  const badgeMeta = PIPELINE_BADGE[pipelineMode] || PIPELINE_BADGE.basic;

  const btnLabel = (() => {
    if (pipelineMode === "asset") {
      const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
      return `Start Discovery · ${cap(discoveryIntensity || "normal")}`;
    }
    return "Start Scan";
  })();

  /* ── Host polling ────────────────────────────────────────────────────────── */
  const startHostPolling = useCallback((scanId) => {
    if (pollHostsRef.current) clearInterval(pollHostsRef.current);
    pollHostsRef.current = setInterval(async () => {
      try {
        const { data: scan } = await api.get(`/scans/${scanId}`);
        const hosts = (scan?.results?.phase1?.data || []).filter(h => h.is_active);
        if (!hosts.length) return;
        const now = fmtTime(new Date());
        hosts.forEach(h => {
          if (!hostFirstSeenRef.current.has(h.ip_address))
            hostFirstSeenRef.current.set(h.ip_address, now);
        });
        const enriched = hosts.map(h => ({
          ...h,
          _seenAt: hostFirstSeenRef.current.get(h.ip_address),
          // Mark fields as enriching until enrichment pass completes
          _enriching_hostname: !h.hostname || h.hostname === "Unknown",
          _enriching_mac: !h.mac_address || h.mac_address === "N/A",
        }));
        setMissionState(prev => {
          const existingIps = new Set(prev.discoveredHosts.map(x => x.ip_address));
          const newOnes = enriched.filter(h => !existingIps.has(h.ip_address)).map(h => h.ip_address);
          if (newOnes.length > 0) {
            setTimeout(() => setMissionState(p => ({ ...p, newHostIps: [] })), 3000);
          }
          return { ...prev, discoveredHosts: enriched, newHostIps: newOnes, discovered: enriched.length };
        });
      } catch { /* ignore */ }
    }, 2500);
  }, []);

  const stopHostPolling = useCallback(() => {
    if (pollHostsRef.current) { clearInterval(pollHostsRef.current); pollHostsRef.current = null; }
  }, []);

  /* ── WebSocket progress listener ─────────────────────────────────────────── */
  const baseURL = api.defaults.baseURL || "";
  const wsPrefix = baseURL.replace(/^http/, "ws");

  const buildWsUrl = (scanId, ticket) =>
    `${wsPrefix}/scans/${scanId}/progress?ticket=${encodeURIComponent(ticket)}`;

  const listenForProgress = useCallback(async (scanId) => {
    let ticket;
    try {
      const res = await api.post("/auth/ticket");
      ticket = res.data.ticket;
    } catch {
      return null; // fall back to polling only
    }
    return new Promise((resolve) => {
      const ws = new WebSocket(buildWsUrl(scanId, ticket));
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const prog = data.progress || {};

          setMissionState(prev => {
            const next = {
              ...prev,
              totalIps: prog.total_ips ?? prev.totalIps,
              progress: prog.status === "complete" ? 100
                : prog.status === "failed" ? prev.progress
                : Math.max(prev.progress, Math.round(
                    ((prog.discovered || 0) / Math.max(prog.total_ips || 1, 1)) * 85
                  )),
            };

            // ── Live host injection from WS batch data ────────────────────
            const incomingHosts = prog.hosts;
            const isEnrichment  = prog.status === "enriching";


            if (Array.isArray(incomingHosts) && incomingHosts.length > 0) {
              const now = fmtTime(new Date());

              if (isEnrichment) {
                // ── Enrichment pass: merge by IP, update hostname/mac in-place
                // Clear enriching flags when data arrives, mark unchanged fields as done enriching
                const patchMap = new Map(incomingHosts.map(h => [h.ip_address, h]));
                const merged = prev.discoveredHosts.map(existing => {
                  const patch = patchMap.get(existing.ip_address);
                  if (!patch) return existing;
                  
                  const updated = {
                    ...existing,
                    // Only overwrite if the patched value is non-empty
                    hostname:     (patch.hostname    && patch.hostname    !== "Unknown") ? patch.hostname    : existing.hostname,
                    mac_address:  (patch.mac_address && patch.mac_address !== "N/A")    ? patch.mac_address : existing.mac_address,
                    vendor:       (patch.vendor      && patch.vendor      !== "Unknown") ? patch.vendor      : existing.vendor,
                  };
                  
                  // Clear enriching flags when enrichment data arrives for that field
                  // Even if the field is still empty, stop showing "Resolving…" after enrichment pass
                  if (patch.hostname !== undefined) updated._enriching_hostname = false;
                  if (patch.mac_address !== undefined) updated._enriching_mac = false;
                  
                  return updated;
                });
                
                // Also add any brand-new IPs that appear only in the enrichment pass
                const existingIps = new Set(prev.discoveredHosts.map(x => x.ip_address));
                const brandNew = incomingHosts
                  .filter(h => !existingIps.has(h.ip_address))
                  .map(h => ({ 
                    ...h, 
                    _seenAt: hostFirstSeenRef.current.get(h.ip_address) || now,
                    // New hosts don't need enriching - they already have data
                    _enriching_hostname: false,
                    _enriching_mac: false,
                  }));
                
                next.discoveredHosts = [...merged, ...brandNew];
                next.discovered      = next.discoveredHosts.length;
                // No glow animation for enrichment updates

              } else {
                // ── Discovery pass: append new hosts with entrance animation
                // Mark all hostname/mac fields as enriching
                incomingHosts.forEach(h => {
                  if (!hostFirstSeenRef.current.has(h.ip_address))
                    hostFirstSeenRef.current.set(h.ip_address, now);
                });
                const enriched = incomingHosts.map(h => ({
                  ...h,
                  _seenAt: hostFirstSeenRef.current.get(h.ip_address),
                  // Mark fields as enriching (will show "Resolving…") until enrichment pass completes
                  _enriching_hostname: !h.hostname || h.hostname === "Unknown",
                  _enriching_mac: !h.mac_address || h.mac_address === "N/A",
                }));
                const existingIps = new Set(prev.discoveredHosts.map(x => x.ip_address));
                const newIps = enriched
                  .filter(h => !existingIps.has(h.ip_address))
                  .map(h => h.ip_address);
                if (newIps.length > 0) {
                  setTimeout(() => setMissionState(p => ({ ...p, newHostIps: [] })), 3000);
                }
                next.discoveredHosts = enriched;
                next.discovered      = enriched.length;
                next.newHostIps      = newIps;
              }
            }


            return next;
          });

          const isDone = prog.status === "complete" || prog.status === "failed";
          if (isDone || data.phase > 1) { ws.close(); resolve({ status: prog.status || "complete" }); }
        } catch { /* ignore */ }
      };
      ws.onerror = () => { ws.close(); resolve({ status: "unknown" }); };
      setTimeout(() => { if (ws.readyState === WebSocket.OPEN) ws.close(); resolve({ status: "timeout" }); }, 600_000);
    });
  }, [wsPrefix]);


  /* ── Main scan handler ───────────────────────────────────────────────────── */
  const handleScan = async () => {
    if (!canExecuteScans) { setError(denyMessage); return; }
    if (!target.trim()) return;

    const trimmedTarget = target.trim();
    const startMs = Date.now();

    // Reset host tracking and transition to mission view
    hostFirstSeenRef.current = new Map();
    setMissionState({
      status: "running",
      progress: 5,
      discovered: 0,
      totalIps: 0,
      discoveredHosts: [],
      newHostIps: [],
      startMs,
      error: "",
      scanId: null,
      scanNo: null,
    });
    setView("mission");
    setLoading(true);
    setError("");
    setSaveStatus("saving");
    setPipelineState(PIPELINE_STATES.DISCOVERY);
    setTarget(trimmedTarget);

    try {
      const payload = buildPhasePayload(pipelineMode || "basic", {
        targets: trimmedTarget.split(",").map(t => t.trim()).filter(Boolean),
        scan_type: "adaptive",
        ...(pipelineMode === "asset" ? { discovery_intensity: discoveryIntensity } : {}),
        ...(rateLimit ? { rate_limit: parseInt(rateLimit, 10) } : {}),
      });

      const { data } = await api.post("/scan/host-discovery", payload);
      if (!data.success) throw new Error(data.error || "Scan failed to start");

      const scanId = data.scan_id;
      const scanNo = data.scan_no ?? data.display_id ?? null;
      missionScanIdRef.current = scanId;

      setScanId(scanId);
      setScanNo(scanNo);
      setMissionState(prev => ({ ...prev, scanId, scanNo, progress: 10 }));

      // Start host polling (every 2.5s) + WS progress listener in parallel
      startHostPolling(scanId);
      const result = await listenForProgress(scanId);
      stopHostPolling();

      const finalStatus = result?.status === "failed" ? "failed" : "complete";

      // Final fetch to populate ScanContext + complete host list
      try {
        const { data: fullScan } = await api.get(`/scans/${scanId}`);
        const activeHosts = (fullScan?.results?.phase1?.data || []).filter(h => h.is_active);
        setPhase1Hosts(fullScan?.results?.phase1?.data || []);
        setPhase1Summary(fullScan?.results?.phase1?.summary || {});
        const now = fmtTime(new Date());
        const enriched = activeHosts.map(h => ({
          ...h, _seenAt: hostFirstSeenRef.current.get(h.ip_address) || now,
        }));
        setMissionState(prev => ({
          ...prev,
          status: finalStatus,
          progress: finalStatus === "failed" ? prev.progress : 100,
          discovered: enriched.length,
          discoveredHosts: enriched,
          newHostIps: [],
        }));
      } catch {
        setMissionState(prev => ({ ...prev, status: finalStatus, progress: 100 }));
      }

      setSaveStatus("saved");
      setTimeout(() => setSaveStatus(""), 3000);

    } catch (err) {
      stopHostPolling();
      const msg = err.response?.data?.detail || err.message || "Scan failed";
      setMissionState(prev => ({ ...prev, status: "failed", error: msg }));
      setSaveStatus("error");
      setTimeout(() => setSaveStatus(""), 4000);
    } finally {
      setLoading(false);
    }
  };

  /* ── Mission action handlers ─────────────────────────────────────────────── */
  const handleRunInBackground = useCallback(() => {
    navigate("/scan-history");
  }, [navigate]);

  const handleViewResults = useCallback(() => {
    navigate(pipelineMode === "advanced" ? "/scan/advanced-scan" : "/scan/host-discovery");
  }, [navigate, pipelineMode]);

  const handleNewScan = useCallback(() => {
    stopHostPolling();
    hostFirstSeenRef.current = new Map();
    setView("setup");
    setMissionState({
      status: "running", progress: 0, discovered: 0, totalIps: 0,
      discoveredHosts: [], newHostIps: [], startMs: Date.now(), error: "", scanId: null, scanNo: null,
    });
    setLoading(false);
    setError("");
  }, [stopHostPolling]);

  /* ── Mission view ────────────────────────────────────────────────────────── */
  if (view === "mission") {
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
  }

  /* ── Setup view ──────────────────────────────────────────────────────────── */
  return (
    <AppLayout pageTitle="New Scan">
      <div className="ns-page">

        {/* Hero */}
        <div className="ns-hero">
          <button className="ns-back" onClick={() => navigate("/dashboard")}>
            ← Back
          </button>
          <div className={`ns-badge ${badgeMeta.cls}`}>
            {badgeMeta.label}
          </div>
          <h1 className="ns-title">{pipeline.label}</h1>
          <p className="ns-sub">{pipeline.description}</p>
        </div>

        {/* Quota bar */}
        <ScanQuotaBar
          onQuotaChange={({ quota_exceeded, concurrent_exceeded }) =>
            setQuotaBlocked(quota_exceeded || concurrent_exceeded)
          }
        />

        {/* Card */}
        <div className="ns-card">

          {/* Target input */}
          <div className="ns-section">
            <div className="ns-label">
              Target
              <span className="ns-label-hint">IP, CIDR, or range</span>
            </div>
            <div className="ns-input-wrap">
              <span className="ns-input-icon" aria-hidden="true">🎯</span>
              <input
                id="ns-target-input"
                className="ns-input"
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === "Enter" && canExecuteScans && !loading && handleScan()}
                placeholder="192.168.1.0/24   ·   10.0.0.1-50   ·   192.168.1.10"
                disabled={loading || !canExecuteScans}
                autoFocus
                autoComplete="off"
                spellCheck={false}
              />
            </div>

            {/* Quick targets */}
            <div className="ns-chips">
              <span className="ns-chips-label">Quick:</span>
              {QUICK_TARGETS.map(t => (
                <button
                  key={t}
                  className="ns-chip"
                  onClick={() => setTarget(t)}
                  disabled={loading || !canExecuteScans}
                  title={`Use ${t}`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Discovery Intensity — Asset only */}
          {pipelineMode === "asset" && (
            <>
              <div className="ns-divider" />
              <div className="ns-section">
                <div className="ns-label">
                  Discovery Intensity
                  <span className="ns-label-hint">Controls Phase 1 speed vs. coverage</span>
                </div>
                <div className="ns-intensity-grid">
                  {DISCOVERY_INTENSITIES.map(di => {
                    const isActive = discoveryIntensity === di.value;
                    return (
                      <button
                        key={di.value}
                        id={`discovery-intensity-${di.value}`}
                        className={[
                          "ns-int-card",
                          `ns-int--${di.value}`,
                          isActive ? "ns-int-card--active" : "",
                        ].join(" ")}
                        onClick={() => setDiscoveryIntensity(di.value)}
                        disabled={loading || !canExecuteScans}
                      >
                        <span className="ns-int-icon">{di.icon}</span>
                        <span className="ns-int-name">{di.label}</span>
                        <span className="ns-int-desc">{di.desc}</span>
                        {isActive && (
                          <span className="ns-int-badge" style={di.badgeStyle}>
                            {di.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {/* Scan Intensity — Advanced only */}
          {pipelineMode === "advanced" && (
            <>
              <div className="ns-divider" />
              <div className="ns-section">
                <div className="ns-label">Scan Intensity</div>
                <div className="ns-intensity-grid">
                  {SCAN_INTENSITIES.map(si => {
                    const isActive = intensity === si.value;
                    return (
                      <button
                        key={si.value}
                        id={`scan-intensity-${si.value}`}
                        className={[
                          "ns-int-card",
                          `ns-int--${si.value}`,
                          isActive ? "ns-int-card--active" : "",
                        ].join(" ")}
                        onClick={() => setIntensity(si.value)}
                        disabled={loading || !canExecuteScans}
                      >
                        <span className="ns-int-icon">{si.icon}</span>
                        <span className="ns-int-name">{si.label}</span>
                        <span className="ns-int-desc">{si.desc}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {/* Rate limit */}
          <div className="ns-divider" />
          <div className="ns-section">
            <div className="ns-label">
              Rate Limit (PPS)
              <span className="ns-label-hint">Leave blank for profile default (e.g., fast is 256)</span>
            </div>
            <div className="ns-input-wrap">
              <span className="ns-input-icon" aria-hidden="true">⏱</span>
              <input
                type="number"
                className="ns-input"
                value={rateLimit}
                onChange={e => setRateLimit(e.target.value)}
                placeholder="e.g. 500"
                disabled={loading || !canExecuteScans}
              />
            </div>
          </div>

          {/* Basic scan notice */}
          {pipelineMode === "basic" && (
            <>
              <div className="ns-divider" />
              <div className="ns-info-notice">
                <span className="ns-info-icon">💡</span>
                <p>
                  <strong>Basic Scan Mechanics:</strong> Uses ultra-fast <code>ARP</code> on local subnets.
                  For routed remote subnets, it falls back to a full TCP handshake on ports 80/443/22 to bypass firewalls, which may be significantly slower.
                </p>
              </div>
            </>
          )}

          {/* Error banner */}
          {error && (
            <div className="ns-error" role="alert">
              <span className="ns-error-icon">⚠</span>
              {error}
            </div>
          )}

          <div className="ns-divider" />

          {/* Start button */}
          <button
            id="ns-start-btn"
            className="ns-start-btn"
            onClick={handleScan}
            disabled={loading || !target.trim() || !canExecuteScans || quotaBlocked}
          >
            {btnLabel}
            <span className="ns-btn-arrow">→</span>
          </button>

        </div>{/* /ns-card */}
      </div>{/* /ns-page */}
    </AppLayout>
  );
}
