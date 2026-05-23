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
  advanced: { label: "Vulnerability Audit", cls: "ns-badge--advanced" },
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
      <div className="am-host-col-status"><span className="am-host-alive-dot" /></div>
      <div className="am-host-col-ip" title={host.ip_address}>{host.ip_address}</div>
      <div className={`am-host-col-hostname${isEnrichingHostname ? " am-enriching" : ""}`} title={hostname || ""}>
        {hostnameContent}
      </div>
      <div className={`am-host-col-mac${isEnrichingMac ? " am-enriching" : ""}`}>
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
  const isUnreachable = status === "unreachable" || (isComplete && discovered === 0);

  const dotClass = isFailed ? "am-live-dot--failed" : isUnreachable ? "am-live-dot--warning" : isComplete ? "am-live-dot--complete" : "";
  const ringClass = isFailed ? "am-ring-fill--failed" : isUnreachable ? "am-ring-fill--warning" : isComplete ? "am-ring-fill--complete" : "";
  const badgeClass = isFailed ? "am-status-badge--failed" : isUnreachable ? "am-status-badge--warning" : isComplete ? "am-status-badge--complete" : "am-status-badge--running";
  const badgeLabel = isFailed ? "Failed" : isUnreachable ? "Unreachable" : isComplete ? "Complete" : "Live Scanning";
  const stripClass = isFailed ? "am-progress-strip-fill--failed" : isUnreachable ? "am-progress-strip-fill--warning" : isComplete ? "am-progress-strip-fill--complete" : "";

  const pipelineLabel = { basic: "Host Discovery", asset: "Asset Discovery", advanced: "Vulnerability Audit" }[pipelineMode] || "Scan";

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
            <button className="am-btn-bg" onClick={onRunInBackground}>📥 Run in Background</button>
          )}
          <button className="am-btn-new" onClick={onNewScan}>← New Scan</button>
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
                  cx="26" cy="26" r={RING_R}
                  strokeDasharray={RING_C}
                  strokeDashoffset={offset}
                />
              </svg>
              <div className="am-ring-pct">{isUnreachable ? "!" : `${pct}%`}</div>
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
              <p>The host <code>{target}</code> did not respond to discovery probes.</p>
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
          <div className={`am-progress-strip-fill ${stripClass}`} style={{ width: isUnreachable ? "100%" : `${pct}%` }} />
        </div>

        <div className="am-stats-bar">
          <div className="am-stat">
            <span className={`am-stat-value ${discovered > 0 ? "am-stat-value--green" : ""}`}>{discovered}</span>
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

        <div className="am-hosts-panel">
          <div className="am-hosts-header">
            <div className="am-hosts-header-left">
              <span className="am-hosts-icon">🖥</span>
              <span className="am-hosts-title">Discovered Systems</span>
              {discoveredHosts.length > 0 && <span className="am-hosts-count-badge">{discoveredHosts.length}</span>}
            </div>
            {isRunning && <div className="am-hosts-scanning-label"><span className="am-hosts-scanning-dot" />scanning…</div>}
          </div>
          {discoveredHosts.length === 0 ? (
            <div className="am-hosts-empty">
              <div className="am-hosts-empty-radar">
                <div className="am-hosts-empty-ring" /><div className="am-hosts-empty-ring" /><div className="am-hosts-empty-ring" /><div className="am-hosts-empty-dot" />
              </div>
              <div className="am-hosts-empty-text">Scanning subnet… waiting for active hosts.</div>
            </div>
          ) : (
            <div className="am-hosts-list" ref={hostsListRef}>
              {discoveredHosts.map(h => (
                <HostCard key={h.ip_address} host={h} isNew={newHostIps.includes(h.ip_address)} />
              ))}
            </div>
          )}
        </div>

        <div className="am-console-footer">
          <span className="am-footer-elapsed">{isRunning ? `Elapsed: ${elapsed}` : isComplete ? "Scan complete" : "Scan ended"}</span>
          <div className="am-footer-actions">
            {!isComplete && !isFailed && <button className="am-btn-bg" onClick={onRunInBackground}>📥 Run in Background</button>}
            {isComplete && <button className="am-btn-view-results" onClick={onViewResults}>View Results →</button>}
            {isFailed && <button className="am-btn-new" onClick={onNewScan}>↩ Try Again</button>}
          </div>
        </div>
      </div>
      {error && <div className="am-error-card"><span>⚠️</span><span>{error}</span></div>}
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
    target, setTarget, pipelineMode, intensity, setIntensity, discoveryIntensity, setDiscoveryIntensity,
    setPhase1Hosts, setPhase1Summary, setPhase2Hosts, setPhase2Summary, setPhase2Results,
    setPhase3Results, setPhase3Summary, setPhase3AuditResults,
    setScanId, setScanNo, setSaveStatus, setPipelineState, setPipelineMode,
    autoRunAdvancedSingleTarget, setAutoRunAdvancedSingleTarget, ctxScanNo,
  } = useScan();

  const isActiveRoute = !!urlScanId;
  const [view, setView] = useState(isActiveRoute ? "mission" : "setup");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [quotaBlocked, setQuotaBlocked] = useState(false);
  const fileInputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [parsedTargets, setParsedTargets] = useState([]);
  const [uploadSummary, setUploadSummary] = useState({ total: 0, valid: 0, invalid: 0, invalidEntries: [], duplicates: 0, show: false });

  const [missionState, setMissionState] = useState({
    status: "running", progress: 0, discovered: 0, totalIps: 0,
    discoveredHosts: [], newHostIps: [], startMs: Date.now(), error: "", scanId: null, scanNo: null,
  });
  const missionScanIdRef = useRef(null);
  const pollHostsRef = useRef(null);
  const hostFirstSeenRef = useRef(new Map());
  const latestDiscoveredHostsRef = useRef([]);

  const pipeline = getScanPipeline(pipelineMode || "basic");
  const badgeMeta = PIPELINE_BADGE[pipelineMode] || PIPELINE_BADGE.basic;
  const btnLabel = pipelineMode === "asset" ? `Start Discovery · ${discoveryIntensity || "normal"}` : "Start Scan";

  const startHostPolling = useCallback((scanId) => {
    if (pollHostsRef.current) clearInterval(pollHostsRef.current);
    pollHostsRef.current = setInterval(async () => {
      try {
        const { data: scan } = await api.get(`/scans/${scanId}`);
        const hosts = (scan?.results?.phase1?.data || []).filter(h => h.is_active);
        if (!hosts.length) return;
        const now = fmtTime(new Date());
        hosts.forEach(h => { if (!hostFirstSeenRef.current.has(h.ip_address)) hostFirstSeenRef.current.set(h.ip_address, now); });
        const enriched = hosts.map(h => ({
          ...h, _seenAt: hostFirstSeenRef.current.get(h.ip_address),
          _enriching_hostname: !h.hostname || h.hostname === "Unknown",
          _enriching_mac: !h.mac_address || h.mac_address === "N/A",
        }));
        latestDiscoveredHostsRef.current = enriched;
        setMissionState(prev => {
          const existingIps = new Set(prev.discoveredHosts.map(x => x.ip_address));
          const newOnes = enriched.filter(h => !existingIps.has(h.ip_address)).map(h => h.ip_address);
          if (newOnes.length > 0) setTimeout(() => setMissionState(p => ({ ...p, newHostIps: [] })), 3000);
          return { ...prev, discoveredHosts: enriched, newHostIps: newOnes, discovered: enriched.length };
        });
      } catch { /* ignore */ }
    }, 2500);
  }, []);

  const stopHostPolling = useCallback(() => { if (pollHostsRef.current) { clearInterval(pollHostsRef.current); pollHostsRef.current = null; } }, []);

  const baseURL = api.defaults.baseURL || "";
  const wsPrefix = baseURL.replace(/^http/, "ws");
  const listenForProgress = useCallback(async (scanId) => {
    let ticket;
    try { const res = await api.post("/auth/ticket"); ticket = res.data.ticket; } catch { return null; }
    return new Promise((resolve) => {
      const ws = new WebSocket(`${wsPrefix}/scans/${scanId}/progress?ticket=${encodeURIComponent(ticket)}`);
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const prog = data.progress || {};
          setMissionState(prev => {
            const next = { ...prev, totalIps: prog.total_ips ?? prev.totalIps, progress: (prog.status === "complete" || prog.status === "unreachable") ? 100 : prog.status === "failed" ? prev.progress : Math.max(prev.progress, Math.round(((prog.discovered || 0) / Math.max(prog.total_ips || 1, 1)) * 85)) };
            const incomingHosts = prog.hosts;
            if (Array.isArray(incomingHosts) && incomingHosts.length > 0) {
              const now = fmtTime(new Date());
              if (prog.status === "enriching") {
                const patchMap = new Map(incomingHosts.map(h => [h.ip_address, h]));
                const merged = prev.discoveredHosts.map(existing => {
                  const patch = patchMap.get(existing.ip_address); if (!patch) return existing;
                  const updated = { ...existing, hostname: (patch.hostname && patch.hostname !== "Unknown") ? patch.hostname : existing.hostname, mac_address: (patch.mac_address && patch.mac_address !== "N/A") ? patch.mac_address : existing.mac_address, vendor: (patch.vendor && patch.vendor !== "Unknown") ? patch.vendor : existing.vendor };
                  if (patch.hostname !== undefined) updated._enriching_hostname = false; if (patch.mac_address !== undefined) updated._enriching_mac = false;
                  return updated;
                });
                const existingIps = new Set(prev.discoveredHosts.map(x => x.ip_address));
                const brandNew = incomingHosts.filter(h => !existingIps.has(h.ip_address)).map(h => ({ ...h, _seenAt: hostFirstSeenRef.current.get(h.ip_address) || now, _enriching_hostname: false, _enriching_mac: false }));
                next.discoveredHosts = [...merged, ...brandNew]; next.discovered = next.discoveredHosts.length; latestDiscoveredHostsRef.current = next.discoveredHosts;
              } else {
                incomingHosts.forEach(h => { if (!hostFirstSeenRef.current.has(h.ip_address)) hostFirstSeenRef.current.set(h.ip_address, now); });
                const enriched = incomingHosts.map(h => ({ ...h, _seenAt: hostFirstSeenRef.current.get(h.ip_address), _enriching_hostname: !h.hostname || h.hostname === "Unknown", _enriching_mac: !h.mac_address || h.mac_address === "N/A" }));
                const existingIps = new Set(prev.discoveredHosts.map(x => x.ip_address));
                const newIps = enriched.filter(h => !existingIps.has(h.ip_address)).map(h => h.ip_address);
                if (newIps.length > 0) setTimeout(() => setMissionState(p => ({ ...p, newHostIps: [] })), 3000);
                next.discoveredHosts = enriched; next.discovered = enriched.length; next.newHostIps = newIps; latestDiscoveredHostsRef.current = next.discoveredHosts;
              }
            }
            return next;
          });
          if (prog.status === "complete" || prog.status === "failed" || prog.status === "unreachable" || data.phase > 1) { ws.close(); resolve({ status: prog.status || "complete" }); }

        } catch { /* ignore */ }
      };
      ws.onerror = () => { ws.close(); resolve({ status: "unknown" }); };
      setTimeout(() => { if (ws.readyState === WebSocket.OPEN) ws.close(); resolve({ status: "timeout" }); }, 600000);
    });
  }, [wsPrefix]);

  const detectTargetType = (val) => {
    if (val.includes('/')) return 'CIDR';
    if (val.includes('-')) { const parts = val.split('-'); if (parts.length === 2) { const left = parts[0].trim(), right = parts[1].trim(); if (/^[0-9.]+$/.test(left) && left.includes('.') && /^[0-9.]+$/.test(right)) return 'Range'; } }
    if (/^[0-9a-fA-F:.]+$/.test(val) && (val.includes('.') || val.includes(':'))) return 'IP';
    return 'Hostname';
  };

  const processFile = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const rawTokens = event.target.result.replace(/\s*-\s*/g, "-").split(/[,\s;]+/).map(t => t.trim()).filter(Boolean);
      const valid = [], inv = [], seen = new Set(); let dups = 0;
      rawTokens.forEach(t => { const clean = t.replace(/[^\w.\-:/\[\]]/g, ""); if (!clean || clean.toLowerCase() === "target") return; if (seen.has(clean)) { dups++; return; } if (/^[\w.\-:/\[\]]+$/.test(clean)) { valid.push({ value: clean, type: detectTargetType(clean) }); seen.add(clean); } else inv.push(clean); });
      if (valid.length > 0) { setTarget(valid.map(r => r.value).join(", ")); setParsedTargets(valid); setUploadSummary({ total: valid.length + inv.length + dups, valid: valid.length, invalid: inv.length, invalidEntries: inv, duplicates: dups, show: true }); }
      else setError("No valid targets found.");
    };
    reader.readAsText(file);
  };

  const handleScan = async () => {
    if (!canExecuteScans || !target.trim()) return;
    const trimmedTarget = target.trim();
    hostFirstSeenRef.current = new Map(); latestDiscoveredHostsRef.current = [];
    setMissionState({ status: "running", progress: 5, discovered: 0, totalIps: 0, discoveredHosts: [], newHostIps: [], startMs: Date.now(), error: "", scanId: null, scanNo: null });
    setView("mission"); setLoading(true); setPipelineState(PIPELINE_STATES.DISCOVERY);
    try {
      const payload = buildPhasePayload(pipelineMode || "basic", { targets: trimmedTarget.split(",").map(t => t.trim()).filter(Boolean), scan_type: "adaptive", ...(pipelineMode === "asset" ? { discovery_intensity: discoveryIntensity } : {}), ...(rateLimit ? { rate_limit: parseInt(rateLimit, 10) } : {}) });
      const { data } = await api.post("/scan/host-discovery", payload); if (!data.success) throw new Error(data.error);
      const sid = data.scan_id, sno = data.scan_no ?? data.display_id;
      
      navigate(`/scan/active/${sid}`, { 
        replace: true, 
        state: { 
          missionMode: true,
          scanId: sid,
          scanNo: sno,
          target: trimmedTarget,
          pipelineMode: pipelineMode || "basic"
        } 
      });
    } catch (err) { stopHostPolling(); setMissionState(prev => ({ ...prev, status: "failed", error: err.message })); } finally { setLoading(false); }
  };

  const handleRunInBackground = useCallback(() => navigate("/scan-history"), [navigate]);
  const handleViewResults = useCallback(() => {
    if (pipelineMode === "asset") { navigate("/scan/asset-discovery"); return; }
    if (pipelineMode === "advanced" && autoRunAdvancedSingleTarget) { navigate("/scan/advanced-scan", { state: { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" } }); return; }
    navigate(pipelineMode === "advanced" ? "/scan/advanced-scan" : "/scan/host-discovery");
  }, [navigate, pipelineMode, autoRunAdvancedSingleTarget]);

  const handleNewScan = useCallback(() => { 
    stopHostPolling(); 
    navigate("/scan/new");
    setView("setup"); 
    setMissionState({ status: "running", progress: 0, discovered: 0, totalIps: 0, discoveredHosts: [], newHostIps: [], startMs: Date.now(), error: "", scanId: null, scanNo: null }); 
    setLoading(false); 
  }, [stopHostPolling, navigate]);

  const hasAutoRunRef = useRef(false);
  useEffect(() => {
    const effectiveScanId = location.state?.scanId || urlScanId;
    const isMission = (location.state?.missionMode || !!urlScanId);

    if (isMission && !hasAutoRunRef.current && effectiveScanId) {
      hasAutoRunRef.current = true;
      const { scanId, scanNo, target: rt, pipelineMode: rm } = location.state || { scanId: effectiveScanId };
      
      setView("mission");
      setMissionState(prev => ({ 
        ...prev, 
        scanId: effectiveScanId, 
        scanNo: scanNo || prev.scanNo, 
        status: "running", 
        progress: 10, 
        startMs: Date.now() 
      }));
      missionScanIdRef.current = effectiveScanId;
      if (rt) setTarget(rt);
      if (rm) setPipelineMode(rm);
      setScanId(effectiveScanId);
      if (scanNo) setScanNo(scanNo);

      startHostPolling(effectiveScanId);
      listenForProgress(effectiveScanId).then(res => {
        stopHostPolling();
        const fs = res?.status === "failed" ? "failed" : res?.status === "unreachable" ? "unreachable" : "complete";
        api.get(`/scans/${effectiveScanId}`).then(({ data: f }) => {
          const d = f?.results?.phase1?.data || latestDiscoveredHostsRef.current, active = d.filter(h => h.is_active);
          setPhase1Hosts(d); setPhase1Summary(f?.results?.phase1?.summary || {});
          setMissionState(prev => ({ ...prev, status: fs, progress: (fs === "failed" || fs === "unreachable") ? prev.progress : 100, discovered: active.length, discoveredHosts: active }));
          if (fs !== "failed" && fs !== "unreachable" && (rm || f?.pipeline_mode) !== "basic") {
            if ((rm || f?.pipeline_mode) === "advanced" && active.length === 1) navigate("/scan/advanced-scan", { replace: true, state: { autoRunAdvancedSingleTarget: true, startPhase: "PORT_SCAN" } });
            else navigate("/scan/asset-discovery", { replace: true });
          }
        });
      });
      
      // Clean up state but stay on the active URL
      if (location.state?.missionMode) {
        navigate(`/scan/active/${effectiveScanId}`, { replace: true, state: {} });
      }
    } else if (location.state?.autoRun && !hasAutoRunRef.current && canExecuteScans && target && !loading && !quotaBlocked) {
      hasAutoRunRef.current = true;
      navigate(".", { replace: true, state: {} });
      setTimeout(() => handleScan(), 100);
    }
  }, [location.state, urlScanId, canExecuteScans, target, loading, quotaBlocked, navigate, startHostPolling, listenForProgress, stopHostPolling, setTarget, setScanId, setScanNo, setPhase1Hosts, setPhase1Summary, handleScan]);

  if (view === "mission") return <AppLayout pageTitle="Active Scan Mission"><ActiveMission scanState={{ ...missionState, target, scanNo: missionState.scanNo ?? ctxScanNo, pipelineMode: pipelineMode || "basic" }} onRunInBackground={handleRunInBackground} onViewResults={handleViewResults} onNewScan={handleNewScan} /></AppLayout>;

  return (
    <AppLayout pageTitle="New Scan">
      <div className="ns-page">
        <div className="ns-hero">
          <button className="ns-back" onClick={() => navigate("/dashboard")}>← Back</button>
          <div className={`ns-badge ${badgeMeta.cls}`}>{badgeMeta.label}</div>
          <h1 className="ns-title">{pipeline.label}</h1>
          <p className="ns-sub">{pipeline.description}</p>
        </div>
        <ScanQuotaBar onQuotaChange={({ quota_exceeded, concurrent_exceeded }) => setQuotaBlocked(quota_exceeded || concurrent_exceeded)} />
        <div className="ns-card">
          <div className="ns-section">
            <div className="ns-label">Target <span className="ns-label-hint">IP, CIDR, or range</span></div>
            <input type="file" ref={fileInputRef} onChange={e => processFile(e.target.files[0])} accept=".txt,.csv" style={{ display: "none" }} />
            <div className={`ns-drop-zone ${isDragging ? 'ns-drop-zone--active' : ''}`} onDragOver={e => { e.preventDefault(); setIsDragging(true); }} onDragLeave={() => setIsDragging(false)} onDrop={e => { e.preventDefault(); setIsDragging(false); if (e.dataTransfer.files?.length) processFile(e.dataTransfer.files[0]); }}>
              <div className="ns-input-row">
                <div className="ns-input-wrap">
                  <span className="ns-input-icon">🎯</span>
                  <input className="ns-input" value={target} onChange={e => { setTarget(e.target.value); if (uploadSummary.show) setUploadSummary(p => ({ ...p, show: false })); if (parsedTargets.length) setParsedTargets([]); }} onKeyDown={e => e.key === "Enter" && canExecuteScans && !loading && handleScan()} placeholder="192.168.1.0/24   ·   10.0.0.1-50" disabled={loading || !canExecuteScans} autoFocus />
                </div>
                <button className="ns-browse-btn" onClick={() => fileInputRef.current.click()} disabled={loading || !canExecuteScans}>📂 Upload File</button>
              </div>
            </div>
            {uploadSummary.show && <div className="ns-upload-summary"><div className="ns-summary-content"><div className="ns-summary-main"><span>Total: <strong>{uploadSummary.total}</strong></span><span className="ns-stat--valid">Valid: <strong>{uploadSummary.valid}</strong></span></div></div><button className="ns-summary-close" onClick={() => { setUploadSummary(p => ({ ...p, show: false })); setParsedTargets([]); }}>×</button></div>}
            <div className="ns-chips"><span className="ns-chips-label">Quick:</span>{QUICK_TARGETS.map(t => <button key={t} className="ns-chip" onClick={() => setTarget(t)} disabled={loading || !canExecuteScans}>{t}</button>)}</div>
          </div>
          {pipelineMode === "asset" && (<><div className="ns-divider" /><div className="ns-section"><div className="ns-label">Discovery Intensity</div><div className="ns-intensity-grid">{DISCOVERY_INTENSITIES.map(di => <button key={di.value} className={`ns-int-card ${discoveryIntensity === di.value ? "ns-int-card--active" : ""}`} onClick={() => setDiscoveryIntensity(di.value)} disabled={loading || !canExecuteScans}><span className="ns-int-icon">{di.icon}</span><span className="ns-int-name">{di.label}</span></button>)}</div></div></>)}
          {pipelineMode === "advanced" && (<><div className="ns-divider" /><div className="ns-section"><div className="ns-label">Scan Intensity</div><div className="ns-intensity-grid">{SCAN_INTENSITIES.map(si => <button key={si.value} className={`ns-int-card ${intensity === si.value ? "ns-int-card--active" : ""}`} onClick={() => setIntensity(si.value)} disabled={loading || !canExecuteScans}><span className="ns-int-icon">{si.icon}</span><span className="ns-int-name">{si.label}</span></button>)}</div></div></>)}
          <div className="ns-divider" /><div className="ns-section"><div className="ns-label">Rate Limit (PPS)</div><div className="ns-input-wrap"><span className="ns-input-icon">⏱</span><input type="number" className="ns-input" value={rateLimit} onChange={e => setRateLimit(e.target.value)} placeholder="e.g. 500" disabled={loading || !canExecuteScans} /></div></div>
          {error && <div className="ns-error">⚠ {error}</div>}
          <div className="ns-divider" /><button id="ns-start-btn" className="ns-start-btn" onClick={handleScan} disabled={loading || !target.trim() || !canExecuteScans || quotaBlocked}>{btnLabel} →</button>
        </div>
      </div>
    </AppLayout>
  );
}
