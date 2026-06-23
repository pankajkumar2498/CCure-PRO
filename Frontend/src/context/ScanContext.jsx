/**
 * src/context/ScanContext.jsx
 *
 * State management for the CCure Audit PRO scan pipeline.
 *
 * PIPELINE STATES:
 *   IDLE → DISCOVERY → PORT_SCAN → VULN_SCAN → REPORT_READY → COMPLETE
 *   Any phase can transition to ERROR or CANCELLED.
 *   PAUSED state allows pause/resume behavior.
 *
 * Session storage is used for persistence across page refreshes.
 */
import { createContext, useContext, useState, useRef, useCallback } from "react";

const ScanContext = createContext(null);

const SS_KEYS = [
  "cc_scanId", "cc_scanNo", "cc_target", "cc_scanType",
  "cc_pipelineMode",
  "cc_phase1Hosts", "cc_phase1Summary",
  "cc_phase2Hosts", "cc_phase2Summary",
  "cc_phase2Results",
  "cc_phase3Results", "cc_phase3Summary",
  "cc_phase3AuditResults",
  "cc_saveStatus",
  "cc_pipelineState",
  "cc_pipelineError",
  "cc_pipelinePhaseTimings",
  "cc_intensity",
  "cc_osDetection",
  "cc_discoveryIntensity",
  "cc_portScanIntensity",
  "cc_autoRunAdvancedSingleTarget",
  "cc_portScanMode",
  "cc_customPorts",
  "cc_portProfile",
  "cc_excludePorts",
];

/* ── Session storage helpers ─────────────────────────────────────────────── */

function ssGet(key, fallback) {
  try {
    const raw = sessionStorage.getItem(key);
    return raw !== null ? JSON.parse(raw) : fallback;
  } catch { return fallback; }
}
function ssSet(key, value) {
  try { sessionStorage.setItem(key, JSON.stringify(value)); } catch {}
}
function ssClear() {
  SS_KEYS.forEach((k) => sessionStorage.removeItem(k));
}

/* ── Pipeline state enum ─────────────────────────────────────────────────── */

export const PIPELINE_STATES = {
  IDLE:          "IDLE",
  DISCOVERY:     "DISCOVERY",
  PORT_SCAN:     "PORT_SCAN",
  VULN_SCAN:     "VULN_SCAN",
  TOPOLOGY_MAP:  "TOPOLOGY_MAP",
  REPORT_READY:  "REPORT_READY",
  COMPLETE:      "COMPLETE",
  ERROR:         "ERROR",
  CANCELLED:     "CANCELLED",
  PAUSED:        "PAUSED",
};

/* ── Provider ─────────────────────────────────────────────────────────────── */

export function ScanProvider({ children }) {
  const [scanId,              setScanIdRaw]              = useState(() => ssGet("cc_scanId",             null));
  const [scanNo,              setScanNoRaw]              = useState(() => ssGet("cc_scanNo",             null));
  const [target,              setTargetRaw]              = useState(() => ssGet("cc_target",             ""));
  const [scanType,            setScanTypeRaw]            = useState(() => ssGet("cc_scanType",           "adaptive"));
  const [pipelineMode,        setPipelineModeRaw]        = useState(() => ssGet("cc_pipelineMode",       "basic"));
  const [phase1Hosts,         setPhase1HostsRaw]         = useState(() => ssGet("cc_phase1Hosts",        []));
  const [phase1Summary,       setPhase1SummaryRaw]       = useState(() => ssGet("cc_phase1Summary",      null));
  const [phase2Hosts,         setPhase2HostsRaw]         = useState(() => ssGet("cc_phase2Hosts",        []));
  const [phase2Summary,       setPhase2SummaryRaw]       = useState(() => ssGet("cc_phase2Summary",      null));
  const [phase2Results,       setPhase2ResultsRaw]       = useState(() => ssGet("cc_phase2Results",      []));
  const [phase3Results,       setPhase3ResultsRaw]       = useState(() => ssGet("cc_phase3Results",      []));
  const [phase3Summary,       setPhase3SummaryRaw]       = useState(() => ssGet("cc_phase3Summary",      null));
  const [phase3AuditResults,  setPhase3AuditResultsRaw]  = useState(() => ssGet("cc_phase3AuditResults", []));
  const [saveStatus,          setSaveStatusRaw]          = useState(() => ssGet("cc_saveStatus",         ""));
  const [intensity,           setIntensityRaw]           = useState(() => ssGet("cc_intensity",          "normal"));
  const [osDetection,         setOsDetectionRaw]         = useState(() => ssGet("cc_osDetection",        true));
  // Asset Discovery Phase 1 intensity (light | normal | deep) — separate from port-scan intensity
  const [discoveryIntensity,  setDiscoveryIntensityRaw]  = useState(() => ssGet("cc_discoveryIntensity",  "normal"));
  // Asset Discovery Phase 2 port scan intensity (light | normal | deep) — configured upfront on setup screen
  const [portScanIntensity,   setPortScanIntensityRaw]   = useState(() => ssGet("cc_portScanIntensity",   "normal"));
  const [autoRunAdvancedSingleTarget, setAutoRunAdvancedSingleTargetRaw] = useState(() => ssGet("cc_autoRunAdvancedSingleTarget", false));
  const [executionMode,       setExecutionModeRaw]       = useState(() => ssGet("cc_executionMode",       "automatic"));
  const [portScanMode,        setPortScanModeRaw]        = useState(() => ssGet("cc_portScanMode",        "intensity"));
  const [customPorts,         setCustomPortsRaw]         = useState(() => ssGet("cc_customPorts",         ""));
  const [portProfile,         setPortProfileRaw]         = useState(() => ssGet("cc_portProfile",         "it"));
  const [excludePorts,        setExcludePortsRaw]        = useState(() => ssGet("cc_excludePorts",        ""));

  // Pipeline state machine
  const [pipelineState,       setPipelineStateRaw]       = useState(() => ssGet("cc_pipelineState",      PIPELINE_STATES.IDLE));
  const [pipelineError,       setPipelineErrorRaw]       = useState(() => ssGet("cc_pipelineError",      null));
  const [pipelinePhaseTimings, setPipelinePhaseTimingsRaw] = useState(() => ssGet("cc_pipelinePhaseTimings", {}));

  // Abort controller for cancellation
  const abortRef = useRef(null);

  const mk = (key, setter) => (v) => { ssSet(key, v); setter(v); };

  const setScanId             = mk("cc_scanId",             setScanIdRaw);
  const setScanNo             = mk("cc_scanNo",             setScanNoRaw);
  const setTarget             = mk("cc_target",             setTargetRaw);
  const setScanType           = mk("cc_scanType",           setScanTypeRaw);
  const setPipelineMode       = mk("cc_pipelineMode",       setPipelineModeRaw);
  const setPhase1Hosts        = mk("cc_phase1Hosts",        setPhase1HostsRaw);
  const setPhase1Summary      = mk("cc_phase1Summary",      setPhase1SummaryRaw);
  const setPhase2Hosts        = mk("cc_phase2Hosts",        setPhase2HostsRaw);
  const setPhase2Summary      = mk("cc_phase2Summary",      setPhase2SummaryRaw);
  const setPhase2Results      = mk("cc_phase2Results",      setPhase2ResultsRaw);
  const setPhase3Results      = mk("cc_phase3Results",      setPhase3ResultsRaw);
  const setPhase3Summary      = mk("cc_phase3Summary",      setPhase3SummaryRaw);
  const setPhase3AuditResults = mk("cc_phase3AuditResults", setPhase3AuditResultsRaw);
  const setSaveStatus         = mk("cc_saveStatus",         setSaveStatusRaw);
  const setIntensity          = mk("cc_intensity",          setIntensityRaw);
  const setOsDetection        = mk("cc_osDetection",        setOsDetectionRaw);
  const setDiscoveryIntensity = mk("cc_discoveryIntensity", setDiscoveryIntensityRaw);
  const setPortScanIntensity  = mk("cc_portScanIntensity",  setPortScanIntensityRaw);
  const setAutoRunAdvancedSingleTarget = mk("cc_autoRunAdvancedSingleTarget", setAutoRunAdvancedSingleTargetRaw);
  const setExecutionMode      = mk("cc_executionMode",      setExecutionModeRaw);
  const setPortScanMode       = mk("cc_portScanMode",       setPortScanModeRaw);
  const setCustomPorts        = mk("cc_customPorts",        setCustomPortsRaw);
  const setPortProfile        = mk("cc_portProfile",        setPortProfileRaw);
  const setExcludePorts       = mk("cc_excludePorts",       setExcludePortsRaw);
  const setPipelineState      = mk("cc_pipelineState",      setPipelineStateRaw);
  const setPipelineError      = mk("cc_pipelineError",      setPipelineErrorRaw);
  const setPipelinePhaseTimings = mk("cc_pipelinePhaseTimings", setPipelinePhaseTimingsRaw);

  const cancelPipeline = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
    setPipelineState(PIPELINE_STATES.CANCELLED);
  }, []);

  const pausePipeline = useCallback(() => {
    setPipelineState(PIPELINE_STATES.PAUSED);
  }, []);

  const resetScan = () => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
    ssClear();
    setScanIdRaw(null);         setScanNoRaw(null);       setTargetRaw("");         setScanTypeRaw("adaptive");
    setPipelineModeRaw("basic");
    setPhase1HostsRaw([]);      setPhase1SummaryRaw(null);
    setPhase2HostsRaw([]);      setPhase2SummaryRaw(null);
    setPhase2ResultsRaw([]);    setPhase3ResultsRaw([]);    setPhase3SummaryRaw(null);
    setPhase3AuditResultsRaw([]);
    setSaveStatusRaw("");
    setIntensityRaw("normal");
    setOsDetectionRaw(true);
    setDiscoveryIntensityRaw("normal");
    setPortScanIntensityRaw("normal");
    setAutoRunAdvancedSingleTargetRaw(false);
    setExecutionModeRaw("automatic");
    setPortScanModeRaw("intensity");
    setCustomPortsRaw("");
    setPortProfileRaw("it");
    setExcludePortsRaw("");
    setPipelineStateRaw(PIPELINE_STATES.IDLE);
    setPipelineErrorRaw(null);
    setPipelinePhaseTimingsRaw({});
  };

  return (
    <ScanContext.Provider value={{
      scanId, setScanId,
      scanNo, setScanNo,
      target, setTarget,
      scanType, setScanType,
      pipelineMode, setPipelineMode,
      phase1Hosts, setPhase1Hosts,
      phase1Summary, setPhase1Summary,
      phase2Hosts, setPhase2Hosts,
      phase2Summary, setPhase2Summary,
      phase2Results, setPhase2Results,
      phase3Results, setPhase3Results,
      phase3Summary, setPhase3Summary,
      phase3AuditResults, setPhase3AuditResults,
      saveStatus, setSaveStatus,
      intensity, setIntensity,
      osDetection, setOsDetection,
      discoveryIntensity, setDiscoveryIntensity,
      portScanIntensity, setPortScanIntensity,
      autoRunAdvancedSingleTarget, setAutoRunAdvancedSingleTarget,
      executionMode, setExecutionMode,
      portScanMode, setPortScanMode,
      customPorts, setCustomPorts,
      portProfile, setPortProfile,
      excludePorts, setExcludePorts,
      pipelineState, setPipelineState,
      pipelineError, setPipelineError,
      pipelinePhaseTimings, setPipelinePhaseTimings,
      abortRef,
      cancelPipeline,
      pausePipeline,
      resetScan,
    }}>
      {children}
    </ScanContext.Provider>
  );
}

export const useScan = () => {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used inside <ScanProvider>");
  return ctx;
};
