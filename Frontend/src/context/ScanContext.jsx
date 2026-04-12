/**
 * src/context/ScanContext.jsx  [FIXED]
 *
 * CHANGE: Added `phase3AuditResults` state.
 * This holds the OUTPUT of Phase 3 (audit results returned by the API),
 * separate from `phase3Results` which is the INPUT (selected hosts from Phase 2).
 * Phase 4 reads from `phase3AuditResults` to build the Risk Report.
 */
import { createContext, useContext, useState } from "react";

const ScanContext = createContext(null);

const SS_KEYS = [
  "cc_scanId", "cc_target", "cc_scanType",
  "cc_pipelineMode",
  "cc_phase1Hosts", "cc_phase1Summary",
  "cc_phase2Hosts", "cc_phase2Summary",
  "cc_phase3Results", "cc_phase3Summary",
  "cc_phase3AuditResults",   // ← NEW: Phase3 API output for Phase4
  "cc_saveStatus",
];

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

export function ScanProvider({ children }) {
  const [scanId,              setScanIdRaw]              = useState(() => ssGet("cc_scanId",             null));
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
  const [phase3AuditResults,  setPhase3AuditResultsRaw]  = useState(() => ssGet("cc_phase3AuditResults", [])); // ← NEW
  const [saveStatus,          setSaveStatusRaw]          = useState(() => ssGet("cc_saveStatus",         ""));

  const mk = (key, setter) => (v) => { ssSet(key, v); setter(v); };

  const setScanId             = mk("cc_scanId",             setScanIdRaw);
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
  const setPhase3AuditResults = mk("cc_phase3AuditResults", setPhase3AuditResultsRaw); // ← NEW
  const setSaveStatus         = mk("cc_saveStatus",         setSaveStatusRaw);

  const resetScan = () => {
    ssClear();
    setScanIdRaw(null);         setTargetRaw("");         setScanTypeRaw("adaptive");
    setPipelineModeRaw("basic");
    setPhase1HostsRaw([]);      setPhase1SummaryRaw(null);
    setPhase2HostsRaw([]);      setPhase2SummaryRaw(null);
    setPhase2ResultsRaw([]);    setPhase3ResultsRaw([]);    setPhase3SummaryRaw(null);
    setPhase3AuditResultsRaw([]);                          // ← NEW
    setSaveStatusRaw("");
  };

  return (
    <ScanContext.Provider value={{
      scanId, setScanId,
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
      phase3AuditResults, setPhase3AuditResults,  // ← NEW
      saveStatus, setSaveStatus,
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
