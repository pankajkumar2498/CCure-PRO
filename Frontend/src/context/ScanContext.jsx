/**
 * src/context/ScanContext.jsx
 * Carries scan state across the 5-page wizard.
 * All state is persisted to sessionStorage so browser-refresh restores progress.
 *
 * Wizard flow:
 *   /scan       → target input (NewScan)
 *   /scan/phase1 → discovered hosts (Phase1Results)
 *   /scan/phase2 → port-scan results (Phase2Results)
 *   /scan/phase3 → vulnerability audit (Phase3Results)
 *   /history    → past scans (re-run loops back to /scan)
 */
import { createContext, useContext, useState } from "react";

const ScanContext = createContext(null);

const SS_KEYS = [
  "cc_scanId", "cc_target", "cc_scanType",
  "cc_phase1Hosts", "cc_phase1Summary",
  "cc_phase2Hosts", "cc_phase2Summary",
  "cc_phase3Results", "cc_phase3Summary",
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
  const [scanId,        setScanIdRaw]        = useState(() => ssGet("cc_scanId",        null));
  const [target,        setTargetRaw]        = useState(() => ssGet("cc_target",        ""));
  const [scanType,      setScanTypeRaw]      = useState(() => ssGet("cc_scanType",      "adaptive"));
  const [phase1Hosts,   setPhase1HostsRaw]   = useState(() => ssGet("cc_phase1Hosts",   []));
  const [phase1Summary, setPhase1SummaryRaw] = useState(() => ssGet("cc_phase1Summary", null));
  const [phase2Hosts,   setPhase2HostsRaw]   = useState(() => ssGet("cc_phase2Hosts",   []));
  const [phase2Summary, setPhase2SummaryRaw] = useState(() => ssGet("cc_phase2Summary", null));
  const [phase3Results, setPhase3ResultsRaw] = useState(() => ssGet("cc_phase3Results", []));
  const [phase3Summary, setPhase3SummaryRaw] = useState(() => ssGet("cc_phase3Summary", null));
  const [saveStatus,    setSaveStatusRaw]    = useState(() => ssGet("cc_saveStatus",    ""));

  const mk = (key, setter) => (v) => { ssSet(key, v); setter(v); };

  const setScanId        = mk("cc_scanId",        setScanIdRaw);
  const setTarget        = mk("cc_target",        setTargetRaw);
  const setScanType      = mk("cc_scanType",      setScanTypeRaw);
  const setPhase1Hosts   = mk("cc_phase1Hosts",   setPhase1HostsRaw);
  const setPhase1Summary = mk("cc_phase1Summary", setPhase1SummaryRaw);
  const setPhase2Hosts   = mk("cc_phase2Hosts",   setPhase2HostsRaw);
  const setPhase2Summary = mk("cc_phase2Summary", setPhase2SummaryRaw);
  const setPhase3Results = mk("cc_phase3Results", setPhase3ResultsRaw);
  const setPhase3Summary = mk("cc_phase3Summary", setPhase3SummaryRaw);
  const setSaveStatus    = mk("cc_saveStatus",    setSaveStatusRaw);

  const resetScan = () => {
    ssClear();
    setScanIdRaw(null);    setTargetRaw("");       setScanTypeRaw("adaptive");
    setPhase1HostsRaw([]); setPhase1SummaryRaw(null);
    setPhase2HostsRaw([]); setPhase2SummaryRaw(null);
    setPhase3ResultsRaw([]); setPhase3SummaryRaw(null);
    setSaveStatusRaw("");
  };

  return (
    <ScanContext.Provider value={{
      scanId, setScanId,
      target, setTarget,
      scanType, setScanType,
      phase1Hosts, setPhase1Hosts,
      phase1Summary, setPhase1Summary,
      phase2Hosts, setPhase2Hosts,
      phase2Summary, setPhase2Summary,
      phase3Results, setPhase3Results,
      phase3Summary, setPhase3Summary,
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
