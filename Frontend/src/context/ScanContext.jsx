/**
 * src/context/ScanContext.jsx
 *
 * Carries scan state across the 5-page wizard:
 *   /scan          → target input
 *   /scan/phase1   → discovered hosts
 *   /scan/phase2   → port results
 *   /scan/phase3   → vulnerability report
 *   /history       → past scans (re-run flows back into /scan)
 *
 * State is persisted in sessionStorage so a browser refresh at any
 * /scan/* route restores all progress instead of losing it.
 *
 * Usage:
 *   const { scanId, phase1Hosts, setScanId, resetScan } = useScan();
 */

import { createContext, useContext, useState } from "react";

const ScanContext = createContext(null);

// ── sessionStorage helpers ────────────────────────────────────────────────────

const SS_KEYS = [
  "cc_scanId",
  "cc_target",
  "cc_scanType",
  "cc_phase1Hosts",
  "cc_phase1Summary",
  "cc_phase2Hosts",
  "cc_phase2Summary",
  "cc_phase3Results",
  "cc_phase3Summary",
  "cc_saveStatus",
];

function ssGet(key, fallback) {
  try {
    const raw = sessionStorage.getItem(key);
    return raw !== null ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function ssSet(key, value) {
  try {
    sessionStorage.setItem(key, JSON.stringify(value));
  } catch { /* quota exceeded — fail silently */ }
}

function ssClear() {
  SS_KEYS.forEach((k) => sessionStorage.removeItem(k));
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function ScanProvider({ children }) {

  // Initialise every piece of state from sessionStorage on first render
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

  // Wrapped setters — write to sessionStorage then update React state
  const setScanId        = (v) => { ssSet("cc_scanId",        v); setScanIdRaw(v);        };
  const setTarget        = (v) => { ssSet("cc_target",        v); setTargetRaw(v);        };
  const setScanType      = (v) => { ssSet("cc_scanType",      v); setScanTypeRaw(v);      };
  const setPhase1Hosts   = (v) => { ssSet("cc_phase1Hosts",   v); setPhase1HostsRaw(v);   };
  const setPhase1Summary = (v) => { ssSet("cc_phase1Summary", v); setPhase1SummaryRaw(v); };
  const setPhase2Hosts   = (v) => { ssSet("cc_phase2Hosts",   v); setPhase2HostsRaw(v);   };
  const setPhase2Summary = (v) => { ssSet("cc_phase2Summary", v); setPhase2SummaryRaw(v); };
  const setPhase3Results = (v) => { ssSet("cc_phase3Results", v); setPhase3ResultsRaw(v); };
  const setPhase3Summary = (v) => { ssSet("cc_phase3Summary", v); setPhase3SummaryRaw(v); };
  const setSaveStatus    = (v) => { ssSet("cc_saveStatus",    v); setSaveStatusRaw(v);    };

  // Reset — clears sessionStorage keys then resets React state
  const resetScan = () => {
    ssClear();
    setScanIdRaw(null);
    setTargetRaw("");
    setScanTypeRaw("adaptive");
    setPhase1HostsRaw([]);   setPhase1SummaryRaw(null);
    setPhase2HostsRaw([]);   setPhase2SummaryRaw(null);
    setPhase3ResultsRaw([]); setPhase3SummaryRaw(null);
    setSaveStatusRaw("");
  };

  return (
    <ScanContext.Provider value={{
      scanId,        setScanId,
      target,        setTarget,
      scanType,      setScanType,
      phase1Hosts,   setPhase1Hosts,
      phase1Summary, setPhase1Summary,
      phase2Hosts,   setPhase2Hosts,
      phase2Summary, setPhase2Summary,
      phase3Results, setPhase3Results,
      phase3Summary, setPhase3Summary,
      saveStatus,    setSaveStatus,
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
