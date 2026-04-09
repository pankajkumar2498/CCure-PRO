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
 * Usage:
 *   const { scanId, phase1Hosts, setScan, resetScan } = useScan();
 */

import { createContext, useContext, useState } from "react";

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const [scanId,       setScanId]       = useState(null);
  const [target,       setTarget]       = useState("");
  const [scanType,     setScanType]     = useState("adaptive");
  const [phase1Hosts,  setPhase1Hosts]  = useState([]);   // all discovered
  const [phase1Summary, setPhase1Summary] = useState(null);
  const [phase2Hosts,  setPhase2Hosts]  = useState([]);   // selected for port scan
  const [phase2Summary, setPhase2Summary] = useState(null);
  const [phase3Results, setPhase3Results] = useState([]);
  const [phase3Summary, setPhase3Summary] = useState(null);
  const [saveStatus,   setSaveStatus]   = useState(""); // "saving"|"saved"|"error"|""

  const resetScan = () => {
    setScanId(null);
    setTarget("");
    setScanType("adaptive");
    setPhase1Hosts([]); setPhase1Summary(null);
    setPhase2Hosts([]); setPhase2Summary(null);
    setPhase3Results([]); setPhase3Summary(null);
    setSaveStatus("");
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
