/**
 * src/pages/Dashboard.jsx
 * Wires phases 1→2→3, carries scanId across them, shows save status.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import PhaseOne   from "../components/scan/PhaseOne";
import PhaseTwo   from "../components/scan/PhaseTwo";
import PhaseThree from "../components/scan/PhaseThree";

const PHASES = [
  { n: 1, label: "Discovery",     sub: "Find live hosts" },
  { n: 2, label: "Port Scan",     sub: "Map open services" },
  { n: 3, label: "Vulnerability", sub: "CVE & risk audit" },
];

export default function Dashboard() {
  const { user, logout } = useAuth();

  const [phase, setPhase]             = useState(1);
  const [scanId, setScanId]           = useState(null);   // DB id returned by phase 1
  const [phase1Hosts, setPhase1Hosts] = useState([]);
  const [phase2Hosts, setPhase2Hosts] = useState([]);
  const [saveStatus, setSaveStatus]   = useState("");     // "saving" | "saved" | "error" | ""

  // Phase 1 complete → get scanId from response, move to phase 2
  const goPhase2 = (selectedHosts, returnedScanId) => {
    setScanId(returnedScanId);
    setPhase1Hosts(selectedHosts);
    setSaveStatus("saved");
    setTimeout(() => setSaveStatus(""), 3000);
    setPhase(2);
  };

  const goPhase3 = (selectedHosts) => {
    setPhase2Hosts(selectedHosts);
    setSaveStatus("saved");
    setTimeout(() => setSaveStatus(""), 3000);
    setPhase(3);
  };

  const onScanComplete = () => {
    setSaveStatus("saved");
    setTimeout(() => setSaveStatus(""), 4000);
  };

  const restart = () => {
    setPhase(1); setScanId(null);
    setPhase1Hosts([]); setPhase2Hosts([]);
    setSaveStatus("");
  };

  return (
    <div className="dashboard">

      {/* ── Header ── */}
      <header className="dash-header">
        <div className="dash-brand">
          <span className="brand-icon">◈</span>
          <span className="brand-name">CCURE AUDIT</span>
          <span className="brand-badge">PRO</span>
        </div>
        <div className="dash-user">
          {/* Save status indicator */}
          {saveStatus === "saving" && (
            <span className="save-status save-status--saving">
              <span className="btn-spinner" style={{ width:12, height:12, borderWidth:2 }} />
              Saving to database…
            </span>
          )}
          {saveStatus === "saved" && (
            <span className="save-status save-status--saved">✓ Saved to history</span>
          )}
          {saveStatus === "error" && (
            <span className="save-status save-status--error">⚠ Save failed</span>
          )}

          <Link to="/history" className="nav-link">📋 Scan History</Link>
          <span className="user-chip">
            <span className="user-dot" />
            {user?.username}
          </span>
          <button className="logout-btn" onClick={logout}>Sign out</button>
        </div>
      </header>

      {/* ── Phase stepper ── */}
      <div className="stepper">
        {PHASES.map((p, i) => (
          <div key={p.n}
            className={`step ${phase === p.n ? "step--active" : ""} ${phase > p.n ? "step--done" : ""}`}>
            <div className="step-circle">{phase > p.n ? "✓" : p.n}</div>
            <div className="step-info">
              <span className="step-label">{p.label}</span>
              <span className="step-sub">{p.sub}</span>
            </div>
            {i < PHASES.length - 1 && <div className="step-line" />}
          </div>
        ))}
        {scanId && (
          <div className="scan-id-pill">Scan #{scanId}</div>
        )}
      </div>

      {/* ── Active phase ── */}
      <main className="dash-main">
        {phase === 1 && (
          <PhaseOne
            onComplete={goPhase2}
            onSaving={() => setSaveStatus("saving")}
          />
        )}
        {phase === 2 && (
          <PhaseTwo
            hosts={phase1Hosts}
            scanId={scanId}
            onBack={() => setPhase(1)}
            onComplete={goPhase3}
            onSaving={() => setSaveStatus("saving")}
          />
        )}
        {phase === 3 && (
          <PhaseThree
            hosts={phase2Hosts}
            scanId={scanId}
            onBack={() => setPhase(2)}
            onRestart={restart}
            onComplete={onScanComplete}
            onSaving={() => setSaveStatus("saving")}
          />
        )}
      </main>
    </div>
  );
}
