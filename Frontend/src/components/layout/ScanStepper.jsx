/**
 * src/components/layout/ScanStepper.jsx
 * Progress indicator shown on all 4 scan pages.
 */
import { useNavigate } from "react-router-dom";
import { useScan } from "../../context/ScanContext";

const STEPS = [
  { n: 1, label: "Discovery",     sub: "Find live hosts",    path: "/scan/phase1" },
  { n: 2, label: "Port Scan",     sub: "Map open services",  path: "/scan/phase2" },
  { n: 3, label: "Vulnerability", sub: "CVE & risk audit",   path: "/scan/phase3" },
];

export default function ScanStepper({ current }) {
  const { scanId } = useScan();

  return (
    <div className="stepper">
      {STEPS.map((s, i) => (
        <div key={s.n}
          className={`step ${current === s.n ? "step--active" : ""} ${current > s.n ? "step--done" : ""}`}>
          <div className="step-circle">{current > s.n ? "✓" : s.n}</div>
          <div className="step-info">
            <span className="step-label">{s.label}</span>
            <span className="step-sub">{s.sub}</span>
          </div>
          {i < STEPS.length - 1 && <div className="step-line" />}
        </div>
      ))}
      {scanId && <div className="scan-id-pill">Scan #{scanId}</div>}
    </div>
  );
}
