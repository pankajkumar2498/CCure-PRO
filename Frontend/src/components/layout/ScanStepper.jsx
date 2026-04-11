/**
 * src/components/layout/ScanStepper.jsx
 * Progress bar shown across all 3 scan-result pages.
 * Uses the unified .stepper CSS classes from global.css.
 */
import { useScan } from "../../context/ScanContext";

const STEPS = [
  { n: 1, label: "Discovery",     sub: "Find live hosts"   },
  { n: 2, label: "Port Scan",     sub: "Map open services" },
  { n: 3, label: "Vulnerability", sub: "CVE & risk audit"  },
];

export default function ScanStepper({ current }) {
  const { scanId } = useScan();

  return (
    <div className="stepper">
      {STEPS.map((s, i) => {
        const done   = current > s.n;
        const active = current === s.n;
        return (
          <div key={s.n} style={{ display: "flex", alignItems: "center" }}>
            <div className={`stepper-step ${active ? "stepper-step--active" : ""} ${done ? "stepper-step--done" : ""}`}>
              <div className="stepper-num">{done ? "✓" : s.n}</div>
              <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
                <span style={{ fontSize: "0.82rem", fontWeight: active ? 700 : 500 }}>{s.label}</span>
                <span style={{ fontSize: "0.7rem", color: "var(--text-faint)" }}>{s.sub}</span>
              </div>
            </div>
            {i < STEPS.length - 1 && <span className="stepper-arrow">›</span>}
          </div>
        );
      })}
      {scanId && (
        <span style={{
          marginLeft: "auto",
          fontFamily: "var(--mono)", fontSize: "0.75rem",
          color: "var(--text-faint)",
          background: "var(--bg-app)", border: "1px solid var(--border)",
          padding: "2px 10px", borderRadius: 4,
          flexShrink: 0,
        }}>
          Scan #{scanId}
        </span>
      )}
    </div>
  );
}
