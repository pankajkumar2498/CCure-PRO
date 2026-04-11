/**
 * src/components/layout/ScanStepper.jsx  [FIXED]
 *
 * CHANGE: Now reads `pipelineMode` from context to conditionally show
 * Phase 4 (Risk Report) step. The stepper is pipeline-aware:
 *   basic:    steps 1 only (shows 1 step, grayed 2–3)
 *   asset:    steps 1–2
 *   advanced: steps 1–4
 *
 * `current` prop still drives which step is highlighted.
 */
import { useScan } from "../../context/ScanContext";
import { getScanPipeline } from "../../config/scanConfig";

const ALL_STEPS = [
  { n: 1, label: "Discovery",     sub: "Find live hosts"   },
  { n: 2, label: "Port Scan",     sub: "Map open services" },
  { n: 3, label: "Vulnerability", sub: "CVE & risk audit"  },
  { n: 4, label: "Risk Report",   sub: "Full assessment"   },
];

export default function ScanStepper({ current }) {
  const { scanId, pipelineMode } = useScan();

  // Only show steps that belong to the current pipeline
  const pipeline = getScanPipeline(pipelineMode || "basic");
  const steps    = ALL_STEPS.filter(s => pipeline.phases.includes(s.n));

  return (
    <div className="stepper">
      {steps.map((s, i) => {
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
            {i < steps.length - 1 && <span className="stepper-arrow">›</span>}
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
