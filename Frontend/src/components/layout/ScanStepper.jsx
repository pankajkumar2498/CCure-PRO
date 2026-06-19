/**
 * src/components/layout/ScanStepper.jsx
 *
 * Enhanced stepper with live pipeline status indicators.
 * Shows: ✓ completed | ● active (pulsing) | ○ pending
 * Driven by `pipelineState` from context for real-time updates.
 */
import { useScan, PIPELINE_STATES } from "../../context/ScanContext";
import { getScanPipeline } from "../../config/scanConfig";

const ALL_STEPS = [
  { n: 1, label: "Discovery",     sub: "Find live hosts",      stateKey: "DISCOVERY"    },
  { n: 2, label: "Port Scan",     sub: "Map open services",    stateKey: "PORT_SCAN"    },
  { n: 3, label: "Vulnerability", sub: "CVE & risk audit",     stateKey: "VULN_SCAN"    },
  { n: 4, label: "Topology",      sub: "Network map (SNMP)",   stateKey: "TOPOLOGY_MAP" },
];

/** Maps pipeline state → active step number */
const STATE_TO_STEP = {
  [PIPELINE_STATES.DISCOVERY]:    1,
  [PIPELINE_STATES.PORT_SCAN]:    2,
  [PIPELINE_STATES.VULN_SCAN]:    3,
  [PIPELINE_STATES.TOPOLOGY_MAP]: 4,
  [PIPELINE_STATES.REPORT_READY]: 5,  // All steps done
  [PIPELINE_STATES.COMPLETE]:     5,
};

export default function ScanStepper({ current }) {
  const { scanId, scanNo, pipelineMode, pipelineState, pipelineError } = useScan();

  const pipeline = getScanPipeline(pipelineMode || "basic");
  
  // Phase 4 (topology) is only shown if it's currently active or completed
  const showTopology = pipelineState === PIPELINE_STATES.TOPOLOGY_MAP
    || (STATE_TO_STEP[pipelineState] || 0) > 4;
  
  const steps = ALL_STEPS.filter(s => {
    if (s.n === 4) return showTopology;  // Only show topology step when relevant
    return pipeline.phases.includes(s.n);
  });

  // Use pipeline state to derive step status, fall back to `current` prop
  const activeStep = STATE_TO_STEP[pipelineState] ?? current ?? 0;
  const isRunning  = [
    PIPELINE_STATES.DISCOVERY,
    PIPELINE_STATES.PORT_SCAN,
    PIPELINE_STATES.VULN_SCAN,
    PIPELINE_STATES.TOPOLOGY_MAP,
  ].includes(pipelineState);

  return (
    <div className="stepper">
      {steps.map((s, i) => {
        const done    = activeStep > s.n;
        const active  = activeStep === s.n;
        const isError = pipelineState === PIPELINE_STATES.ERROR && active;

        let stepClass = "stepper-step";
        if (done)    stepClass += " stepper-step--done";
        if (active)  stepClass += " stepper-step--active";
        if (isError) stepClass += " stepper-step--error";
        if (active && isRunning) stepClass += " stepper-step--running";

        return (
          <div key={s.n} style={{ display: "flex", alignItems: "center" }}>
            <div className={stepClass}>
              <div className="stepper-num">
                {done ? "✓" : isError ? "!" : s.n}
              </div>
              <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.2 }}>
                <span style={{ fontSize: "0.82rem", fontWeight: active ? 700 : 500 }}>{s.label}</span>
                <span style={{ fontSize: "0.7rem", color: "var(--text-faint)" }}>
                  {active && isRunning ? "Scanning…" : isError ? "Failed" : done ? "Complete" : s.sub}
                </span>
              </div>
            </div>
            {i < steps.length - 1 && (
              <span className={`stepper-arrow ${done ? "stepper-arrow--done" : ""}`}>›</span>
            )}
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
          Scan No. {scanNo ?? "-"}
        </span>
      )}
    </div>
  );
}
