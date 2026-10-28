/**
 * src/modules/audit/components/scan/ScanStepper.jsx
 *
 * The scan pipeline's steps and where the scan has got to. Driven by
 * `pipelineState` from ScanContext, with the page's `current` as fallback.
 * Consumed by Phase1Results, Phase2Results and Phase3Results.
 *
 * Checkpoint 3C batch 15: an ordered list with `aria-current="step"`, the
 * shape batch 8 gave the web-scan pipeline. A step's state is in words —
 * Complete, Scanning…, Failed, or its description — and the tick, the "!",
 * the step number and the separators are hidden from assistive technology
 * because they only repeat those words. Layout and colour: scan-stepper.css.
 */
import { CcureBadge } from "../../../../design-system";
import { useScan, PIPELINE_STATES } from "@audit/context/ScanContext";
import { getScanPipeline } from "@audit/config/scanConfig";
import "../../styles/scan-stepper.css";

const ALL_STEPS = [
  { n: 1, label: "Discovery", sub: "Find live hosts", stateKey: "DISCOVERY" },
  { n: 2, label: "Port Scan", sub: "Map open services", stateKey: "PORT_SCAN" },
  {
    n: 3,
    label: "Vulnerability",
    sub: "CVE & risk audit",
    stateKey: "VULN_SCAN",
  },
  {
    n: 4,
    label: "Topology",
    sub: "Network map (SNMP)",
    stateKey: "TOPOLOGY_MAP",
  },
];

/** Maps pipeline state → active step number */
const STATE_TO_STEP = {
  [PIPELINE_STATES.DISCOVERY]: 1,
  [PIPELINE_STATES.PORT_SCAN]: 2,
  [PIPELINE_STATES.VULN_SCAN]: 3,
  [PIPELINE_STATES.TOPOLOGY_MAP]: 4,
  [PIPELINE_STATES.REPORT_READY]: 5, // All steps done
  [PIPELINE_STATES.COMPLETE]: 5,
};

const RUNNING_STATES = new Set([
  PIPELINE_STATES.DISCOVERY,
  PIPELINE_STATES.PORT_SCAN,
  PIPELINE_STATES.VULN_SCAN,
  PIPELINE_STATES.TOPOLOGY_MAP,
]);

export default function ScanStepper({ current }) {
  const { scanId, scanNo, pipelineMode, pipelineState } = useScan();

  const pipeline = getScanPipeline(pipelineMode || "basic");

  // Phase 4 (topology) is an optional bolt-on, not part of the basic or asset
  // pipelines. COMPLETE maps to step 5, so testing "> 4" showed a green
  // "Topology ✓ Complete" on every finished scan — including two-phase Asset
  // Discovery runs that never mapped anything. Show it only when the pipeline
  // actually declares it, or while it is genuinely running.
  const showTopology =
    pipeline.phases.includes(4) ||
    pipelineState === PIPELINE_STATES.TOPOLOGY_MAP;

  const steps = ALL_STEPS.filter((s) => {
    if (s.n === 4) return showTopology; // Only show topology step when relevant
    return pipeline.phases.includes(s.n);
  });

  // Use pipeline state to derive step status, fall back to `current` prop
  const activeStep = STATE_TO_STEP[pipelineState] ?? current ?? 0;
  const isRunning = RUNNING_STATES.has(pipelineState);

  return (
    <div className="sst" role="region" aria-label="Scan progress" tabIndex={0}>
      <ol className="sst__steps" aria-label="Scan pipeline">
        {steps.map((s, i) => {
          const done = activeStep > s.n;
          const active = activeStep === s.n;
          const isError = pipelineState === PIPELINE_STATES.ERROR && active;
          const running = active && isRunning;

          const state = isError
            ? "error"
            : running
              ? "running"
              : done
                ? "done"
                : active
                  ? "active"
                  : "pending";

          const caption = running
            ? "Scanning…"
            : isError
              ? "Failed"
              : done
                ? "Complete"
                : s.sub;

          const previousDone = i > 0 && activeStep > steps[i - 1].n;

          return (
            <li
              key={s.n}
              className={`sst__step sst__step--${state}`}
              aria-current={active ? "step" : undefined}
            >
              {i > 0 && (
                <span
                  className={`sst__sep${previousDone ? " sst__sep--done" : ""}`}
                  aria-hidden="true"
                >
                  ›
                </span>
              )}
              <span className="sst__body">
                <span className="sst__marker" aria-hidden="true">
                  {done ? "✓" : isError ? "!" : s.n}
                </span>
                <span className="sst__text">
                  <span className="sst__label">{s.label}</span>
                  <span className="sst__caption">{caption}</span>
                </span>
              </span>
            </li>
          );
        })}
      </ol>
      {scanId && (
        <CcureBadge mono size="md" className="sst__scan-no">
          Scan No. {scanNo ?? "-"}
        </CcureBadge>
      )}
    </div>
  );
}
