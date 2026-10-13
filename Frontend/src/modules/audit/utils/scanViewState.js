/**
 * What the scan pages should show for a scan loaded from `GET /scans/{id}`.
 *
 * The phase pages were written for the live pipeline: they read whatever the
 * session last held and, on mount, decided which phase to *start*. Opened from
 * Scan History on a finished scan, that meant a completed Vulnerability Audit
 * rendered as "Running Port Scan… Phase 2 of 3" with a Cancel button, the
 * Phase 3 URL showed whichever scan had been viewed before, and the pages were
 * one guard away from re-dispatching a phase against a finished scan.
 *
 * The scan record is authoritative. This maps it to context state in one
 * place: every phase's results, and a pipeline state derived from the scan's
 * real status — never "running" for a scan the backend says has finished.
 */
import { PIPELINE_STATES } from "../context/ScanContext";

const TERMINAL_STATUSES = new Set([
  "complete",
  "completed",
  "failed",
  "cancelled",
  "canceled",
  "unreachable",
  "timeout",
]);

/** True when the backend says the scan will not change any more. */
export function isTerminalScanStatus(status) {
  return TERMINAL_STATUSES.has(String(status || "").toLowerCase());
}

function phaseOf(scan) {
  const phase = Number(scan?.phase);
  return Number.isFinite(phase) && phase > 0 ? phase : 1;
}

function phaseKey(phase) {
  if (phase >= 3) return "VULN_SCAN";
  if (phase === 2) return "PORT_SCAN";
  return "DISCOVERY";
}

/** The pipeline state a scan's own status and phase imply. */
export function pipelineStateForScan(scan) {
  const status = String(scan?.status || "").toLowerCase();
  const mode = String(scan?.pipeline_mode || "basic").toLowerCase();
  switch (status) {
    case "complete":
    case "completed":
    case "unreachable":
      return mode === "basic"
        ? PIPELINE_STATES.COMPLETE
        : PIPELINE_STATES.REPORT_READY;
    case "failed":
    case "timeout":
      return PIPELINE_STATES.ERROR;
    case "cancelled":
    case "canceled":
      return PIPELINE_STATES.CANCELLED;
    default: {
      const phase = phaseOf(scan);
      if (phase >= 3) return PIPELINE_STATES.VULN_SCAN;
      if (phase === 2) return PIPELINE_STATES.PORT_SCAN;
      return PIPELINE_STATES.DISCOVERY;
    }
  }
}

function hostsOf(phaseBlock) {
  const block = phaseBlock || {};
  const hosts = block.data || block.hosts || [];
  return Array.isArray(hosts) ? hosts : [];
}

/** Context values for a scan record, every phase at once. */
export function scanViewState(scan) {
  const results = scan?.results || {};
  const status = String(scan?.status || "").toLowerCase();
  const failed = status === "failed" || status === "timeout";
  return {
    scanId: scan?.id ?? null,
    scanNo: scan?.scan_no ?? null,
    target: scan?.target || "",
    pipelineMode: scan?.pipeline_mode || "basic",
    phase1Hosts: hostsOf(results.phase1),
    phase1Summary: results.phase1?.summary || scan?.summary || null,
    phase2Results: hostsOf(results.phase2),
    phase2Summary: results.phase2?.summary || null,
    phase3AuditResults: hostsOf(results.phase3),
    phase3Summary: results.phase3?.summary || null,
    pipelineState: pipelineStateForScan(scan),
    pipelineError: failed
      ? {
          phase: phaseKey(phaseOf(scan)),
          message: scan?.failure_reason || "The scan failed.",
        }
      : null,
    status,
    terminal: isTerminalScanStatus(status),
  };
}
