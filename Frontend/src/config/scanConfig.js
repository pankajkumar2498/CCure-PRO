/**
 * src/config/scanConfig.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Single source-of-truth for scan-type → phase pipeline mapping.
 *
 * SCAN MODES
 * ──────────
 *  basic             → Phase 1 only  (Host Discovery)
 *  asset             → Phase 1 → Phase 2  (always re-runs Phase 1, no stored results)
 *  vulnerability_audit → Phase 1 → Phase 2 → Phase 3 (full pipeline)
 *
 * HOW TO USE
 * ──────────
 *  import { SCAN_PIPELINES, getScanPipeline, buildPhasePayload } from "@/config/scanConfig";
 *
 *  const pipeline = getScanPipeline("asset");   // { phases: [1, 2], label: "...", ... }
 *  const payload  = buildPhasePayload("basic", { targets, scan_type });
 */

// ─── Pipeline definitions ────────────────────────────────────────────────────
export const SCAN_PIPELINES = {
  /**
   * Basic Network Scan
   * Executes Phase 1 ONLY — stops after Host Discovery.
   * Backend receives: { phases: [1] }
   */
  basic: {
    id: "basic",
    label: "Basic Network Scan",
    description: "Identifies the live hosts in the network.",
    phases: [1],
    entryRoute: "/scan",
    badge: "Phase 1 Only",
  },

  /**
   * Asset Discovery
   * Always starts fresh with Phase 1, then proceeds to Phase 2.
   * Never skips Phase 1 — stored results are intentionally ignored.
   * Backend receives: { phases: [1, 2] }
   */
  asset: {
    id: "asset",
    label: "Asset Discovery",
    description:
      "Identifies Assets in the Network with Open Ports Information.",
    phases: [1, 2],
    entryRoute: "/scan", // always starts at /scan, not /scan/asset-discovery
    badge: "Phase 1 → 2",
    alwaysRestart: true, // signals: never jump to asset-discovery using cached host-discovery data
  },

  /**
   * Vulnerability Audit
   * Full pipeline: Phase 1 → 2 → 3
   * Backend receives: { phases: [1, 2, 3] }
   */
  vulnerability_audit: {
    id: "vulnerability_audit",
    label: "Vulnerability Audit",
    description:
      "Full vulnerability audit pipeline with host, port, and risk assessment.",
    phases: [1, 2, 3],
    entryRoute: "/scan",
    badge: "Full Pipeline",
  },
  advanced: {
    id: "advanced",
    label: "Vulnerability Audit",
    description:
      "Full vulnerability audit pipeline with host, port, and risk assessment.",
    phases: [1, 2, 3],
    entryRoute: "/scan",
    badge: "Full Pipeline",
  },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Returns the pipeline config for a given scan mode.
 * @param {"basic" | "asset" | "advanced" | "vulnerability_audit"} mode
 * @returns {object} pipeline config
 */
export const PHASES = {
  1: {
    id: 1,
    label: "Host Discovery",
    route: "/scan/host-discovery",
  },
  2: {
    id: 2,
    label: "Port Scan",
    route: "/scan/asset-discovery",
  },
  3: {
    id: 3,
    label: "Vulnerability Audit",
    route: "/scan/vulnerability-audit",
  },
  4: {
    id: 4,
    label: "Network Topology",
    route: "/scan/topology-map",
  },
};

export function getScanPipeline(mode) {
  const pipeline = SCAN_PIPELINES[mode];
  if (!pipeline) throw new Error(`Unknown scan mode: "${mode}"`);
  return pipeline;
}

/**
 * Returns true if the given phaseNumber is part of the pipeline.
 * @param {"basic" | "asset" | "advanced" | "vulnerability_audit"} mode
 * @param {number} phaseNumber
 */
export function isPhaseEnabled(mode, phaseNumber) {
  return getScanPipeline(mode).phases.includes(phaseNumber);
}

/**
 * Returns the next phase descriptor after the given phase within the pipeline,
 * or null if the given phase is the last one.
 * @param {"basic" | "asset" | "advanced" | "vulnerability_audit"} mode
 * @param {number} currentPhase
 */
export function getNextPhase(mode, currentPhase) {
  const { phases } = getScanPipeline(mode);
  const idx = phases.indexOf(currentPhase);
  if (idx === -1 || idx === phases.length - 1) return null;
  return PHASES[phases[idx + 1]];
}

/**
 * Builds the base payload that should be sent to the backend.
 * The backend uses `phases` to know exactly which phases to execute.
 *
 * @param {"basic" | "asset" | "advanced" | "vulnerability_audit"} mode
 * @param {object} extra - additional fields merged into the payload
 * @returns {object} payload ready for API
 *
 * @example
 * buildPhasePayload("asset", { targets: ["10.180.6.0/24"], scan_type: "adaptive" })
 * // → { phases: [1, 2], pipeline_mode: "asset", targets: [...], scan_type: "adaptive" }
 */
export function buildPhasePayload(mode, extra = {}) {
  const pipeline = getScanPipeline(mode);
  return {
    phases: pipeline.phases,
    pipeline_mode: mode,
    ...extra,
  };
}
