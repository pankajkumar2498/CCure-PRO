/**
 * src/config/scanConfig.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Single source-of-truth for scan-type → phase pipeline mapping.
 *
 * SCAN MODES
 * ──────────
 *  basic     → Phase 1 only  (Host Discovery)
 *  asset     → Phase 1 → Phase 2  (always re-runs Phase 1, no stored results)
 *  advanced  → Phase 1 → Phase 2 → Phase 3 (full pipeline)
 *
 * HOW TO USE
 * ──────────
 *  import { SCAN_PIPELINES, getScanPipeline, buildPhasePayload } from "@/config/scanConfig";
 *
 *  const pipeline = getScanPipeline("asset");   // { phases: [1, 2], label: "...", ... }
 *  const payload  = buildPhasePayload("basic", { targets, scan_type });
 */

// ─── Phase descriptors ───────────────────────────────────────────────────────
export const PHASES = {
  1: {
    id:       1,
    key:      "phase1",
    label:    "Host Discovery",
    endpoint: "/scan/host-discovery",
    route:    "/scan/host-discovery",
  },
  2: {
    id:       2,
    key:      "phase2",
    label:    "Port Scanning",
    endpoint: "/scan/asset-discovery",
    route:    "/scan/asset-discovery",
  },
  3: {
    id:       3,
    key:      "phase3",
    label:    "Vulnerability & Risk Audit",
    endpoint: "/scan/advanced-scan",
    route:    "/scan/advanced-scan",
  },
};

// ─── Pipeline definitions ────────────────────────────────────────────────────
export const SCAN_PIPELINES = {
  /**
   * Basic Network Scan
   * Executes Phase 1 ONLY — stops after Host Discovery.
   * Backend receives: { phases: [1] }
   */
  basic: {
    id:          "basic",
    label:       "Basic Network Scan",
    description: "Identifies only the live hosts on the network.",
    phases:      [1],
    entryRoute:  "/scan",
    badge:       "Phase 1 Only",
  },

  /**
   * Asset Discovery
   * Always starts fresh with Phase 1, then proceeds to Phase 2.
   * Never skips Phase 1 — stored results are intentionally ignored.
   * Backend receives: { phases: [1, 2] }
   */
  asset: {
    id:          "asset",
    label:       "Asset Discovery",
    description: "Identifies Assets in the Network with Basic Information.",
    phases:      [1, 2],
    entryRoute:  "/scan",           // always starts at /scan, not /scan/asset-discovery
    badge:       "Phase 1 → 2",
    alwaysRestart: true,            // signals: never jump to asset-discovery using cached host-discovery data
  },

  /**
   * Advanced Scan
   * Full pipeline: Phase 1 → 2 → 3
   * Backend receives: { phases: [1, 2, 3] }
   */
  advanced: {
    id:          "advanced",
    label:       "Advanced Scan",
    description: "Full Network Scan with Detailed Information.",
    phases:      [1, 2, 3],
    entryRoute:  "/scan",
    badge:       "Full Pipeline",
  },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Returns the pipeline config for a given scan mode.
 * @param {"basic" | "asset" | "advanced"} mode
 * @returns {object} pipeline config
 */
export function getScanPipeline(mode) {
  const pipeline = SCAN_PIPELINES[mode];
  if (!pipeline) throw new Error(`Unknown scan mode: "${mode}"`);
  return pipeline;
}

/**
 * Returns true if the given phaseNumber is part of the pipeline.
 * @param {"basic" | "asset" | "advanced"} mode
 * @param {number} phaseNumber
 */
export function isPhaseEnabled(mode, phaseNumber) {
  return getScanPipeline(mode).phases.includes(phaseNumber);
}

/**
 * Returns the next phase descriptor after the given phase within the pipeline,
 * or null if the given phase is the last one.
 * @param {"basic" | "asset" | "advanced"} mode
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
 * @param {"basic" | "asset" | "advanced"} mode
 * @param {object} extra - additional fields merged into the payload
 * @returns {object} payload ready for API
 *
 * @example
 * buildPhasePayload("asset", { targets: ["192.168.1.0/24"], scan_type: "adaptive" })
 * // → { phases: [1, 2], pipeline_mode: "asset", targets: [...], scan_type: "adaptive" }
 */
export function buildPhasePayload(mode, extra = {}) {
  const pipeline = getScanPipeline(mode);
  return {
    phases:        pipeline.phases,
    pipeline_mode: mode,
    ...extra,
  };
}
